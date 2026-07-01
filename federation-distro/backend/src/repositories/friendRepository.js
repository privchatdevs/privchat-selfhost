const { randomUUID } = require("crypto");
const friendDb = require("../config/messageDb"); // friendships live in data.db
const db = require("../config/db");               // users live in auth.db
const { isPublicOnline } = require("../services/presence");

const FRIEND_CAP = 5000;
const PENDING_INCOMING_CAP = 100;

// Whether userA and userB share at least one accepted mutual friend (a third
// user who is friends with both) - powers the "friends of friends" privacy level.
function hasMutualFriend(userA, userB) {
  const row = friendDb.prepare(`
    SELECT 1 FROM (
      SELECT CASE WHEN requester_id = ? THEN addressee_id ELSE requester_id END AS fid
      FROM friendships WHERE status = 'accepted' AND (requester_id = ? OR addressee_id = ?)
    ) a
    JOIN (
      SELECT CASE WHEN requester_id = ? THEN addressee_id ELSE requester_id END AS fid
      FROM friendships WHERE status = 'accepted' AND (requester_id = ? OR addressee_id = ?)
    ) b ON a.fid = b.fid
    LIMIT 1
  `).get(userA, userA, userA, userB, userB, userB);
  return Boolean(row);
}

/**
 * Count how many accepted friends a user currently has.
 */
function countFriends(userId) {
  const row = friendDb.prepare(`
    SELECT COUNT(*) AS cnt
    FROM friendships
    WHERE status = 'accepted'
      AND (requester_id = ? OR addressee_id = ?)
  `).get(userId, userId);
  return row?.cnt ?? 0;
}

/**
 * Count how many incoming pending friend requests a user currently has.
 */
function countPendingIncoming(userId) {
  const row = friendDb.prepare(`
    SELECT COUNT(*) AS cnt
    FROM friendships
    WHERE addressee_id = ?
      AND status = 'pending'
  `).get(userId);
  return row?.cnt ?? 0;
}

function getBlock(blockerId, blockedId) {
  return friendDb.prepare(`
    SELECT blocker_id, blocked_id, created_at
    FROM user_blocks
    WHERE blocker_id = ?
      AND blocked_id = ?
    LIMIT 1
  `).get(blockerId, blockedId) || null;
}

function getBlockBetween(userA, userB) {
  return friendDb.prepare(`
    SELECT blocker_id, blocked_id, created_at
    FROM user_blocks
    WHERE (blocker_id = ? AND blocked_id = ?)
       OR (blocker_id = ? AND blocked_id = ?)
    LIMIT 1
  `).get(userA, userB, userB, userA) || null;
}

function blockUser(blockerId, blockedId) {
  friendDb.prepare(`
    INSERT OR IGNORE INTO user_blocks (blocker_id, blocked_id)
    VALUES (?, ?)
  `).run(blockerId, blockedId);

  friendDb.prepare(`
    DELETE FROM friendships
    WHERE (requester_id = ? AND addressee_id = ?)
       OR (requester_id = ? AND addressee_id = ?)
  `).run(blockerId, blockedId, blockedId, blockerId);
}

function unblockUser(blockerId, blockedId) {
  friendDb.prepare(`
    DELETE FROM user_blocks
    WHERE blocker_id = ?
      AND blocked_id = ?
  `).run(blockerId, blockedId);
}

// Internal ids of everyone in a block relationship with this user (either
// direction) - used to exclude blocked people from people search.
function getBlockedIdsForUser(userId) {
  return friendDb.prepare(`
    SELECT blocked_id AS id FROM user_blocks WHERE blocker_id = ?
    UNION
    SELECT blocker_id AS id FROM user_blocks WHERE blocked_id = ?
  `).all(userId, userId).map((row) => row.id);
}

function getBlockedUsers(userId, search = "") {
  const normalizedSearch = search.trim().toLowerCase();
  const rows = friendDb.prepare(`
    SELECT blocked_id, created_at
    FROM user_blocks
    WHERE blocker_id = ?
    ORDER BY created_at DESC
  `).all(userId);

  if (rows.length === 0) return [];

  const placeholders = rows.map(() => "?").join(", ");
  const blockedIds = rows.map((row) => row.blocked_id);
  const users = db.prepare(`
    SELECT user_id, public_user_id, username, profile_alias, bio, profile_banner_mime, updated_at
    FROM users
    WHERE user_id IN (${placeholders})
  `).all(...blockedIds);

  const userMap = Object.fromEntries(users.map((u) => [u.user_id, u]));
  const mapped = rows
    .map((row) => {
      const u = userMap[row.blocked_id];
      if (!u) return null;
      return {
        user_id: u.user_id,
        public_user_id: u.public_user_id,
        username: u.username,
        profile_alias: u.profile_alias,
        bio: u.bio,
        profile_banner_mime: u.profile_banner_mime,
        updated_at: u.updated_at,
        blocked_at: row.created_at,
      };
    })
    .filter(Boolean);

  if (!normalizedSearch) return mapped.slice(0, 50);
  return mapped
    .filter((user) => {
      const username = user.username?.toLowerCase() || "";
      const alias = user.profile_alias?.toLowerCase() || "";
      return username.includes(normalizedSearch) || alias.includes(normalizedSearch);
    })
    .slice(0, 50);
}

/**
 * Look up a user by username for sending a friend request.
 * Returns minimal public fields only.
 */
function findUserByUsername(username) {
  return db.prepare(`
    SELECT user_id, username, profile_alias
    FROM users
    WHERE username_normalized = ?
    LIMIT 1
  `).get(username.toLowerCase()) || null;
}

/**
 * Get the existing friendship row between two users (regardless of direction).
 */
function getFriendship(userA, userB) {
  return friendDb.prepare(`
    SELECT friendship_id, requester_id, addressee_id, status
    FROM friendships
    WHERE (requester_id = ? AND addressee_id = ?)
       OR (requester_id = ? AND addressee_id = ?)
    LIMIT 1
  `).get(userA, userB, userB, userA) || null;
}

function getFriendshipById(friendshipId) {
  return friendDb.prepare(`
    SELECT friendship_id, requester_id, addressee_id, status
    FROM friendships
    WHERE friendship_id = ?
    LIMIT 1
  `).get(friendshipId) || null;
}

/**
 * Insert a new pending friend request.
 */
function sendRequest(requesterId, addresseeId) {
  const id = randomUUID();
  friendDb.prepare(`
    INSERT INTO friendships (friendship_id, requester_id, addressee_id, status)
    VALUES (?, ?, ?, 'pending')
  `).run(id, requesterId, addresseeId);
  return id;
}

/**
 * Accept an incoming request. Only the addressee can accept.
 */
function acceptRequest(friendshipId, addresseeId) {
  const result = friendDb.prepare(`
    UPDATE friendships
    SET status = 'accepted',
        updated_at = datetime('now')
    WHERE friendship_id = ?
      AND addressee_id = ?
      AND status = 'pending'
  `).run(friendshipId, addresseeId);
  return result.changes || 0;
}

/**
 * Decline an incoming request. Only the addressee can decline.
 */
function declineRequest(friendshipId, addresseeId) {
  friendDb.prepare(`
    DELETE FROM friendships
    WHERE friendship_id = ?
      AND addressee_id = ?
      AND status = 'pending'
  `).run(friendshipId, addresseeId);
}

/**
 * Cancel an outgoing request. Only the requester can cancel.
 */
function cancelRequest(friendshipId, requesterId) {
  friendDb.prepare(`
    DELETE FROM friendships
    WHERE friendship_id = ?
      AND requester_id = ?
      AND status = 'pending'
  `).run(friendshipId, requesterId);
}

/**
 * Remove an accepted friend (either direction). Returns the other user's id (so
 * the caller can close the DM thread), or null if no matching friendship.
 */
function removeFriend(friendshipId, userId) {
  const row = friendDb.prepare(`
    SELECT requester_id, addressee_id FROM friendships
    WHERE friendship_id = ?
      AND status = 'accepted'
      AND (requester_id = ? OR addressee_id = ?)
  `).get(friendshipId, userId, userId);
  friendDb.prepare(`
    DELETE FROM friendships
    WHERE friendship_id = ?
      AND status = 'accepted'
      AND (requester_id = ? OR addressee_id = ?)
  `).run(friendshipId, userId, userId);
  if (!row) return null;
  return row.requester_id === userId ? row.addressee_id : row.requester_id;
}

/**
 * Remove EVERY accepted friendship the user is part of (either direction).
 * Returns the other side's user_ids first so callers can refresh those users'
 * friend lists in real time. Pending requests are left untouched - they aren't
 * friends yet.
 */
function removeAllFriends(userId) {
  const rows = friendDb.prepare(`
    SELECT CASE WHEN requester_id = ? THEN addressee_id ELSE requester_id END AS friend_id
    FROM friendships
    WHERE status = 'accepted'
      AND (requester_id = ? OR addressee_id = ?)
  `).all(userId, userId, userId);

  friendDb.prepare(`
    DELETE FROM friendships
    WHERE status = 'accepted'
      AND (requester_id = ? OR addressee_id = ?)
  `).run(userId, userId);

  return rows.map((r) => r.friend_id);
}

function removeFriendshipBetween(userA, userB) {
  friendDb.prepare(`
    DELETE FROM friendships
    WHERE (requester_id = ? AND addressee_id = ?)
       OR (requester_id = ? AND addressee_id = ?)
  `).run(userA, userB, userB, userA);
}

/**
 * Get all accepted friends for a user with their public info.
 * Friendships are in data.db; user details are fetched from auth.db.
 */
function getFriends(userId) {
  // Step 1: get friend user_ids from data.db
  const rows = friendDb.prepare(`
    SELECT
      friendship_id,
      CASE WHEN requester_id = ? THEN addressee_id ELSE requester_id END AS friend_id
    FROM friendships
    WHERE status = 'accepted'
      AND (requester_id = ? OR addressee_id = ?)
  `).all(userId, userId, userId);

  if (rows.length === 0) return [];

  // Step 2: fetch user details from auth.db for each friend
  const placeholders = rows.map(() => "?").join(", ");
  const friendIds = rows.map((r) => r.friend_id);
  const users = db.prepare(`
    SELECT user_id, public_user_id, user_number, username, profile_alias, bio, profile_banner_mime, last_seen_at, presence_status, public_key, updated_at
    FROM users
    WHERE user_id IN (${placeholders})
  `).all(...friendIds);

  const userMap = Object.fromEntries(users.map((u) => [u.user_id, u]));

  return rows
    .map((row) => {
      const u = userMap[row.friend_id];
      if (!u) return null;
      const isOnline = isPublicOnline(u);
      return {
        friendship_id: row.friendship_id,
        user_id: u.user_id,
        public_user_id: u.public_user_id,
        user_number: u.user_number,
        username: u.username,
        profile_alias: u.profile_alias,
        bio: u.bio,
        profile_banner_mime: u.profile_banner_mime,
        last_seen_at: u.last_seen_at,
        presence_status: u.presence_status,
        updated_at: u.updated_at,
        public_key: u.public_key,
        is_online: isOnline ? 1 : 0,
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.is_online - a.is_online);
}

/**
 * Get the last 20 incoming (pending) friend requests for a user.
 */
function getPendingIncoming(userId) {
  // Step 1: get pending requests from data.db
  const rows = friendDb.prepare(`
    SELECT friendship_id, requester_id, created_at AS requested_at
    FROM friendships
    WHERE addressee_id = ?
      AND status = 'pending'
    ORDER BY created_at DESC
    LIMIT 20
  `).all(userId);

  if (rows.length === 0) return [];

  // Step 2: fetch requester user details from auth.db
  const placeholders = rows.map(() => "?").join(", ");
  const requesterIds = rows.map((r) => r.requester_id);
  const users = db.prepare(`
    SELECT user_id, public_user_id, username, profile_alias, bio, profile_banner_mime, public_key, updated_at
    FROM users
    WHERE user_id IN (${placeholders})
  `).all(...requesterIds);

  const userMap = Object.fromEntries(users.map((u) => [u.user_id, u]));

  return rows.map((row) => {
    const u = userMap[row.requester_id] || {};
    return {
      friendship_id: row.friendship_id,
      requested_at: row.requested_at,
      user_id: u.user_id,
      public_user_id: u.public_user_id,
      username: u.username,
      profile_alias: u.profile_alias,
      bio: u.bio,
      profile_banner_mime: u.profile_banner_mime,
      public_key: u.public_key,
      updated_at: u.updated_at,
    };
  });
}

/**
 * Get the last 20 outgoing (pending) friend requests for a user.
 */
function getPendingOutgoing(userId) {
  const rows = friendDb.prepare(`
    SELECT friendship_id, addressee_id, created_at AS requested_at
    FROM friendships
    WHERE requester_id = ?
      AND status = 'pending'
    ORDER BY created_at DESC
    LIMIT 20
  `).all(userId);

  if (rows.length === 0) return [];

  const placeholders = rows.map(() => "?").join(", ");
  const addresseeIds = rows.map((r) => r.addressee_id);
  const users = db.prepare(`
    SELECT user_id, public_user_id, username, profile_alias, bio, profile_banner_mime, public_key, updated_at
    FROM users
    WHERE user_id IN (${placeholders})
  `).all(...addresseeIds);

  const userMap = Object.fromEntries(users.map((u) => [u.user_id, u]));

  return rows.map((row) => {
    const u = userMap[row.addressee_id] || {};
    return {
      friendship_id: row.friendship_id,
      requested_at: row.requested_at,
      user_id: u.user_id,
      public_user_id: u.public_user_id,
      username: u.username,
      profile_alias: u.profile_alias,
      bio: u.bio,
      profile_banner_mime: u.profile_banner_mime,
      public_key: u.public_key,
      updated_at: u.updated_at,
    };
  });
}

module.exports = {
  hasMutualFriend,
  FRIEND_CAP,
  PENDING_INCOMING_CAP,
  acceptRequest,
  cancelRequest,
  blockUser,
  countFriends,
  countPendingIncoming,
  declineRequest,
  findUserByUsername,
  getBlock,
  getBlockBetween,
  getBlockedUsers,
  getBlockedIdsForUser,
  getFriendship,
  getFriendshipById,
  getFriends,
  getPendingIncoming,
  getPendingOutgoing,
  removeAllFriends,
  removeFriendshipBetween,
  removeFriend,
  sendRequest,
  unblockUser,
};
