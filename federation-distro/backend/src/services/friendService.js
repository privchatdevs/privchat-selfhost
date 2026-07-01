const friendRepository = require("../repositories/friendRepository");
const userRepository = require("../repositories/userRepository");
const serverRepository = require("../repositories/serverRepository");
const serverPrivacyRepository = require("../repositories/serverPrivacyRepository");
const messageRepository = require("../repositories/messageRepository");
const messageService = require("./messageService");
const { getUserBadges } = require("./badges");
const { publicPresenceStatus } = require("./presence");

const { FRIEND_CAP, PENDING_INCOMING_CAP } = friendRepository;

// Does `fromUserId` clear `toUserId`'s privacy set for initiating contact?
// `levelsCsv` is a comma-separated set; the allowed groups combine with OR.
function meetsPrivacyLevel(levelsCsv, fromUserId, toUserId) {
  const levels = String(levelsCsv || "").split(",").map((token) => token.trim()).filter(Boolean);
  if (levels.includes("anyone")) return true;
  if (levels.includes("mutual_servers") && serverRepository.shareServer(fromUserId, toUserId)) return true;
  if (levels.includes("friends_of_friends") && friendRepository.hasMutualFriend(fromUserId, toUserId)) return true;
  return false;
}

function friendError(message, status = 400) {
  const err = new Error(message);
  err.statusCode = status;
  return err;
}

/**
 * Public user shape returned to the client.
 * Profile picture is served from the auth endpoint, keyed by public_user_id.
 */
function publicFriend(row) {
  return {
    friendshipId: row.friendship_id,
    userId: row.public_user_id || row.user_id,
    username: row.username,
    alias: row.profile_alias || "",
    bio: row.bio || "",
    isOnline: Boolean(row.is_online),
    publicKey: row.public_key || null,
    // Profile picture URL - same pattern as authService
    profilePictureUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(row.public_user_id || row.user_id)}&v=${encodeURIComponent(row.updated_at || row.requested_at || "")}`,
    profileBannerUrl: row.profile_banner_mime
      ? `/api/auth/profile-banner?uid=${encodeURIComponent(row.public_user_id || row.user_id)}&v=${encodeURIComponent(row.updated_at || row.requested_at || Date.now())}`
      : "",
    badges: getUserBadges(row),
    requestedAt: row.requested_at || null,
    presenceStatus: publicPresenceStatus(row),
  };
}

function publicBlockedUser(row) {
  return {
    userId: row.public_user_id || row.user_id,
    username: row.username,
    alias: row.profile_alias || "",
    bio: row.bio || "",
    blockedAt: row.blocked_at || null,
    profilePictureUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(row.public_user_id || row.user_id)}&v=${encodeURIComponent(row.updated_at || row.blocked_at || "")}`,
    profileBannerUrl: row.profile_banner_mime
      ? `/api/auth/profile-banner?uid=${encodeURIComponent(row.public_user_id || row.user_id)}&v=${encodeURIComponent(row.updated_at || row.blocked_at || Date.now())}`
      : "",
  };
}

/**
 * Direct messages are allowed between accepted friends and between users who
 * share at least one server. A block in either direction always wins, even if
 * the two users share a server.
 */
function canDirectMessage(userIdA, userIdB) {
  if (friendRepository.getBlockBetween(userIdA, userIdB)) return false;
  const friendship = friendRepository.getFriendship(userIdA, userIdB);
  if (friendship && friendship.status === "accepted") return true;
  // Per-server privacy: if the recipient (B) has blocked DMs from a server the
  // sender (A) belongs to, A can't message B - even if they share that server.
  // Friends (handled above) are always allowed; this only gates non-friends.
  if (serverPrivacyRepository.isSenderBlockedByServer(userIdB, userIdA, "block_dms")) return false;
  // Privacy is enforced continuously - there is NO "already-open thread" bypass.
  // A DM is allowed only while the sender still clears the recipient's privacy set
  // (shares a server, has a mutual friend, or it's "anyone"). So if someone
  // unfriends you and shares no server and has no mutual friend, they can no
  // longer message you even if you'd talked before.
  return meetsPrivacyLevel(userRepository.getPrivacySettings(userIdB).dmPrivacy, userIdA, userIdB);
}

/**
 * Whether userIdA may VIEW / interact with an existing DM with userIdB - read the
 * history, see their DM profile, react, delete. Unlike sending (canDirectMessage),
 * this KEEPS the "already-open thread" allowance: a thread you've talked in before
 * stays readable even after you unfriend them or your privacy tightens. You just
 * can't send new messages.
 */
function canViewConversation(userIdA, userIdB) {
  if (friendRepository.getBlockBetween(userIdA, userIdB)) return false;
  const friendship = friendRepository.getFriendship(userIdA, userIdB);
  if (friendship && friendship.status === "accepted") return true;
  if (messageRepository.conversationExists(userIdA, userIdB)) return true;
  return meetsPrivacyLevel(userRepository.getPrivacySettings(userIdB).dmPrivacy, userIdA, userIdB);
}

async function getFriends(userId) {
  const rows = friendRepository.getFriends(userId);
  return rows.map(publicFriend);
}

async function getPendingIncoming(userId) {
  const rows = friendRepository.getPendingIncoming(userId);
  return rows.map(publicFriend);
}

async function getPendingOutgoing(userId) {
  const rows = friendRepository.getPendingOutgoing(userId);
  return rows.map(publicFriend);
}

async function getBlockedUsers(userId, search = "") {
  const rows = friendRepository.getBlockedUsers(userId, search);
  return rows.map(publicBlockedUser);
}

async function sendFriendRequest({ requesterId, targetUsername }) {
  // 1. Find target user
  const target = friendRepository.findUserByUsername(targetUsername);
  if (!target) {
    throw friendError("No user found with that username.");
  }

  // 2. Cannot friend yourself
  if (target.user_id === requesterId) {
    throw friendError("You cannot send a friend request to yourself.");
  }

  const block = friendRepository.getBlockBetween(requesterId, target.user_id);
  if (block?.blocker_id === requesterId) {
    throw friendError(`You cannot send a friend request to @${target.username} because you have blocked them.`);
  }
  if (block?.blocker_id === target.user_id) {
    throw friendError(`You cannot send a friend request to @${target.username}.`);
  }

  // 3. Check for existing friendship / pending request
  const existing = friendRepository.getFriendship(requesterId, target.user_id);
  if (existing) {
    if (existing.status === "accepted") {
      throw friendError("You are already friends with this user.");
    }
    if (existing.status === "pending") {
      // If they already sent us one, auto-accept it
      if (existing.requester_id === target.user_id) {
        const result = await acceptRequest({
          friendshipId: existing.friendship_id,
          userId: requesterId,
        });
        return { ...result, action: "accepted", message: "You are now friends!" };
      }
      throw friendError("You have already sent a friend request to this user.");
    }
  }

  // 3b. Per-server privacy: if the target blocked friend requests from a server
  // the requester belongs to, deny it (reuses the same generic message).
  if (serverPrivacyRepository.isSenderBlockedByServer(target.user_id, requesterId, "block_friend_reqs")) {
    throw friendError(`@${target.username} isn't accepting friend requests right now.`);
  }

  // 3c. Respect the target's friend-request privacy (anyone / mutual servers /
  // friends of friends). Default "anyone" preserves the prior open behaviour.
  const frPrivacy = userRepository.getPrivacySettings(target.user_id).friendRequestPrivacy;
  if (!meetsPrivacyLevel(frPrivacy, requesterId, target.user_id)) {
    throw friendError(`@${target.username} isn't accepting friend requests right now.`);
  }

  // 4. Enforce 5,000 friend cap for both sides
  const requesterCount = friendRepository.countFriends(requesterId);
  if (requesterCount >= FRIEND_CAP) {
    throw friendError(`You have reached the maximum of ${FRIEND_CAP} friends.`);
  }
  const targetCount = friendRepository.countFriends(target.user_id);
  if (targetCount >= FRIEND_CAP) {
    throw friendError("That user has reached the maximum number of friends.");
  }

  const targetPendingIncomingCount = friendRepository.countPendingIncoming(target.user_id);
  if (targetPendingIncomingCount >= PENDING_INCOMING_CAP) {
    throw friendError(`Sorry, @${target.username} has too many pending friend requests.`);
  }

  // 5. Insert
  friendRepository.sendRequest(requesterId, target.user_id);
  return {
    action: "requested",
    message: `Friend request sent to @${target.username}.`,
    requesterId,
    addresseeId: target.user_id,
  };
}

async function acceptRequest({ friendshipId, userId }) {
  const friendship = friendRepository.getFriendshipById(friendshipId);
  if (!friendship || friendship.addressee_id !== userId || friendship.status !== "pending") {
    throw friendError("Friend request not found.", 404);
  }

  const count = friendRepository.countFriends(userId);
  if (count >= FRIEND_CAP) {
    throw friendError(`You have reached the maximum of ${FRIEND_CAP} friends.`);
  }

  const requesterCount = friendRepository.countFriends(friendship.requester_id);
  if (requesterCount >= FRIEND_CAP) {
    throw friendError("That user has reached the maximum number of friends.");
  }

  const accepted = friendRepository.acceptRequest(friendshipId, userId);
  if (!accepted) {
    throw friendError("Friend request not found.", 404);
  }

  await messageService.openConversationPair(friendship.requester_id, userId);

  const requester = userRepository.findById(friendship.requester_id);
  const addressee = userRepository.findById(userId);

  return {
    friend: requester ? publicFriend({ ...requester, friendship_id: friendshipId, is_online: false }) : null,
    requesterId: friendship.requester_id,
    addresseeId: userId,
    requesterPublicId: requester?.public_user_id || friendship.requester_id,
    addresseePublicId: addressee?.public_user_id || userId,
  };
}

async function declineRequest({ friendshipId, userId }) {
  // Grab the friendship first so we can tell the requester their sent request
  // was removed (their "Pending → Sent" list should update live).
  const friendship = friendRepository.getFriendshipById(friendshipId);
  friendRepository.declineRequest(friendshipId, userId);
  return { otherId: friendship && friendship.addressee_id === userId ? friendship.requester_id : null };
}

async function cancelRequest({ friendshipId, userId }) {
  const friendship = friendRepository.getFriendshipById(friendshipId);
  friendRepository.cancelRequest(friendshipId, userId);
  // The addressee should see the incoming request disappear live.
  return { otherId: friendship && friendship.requester_id === userId ? friendship.addressee_id : null };
}

async function removeFriend({ friendshipId, userId }) {
  const partnerId = friendRepository.removeFriend(friendshipId, userId);
  // Friendship is what opened the DM thread (accepting a request calls
  // openConversationPair). Closing it on removal revokes the "open thread"
  // bypass, so the removed person can no longer message past DM privacy. Message
  // history is kept; only the open-thread state is dropped.
  if (partnerId) {
    messageService.closeConversationPair(userId, partnerId);
  }
}

// Remove all of the user's friends at once. Returns the former friends' ids so
// the caller can refresh their lists too.
async function removeAllFriends(userId) {
  const friendIds = friendRepository.removeAllFriends(userId);
  // Close each DM thread too (same reason as single removal): drop the
  // open-thread bypass so removed friends can't message past DM privacy.
  friendIds.forEach((friendId) => messageService.closeConversationPair(userId, friendId));
  return friendIds;
}

async function blockUser({ userId, targetUserId }) {
  const target = userRepository.findByAnyId(targetUserId);
  if (!target) throw friendError("User not found.", 404);
  if (target.user_id === userId) throw friendError("You cannot block yourself.");

  friendRepository.blockUser(userId, target.user_id);
  return {
    ok: true,
    blocked: true,
    user: publicBlockedUser({
      ...target,
      blocked_at: new Date().toISOString(),
    }),
  };
}

async function unblockUser({ userId, targetUserId }) {
  const target = userRepository.findByAnyId(targetUserId);
  if (!target) throw friendError("User not found.", 404);

  friendRepository.unblockUser(userId, target.user_id);
  return { ok: true, blocked: false };
}

async function getBlockState({ userId, targetUserId }) {
  const target = userRepository.findByAnyId(targetUserId);
  if (!target) throw friendError("User not found.", 404);

  const blockedByMe = Boolean(friendRepository.getBlock(userId, target.user_id));
  const blockedMe = Boolean(friendRepository.getBlock(target.user_id, userId));
  return { blockedByMe, blockedMe };
}

module.exports = {
  acceptRequest,
  blockUser,
  canDirectMessage,
  canViewConversation,
  cancelRequest,
  declineRequest,
  getBlockedUsers,
  getBlockState,
  getFriends,
  getPendingIncoming,
  getPendingOutgoing,
  removeFriend,
  removeAllFriends,
  sendFriendRequest,
  unblockUser,
};
