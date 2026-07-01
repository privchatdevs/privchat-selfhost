const { randomUUID } = require("crypto");
const db = require("../config/messageDb");

// Group DMs. Everything here deals in INTERNAL user ids (the controller maps to
// public ids on the way out). Messages are E2E ciphertext blobs - the server
// never reads them. New members only ever see messages sent AFTER they joined
// (their public key wasn't in older messages' wrapped-key set), so getMessages
// filters by the member's joined_at.

const MAX_GROUP_MEMBERS = 20;

// A group with no new message in this many days is reaped wholesale by the
// auto-delete sweeper (see groupService.sweepInactiveGroups). Internal only.
const INACTIVE_GROUP_TTL_DAYS = 60;
// node:sqlite is synchronous - purge big tables in capped chunks with small
// pauses so a backlog never freezes the server (mirrors messageRepository).
const DELETE_BATCH_SIZE = 1000;
const DELETE_BATCH_PAUSE_MS = 25;
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

// ── Groups ───────────────────────────────────────────────────────────────────
function createGroup({ ownerId, name }) {
  const id = randomUUID();
  db.prepare(
    "INSERT INTO group_conversations (group_id, name, owner_id) VALUES (?, ?, ?)"
  ).run(id, name || null, ownerId);
  return id;
}

function getGroup(groupId) {
  return db.prepare(
    "SELECT group_id, name, owner_id, icon_key, icon_mime, created_at, updated_at FROM group_conversations WHERE group_id = ?"
  ).get(groupId) || null;
}

function updateIcon(groupId, iconKey, iconMime) {
  db.prepare(
    "UPDATE group_conversations SET icon_key = ?, icon_mime = ?, updated_at = datetime('now') WHERE group_id = ?"
  ).run(iconKey, iconMime, groupId);
}

function getIcon(groupId) {
  return db.prepare(
    "SELECT name, icon_key, icon_mime FROM group_conversations WHERE group_id = ?"
  ).get(groupId) || null;
}

function renameGroup(groupId, name) {
  db.prepare(
    "UPDATE group_conversations SET name = ?, updated_at = datetime('now') WHERE group_id = ?"
  ).run(name || null, groupId);
}

function setOwner(groupId, userId) {
  db.prepare(
    "UPDATE group_conversations SET owner_id = ?, updated_at = datetime('now') WHERE group_id = ?"
  ).run(userId, groupId);
}

function touchGroup(groupId) {
  db.prepare("UPDATE group_conversations SET updated_at = datetime('now') WHERE group_id = ?").run(groupId);
}

// Drop the whole group: messages, members, then the group row. Group message
// counts are tiny relative to servers, so a plain delete is fine here.
function deleteGroup(groupId) {
  db.prepare("DELETE FROM group_messages WHERE group_id = ?").run(groupId);
  db.prepare("DELETE FROM group_members WHERE group_id = ?").run(groupId);
  db.prepare("DELETE FROM group_conversations WHERE group_id = ?").run(groupId);
}

// Groups with no new message in INACTIVE_GROUP_TTL_DAYS - using the latest
// message time, or the group's creation time for groups that never had one.
// Returns id + icon key so the sweeper can also free the stored picture.
function getInactiveGroups(limit = 200) {
  return db.prepare(`
    SELECT g.group_id, g.icon_key
    FROM group_conversations g
    WHERE COALESCE(
            (SELECT MAX(created_at) FROM group_messages m WHERE m.group_id = g.group_id),
            g.created_at
          ) < datetime('now', '-${INACTIVE_GROUP_TTL_DAYS} days')
    LIMIT ?
  `).all(limit);
}

// Batched purge of a group's messages, for the auto-delete sweeper.
async function deleteGroupMessagesInBatches(groupId) {
  const stmt = db.prepare(`
    DELETE FROM group_messages WHERE rowid IN (
      SELECT rowid FROM group_messages WHERE group_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `);
  for (;;) {
    const info = stmt.run(groupId);
    if (!info.changes) break;
    await sleep(DELETE_BATCH_PAUSE_MS);
  }
}

// Every group id a user belongs to (cheap - rides IX_group_members_user). Used to
// purge a user out of all their groups on account deletion / DM purge.
function getGroupIdsForUser(userId) {
  return db.prepare("SELECT group_id FROM group_members WHERE user_id = ?")
    .all(userId)
    .map((row) => row.group_id);
}

// Batched delete of ONLY this user's authored messages in a group (the rest of the
// group's history stays). sender_id is the internal user id.
async function deleteUserMessagesInGroup(groupId, senderId) {
  const stmt = db.prepare(`
    DELETE FROM group_messages WHERE rowid IN (
      SELECT rowid FROM group_messages WHERE group_id = ? AND sender_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `);
  for (;;) {
    const info = stmt.run(groupId, senderId);
    if (!info.changes) break;
    await sleep(DELETE_BATCH_PAUSE_MS);
  }
}

// ── Members ──────────────────────────────────────────────────────────────────
function addMember(groupId, userId) {
  db.prepare(
    "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)"
  ).run(groupId, userId);
}

function removeMember(groupId, userId) {
  db.prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?").run(groupId, userId);
}

function isMember(groupId, userId) {
  return Boolean(
    db.prepare("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?").get(groupId, userId)
  );
}

function getMemberIds(groupId) {
  return db.prepare("SELECT user_id FROM group_members WHERE group_id = ?")
    .all(groupId)
    .map((row) => row.user_id);
}

function getMembers(groupId) {
  return db.prepare(
    "SELECT user_id, joined_at, last_read_at FROM group_members WHERE group_id = ? ORDER BY joined_at ASC"
  ).all(groupId);
}

function countMembers(groupId) {
  return db.prepare("SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?").get(groupId)?.n ?? 0;
}

function getMembership(groupId, userId) {
  return db.prepare(
    "SELECT group_id, user_id, joined_at, last_read_at FROM group_members WHERE group_id = ? AND user_id = ?"
  ).get(groupId, userId) || null;
}

// Every group a user belongs to, newest activity first, with a member count and
// the timestamp of the latest message (for sidebar ordering + unread checks).
function listGroupsForUser(userId) {
  return db.prepare(`
    SELECT g.group_id, g.name, g.owner_id, g.icon_key, g.created_at,
           gm.last_read_at,
           (SELECT COUNT(*) FROM group_members m WHERE m.group_id = g.group_id) AS member_count,
           (SELECT MAX(created_at) FROM group_messages msg WHERE msg.group_id = g.group_id) AS last_message_at,
           (SELECT COUNT(*) FROM group_messages msg2
              WHERE msg2.group_id = g.group_id
                AND msg2.sender_id != ?
                AND (gm.last_read_at IS NULL OR msg2.created_at > gm.last_read_at)
           ) AS unread_count
    FROM group_conversations g
    JOIN group_members gm ON gm.group_id = g.group_id AND gm.user_id = ?
    ORDER BY last_message_at DESC NULLS LAST, g.created_at DESC
  `).all(userId, userId);
}

function updateLastRead(groupId, userId) {
  db.prepare(
    "UPDATE group_members SET last_read_at = datetime('now') WHERE group_id = ? AND user_id = ?"
  ).run(groupId, userId);
}

// ── Messages ─────────────────────────────────────────────────────────────────
const GROUP_MESSAGE_COLS =
  "message_id, group_id, sender_id, content, reply_to_message_id, edited_at, created_at, expires_at, pinned_at, pinned_by, suppressed_embeds";

const MAX_GROUP_PINS = 50;

function getMessageById(messageId) {
  return db.prepare(`SELECT ${GROUP_MESSAGE_COLS} FROM group_messages WHERE message_id = ?`).get(messageId) || null;
}

// Mirror DM pins. Returns false (without changing anything) when the group has
// already hit MAX_GROUP_PINS and this message isn't already pinned.
function pinMessage(messageId, pinnedBy) {
  const row = db.prepare("SELECT group_id, pinned_at FROM group_messages WHERE message_id = ?").get(messageId);
  if (!row) return false;
  if (row.pinned_at) return true; // already pinned - idempotent no-op
  const count = db.prepare("SELECT COUNT(*) AS n FROM group_messages WHERE group_id = ? AND pinned_at IS NOT NULL").get(row.group_id)?.n ?? 0;
  if (count >= MAX_GROUP_PINS) return false;
  db.prepare("UPDATE group_messages SET pinned_at = datetime('now'), pinned_by = ? WHERE message_id = ?").run(pinnedBy, messageId);
  return true;
}
function unpinMessage(messageId) {
  db.prepare("UPDATE group_messages SET pinned_at = NULL, pinned_by = NULL WHERE message_id = ?").run(messageId);
}
function getPinnedMessages(groupId) {
  return db.prepare(
    `SELECT ${GROUP_MESSAGE_COLS} FROM group_messages WHERE group_id = ? AND pinned_at IS NOT NULL AND (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY datetime(pinned_at) DESC`
  ).all(groupId);
}

function saveMessage({ groupId, senderId, content, replyToMessageId = null, ttlSeconds = 0 }) {
  const id = randomUUID();
  let replyTo = null;
  if (replyToMessageId) {
    const target = db.prepare(
      "SELECT message_id FROM group_messages WHERE message_id = ? AND group_id = ?"
    ).get(replyToMessageId, groupId);
    if (target) replyTo = target.message_id;
  }
  // Auto-delete: stamp the death time once if the sender has DM auto-delete on (the
  // controller passes the TTL). No per-message timer - reads skip it, sweeper reaps it.
  if (ttlSeconds > 0) {
    db.prepare(
      "INSERT INTO group_messages (message_id, group_id, sender_id, content, reply_to_message_id, expires_at) VALUES (?, ?, ?, ?, ?, datetime('now', ?))"
    ).run(id, groupId, senderId, content, replyTo, `+${ttlSeconds} seconds`);
  } else {
    db.prepare(
      "INSERT INTO group_messages (message_id, group_id, sender_id, content, reply_to_message_id) VALUES (?, ?, ?, ?, ?)"
    ).run(id, groupId, senderId, content, replyTo);
  }
  touchGroup(groupId);
  return getMessageById(id);
}

function editMessage(messageId, content) {
  // Editing changes the content, so previously-suppressed embed indices are stale.
  db.prepare(
    "UPDATE group_messages SET content = ?, edited_at = datetime('now'), suppressed_embeds = NULL WHERE message_id = ?"
  ).run(content, messageId);
  return getMessageById(messageId);
}

// Add an embed index to a message's suppressed set (dedup + clamp 0..1). Returns
// the new array, or null if the message is gone.
function addSuppressedEmbed(messageId, index) {
  const row = db.prepare("SELECT suppressed_embeds FROM group_messages WHERE message_id = ?").get(messageId);
  if (!row) return null;
  let list = [];
  try { list = JSON.parse(row.suppressed_embeds || "[]"); } catch { list = []; }
  const idx = Math.max(0, Math.min(1, Math.trunc(Number(index))));
  if (!Number.isFinite(idx)) return list;
  if (!list.includes(idx)) list.push(idx);
  list.sort((a, b) => a - b);
  db.prepare("UPDATE group_messages SET suppressed_embeds = ? WHERE message_id = ?").run(JSON.stringify(list), messageId);
  return list;
}

function deleteMessage(messageId) {
  db.prepare("DELETE FROM group_messages WHERE message_id = ?").run(messageId);
}

// Newest-first page of messages, but never older than `sinceIso` (the caller
// passes the member's joined_at so they can't read pre-join history they have no
// key for). `before` paginates upward through history.
function getMessages(groupId, sinceIso, limit = 50, before = null) {
  const params = [groupId];
  let where = "group_id = ? AND (expires_at IS NULL OR expires_at > datetime('now'))";
  if (sinceIso) { where += " AND created_at >= ?"; params.push(sinceIso); }
  if (before) { where += " AND created_at < ?"; params.push(before); }
  params.push(limit);
  return db.prepare(
    `SELECT ${GROUP_MESSAGE_COLS} FROM group_messages WHERE ${where} ORDER BY created_at DESC, rowid DESC LIMIT ?`
  ).all(...params).reverse();
}

// Reap expired group messages in capped batches (group messages have no reactions
// table, so this is a single delete - mirrors sweepExpiredServerMessages otherwise).
async function sweepExpiredGroupMessages() {
  const stmt = db.prepare(`
    DELETE FROM group_messages WHERE rowid IN (
      SELECT rowid FROM group_messages
      WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')
      LIMIT ${DELETE_BATCH_SIZE})
  `);
  for (;;) {
    const info = stmt.run();
    if (!info.changes) break;
    await sleep(DELETE_BATCH_PAUSE_MS);
  }
}

// When a user leaves/is removed, drop only THEIR authored messages? No - group
// history stays for the remaining members (Discord keeps it). We only delete the
// whole group when it empties out.

module.exports = {
  MAX_GROUP_MEMBERS,
  INACTIVE_GROUP_TTL_DAYS,
  createGroup,
  getGroup,
  updateIcon,
  getIcon,
  renameGroup,
  setOwner,
  touchGroup,
  deleteGroup,
  getInactiveGroups,
  deleteGroupMessagesInBatches,
  getGroupIdsForUser,
  deleteUserMessagesInGroup,
  addMember,
  removeMember,
  isMember,
  getMemberIds,
  getMembers,
  countMembers,
  getMembership,
  listGroupsForUser,
  updateLastRead,
  getMessageById,
  pinMessage,
  unpinMessage,
  getPinnedMessages,
  saveMessage,
  editMessage,
  addSuppressedEmbed,
  deleteMessage,
  getMessages,
  sweepExpiredGroupMessages,
};
