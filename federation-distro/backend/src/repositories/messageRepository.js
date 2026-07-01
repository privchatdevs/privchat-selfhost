const { randomUUID } = require("crypto");
const db = require("../config/messageDb");
const { toSqliteUtc } = require("../utils/time");

const MAX_REACTION_EMOJIS = 5;

// node:sqlite is synchronous - purging a huge conversation in one DELETE would
// freeze the server. Delete in capped chunks, pausing between each.
const DELETE_BATCH_SIZE = 1000;
const DELETE_BATCH_PAUSE_MS = 25;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function deleteInBatches(sql, params) {
  const stmt = db.prepare(sql);
  for (;;) {
    const info = stmt.run(...params);
    if (!info.changes) break;
    await sleep(DELETE_BATCH_PAUSE_MS);
  }
}

// ── Save a message ─────────────────────────────────────────────────────────────

function saveMessage({ senderId, receiverId, content, replyToMessageId = null, ttlSeconds = 0 }) {
  openConversationPair(senderId, receiverId);

  const id = randomUUID();
  // Only honour a reply target that's a real message between these two users.
  let replyTo = null;
  if (replyToMessageId) {
    const target = db.prepare(`
      SELECT message_id FROM messages
      WHERE message_id = ?
        AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
    `).get(replyToMessageId, senderId, receiverId, receiverId, senderId);
    if (target) replyTo = target.message_id;
  }

  // Stamp the death time once, here (Telegram-style: computed at send from the
  // sender's + recipient's global auto-delete settings, never a per-message timer).
  const ttl = ttlSeconds;
  if (ttl > 0) {
    db.prepare(`
      INSERT INTO messages (message_id, sender_id, receiver_id, content, reply_to_message_id, expires_at)
      VALUES (?, ?, ?, ?, ?, datetime('now', ?))
    `).run(id, senderId, receiverId, content, replyTo, `+${ttl} seconds`);
  } else {
    db.prepare(`
      INSERT INTO messages (message_id, sender_id, receiver_id, content, reply_to_message_id)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, senderId, receiverId, content, replyTo);
  }
  return getMessageById(id);
}

// Has `senderId` already posted an "auto-delete enabled" system notice to
// `receiverId` since they last turned it on? Stops us re-announcing on every send.
function hasAutoDeleteNoticeSince(senderId, receiverId, sinceIso) {
  if (!sinceIso) return true; // no "since" → treat as already-handled (don't post)
  const row = db.prepare(`
    SELECT 1 FROM messages
    WHERE sender_id = ? AND receiver_id = ?
      AND created_at >= ?
      AND content LIKE '%"kind":"autodelete"%'
    LIMIT 1
  `).get(senderId, receiverId, sinceIso);
  return Boolean(row);
}

// Delete `senderId`'s previous auto-delete notices to `receiverId` (there are at
// most a handful), so only the newest enable/disable notice is ever shown.
// Returns the removed message ids so the caller can tell clients to drop them.
function deleteAutoDeleteNotices(senderId, receiverId) {
  const rows = db.prepare(`
    SELECT message_id FROM messages
    WHERE sender_id = ? AND receiver_id = ?
      AND content LIKE '%"kind":"autodelete"%'
  `).all(senderId, receiverId);
  if (rows.length) {
    db.prepare(`
      DELETE FROM messages
      WHERE sender_id = ? AND receiver_id = ?
        AND content LIKE '%"kind":"autodelete"%'
    `).run(senderId, receiverId);
  }
  return rows.map((row) => row.message_id);
}

// Distinct partners `senderId` posted an auto-delete notice to since `sinceIso`
// (i.e. the conversations where auto-delete was announced during the active
// period). Used to post the matching "disabled" notice when they turn it off.
function listAutoDeleteNoticeReceivers(senderId, sinceIso) {
  if (!sinceIso) return [];
  return db.prepare(`
    SELECT DISTINCT receiver_id FROM messages
    WHERE sender_id = ?
      AND created_at >= ?
      AND content LIKE '%"kind":"autodelete"%'
  `).all(senderId, sinceIso).map((row) => row.receiver_id);
}

// The most recent auto-delete notice `senderId` posted to `receiverId` (its
// message_id + content JSON), or null. Lets a conversation lazily refresh its
// notice on open - e.g. flip a stale "enabled" to "disabled".
function getLatestAutoDeleteNotice(senderId, receiverId) {
  return db.prepare(`
    SELECT message_id, content FROM messages
    WHERE sender_id = ? AND receiver_id = ?
      AND content LIKE '%"kind":"autodelete"%'
    ORDER BY created_at DESC, rowid DESC
    LIMIT 1
  `).get(senderId, receiverId) || null;
}

// Cancel pending auto-deletes on messages from `senderId` to `receiverId` (clear
// their future expires_at) - used when someone disables auto-delete so messages
// that were scheduled to vanish are kept. Batched so a huge chat never blocks.
async function clearPendingExpiry(senderId, receiverId) {
  await deleteInBatches(`
    UPDATE messages SET expires_at = NULL WHERE rowid IN (
      SELECT rowid FROM messages
      WHERE sender_id = ? AND receiver_id = ?
        AND expires_at IS NOT NULL AND expires_at > datetime('now')
      LIMIT ${DELETE_BATCH_SIZE})
  `, [senderId, receiverId]);
}

// Per-DM "cancel auto-delete" opt-out. The flag lives on the OWNER's side of the
// conversation pair (user_id = the person who set it), so each user controls their
// own auto-delete for the thread independently.
function getConversationAutoDeleteExempt(userId, partnerId) {
  const row = db.prepare(
    "SELECT autodelete_exempt FROM dm_conversations WHERE user_id = ? AND partner_id = ?"
  ).get(userId, partnerId);
  return Boolean(row?.autodelete_exempt);
}

// Set (or clear) the opt-out. Upserts so it works even before the conversation row
// exists on this side (mirrors openConversationPair's shape).
function setConversationAutoDeleteExempt(userId, partnerId, exempt) {
  db.prepare(`
    INSERT INTO dm_conversations (user_id, partner_id, autodelete_exempt)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id, partner_id) DO UPDATE SET autodelete_exempt = excluded.autodelete_exempt
  `).run(userId, partnerId, exempt ? 1 : 0);
}

function setConversationPinned(userId, partnerId, pinned) {
  if (pinned) {
    db.prepare(`
      INSERT INTO dm_conversations (user_id, partner_id, pinned_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(user_id, partner_id) DO UPDATE SET pinned_at = datetime('now')
    `).run(userId, partnerId);
  } else {
    db.prepare(`
      UPDATE dm_conversations
      SET pinned_at = NULL
      WHERE user_id = ? AND partner_id = ?
    `).run(userId, partnerId);
  }
  return db.prepare(`
    SELECT pinned_at
    FROM dm_conversations
    WHERE user_id = ? AND partner_id = ?
  `).get(userId, partnerId) || null;
}

function getPinnedConversationIds(userId) {
  return db.prepare(`
    SELECT partner_id
    FROM dm_conversations
    WHERE user_id = ? AND pinned_at IS NOT NULL
    ORDER BY pinned_at DESC
  `).all(userId).map((row) => row.partner_id);
}

// Reap expired DM messages (and their reactions) in capped batches so a backlog
// never freezes the synchronous DB. Returns { senderId, content } for any expiring
// attachment-marker messages so the caller can also delete the underlying media
// (not just leave a dead link) - the senderId lets the caller verify ownership
// before deleting. A single `cutoff` is captured up front and used for both the
// collect and the deletes, so we never delete a row we didn't first gather for.
async function sweepExpiredMessages() {
  const cutoff = db.prepare("SELECT datetime('now') AS t").get().t;
  const attachments = db.prepare(`
    SELECT sender_id, content FROM messages
    WHERE expires_at IS NOT NULL AND expires_at <= ?
      AND content LIKE '{%' AND content LIKE '%"_att"%'
  `).all(cutoff).map((row) => ({ senderId: row.sender_id, content: row.content }));

  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN messages m ON m.message_id = mr.message_id
      WHERE m.expires_at IS NOT NULL AND m.expires_at <= ?
      LIMIT ${DELETE_BATCH_SIZE})
  `, [cutoff]);
  await deleteInBatches(`
    DELETE FROM messages WHERE rowid IN (
      SELECT rowid FROM messages
      WHERE expires_at IS NOT NULL AND expires_at <= ?
      LIMIT ${DELETE_BATCH_SIZE})
  `, [cutoff]);

  return attachments;
}

function openConversationPair(userA, userB) {
  const open = db.prepare(`
    INSERT INTO dm_conversations (user_id, partner_id)
    VALUES (?, ?)
    ON CONFLICT(user_id, partner_id) DO UPDATE SET opened_at = datetime('now')
  `);
  open.run(userA, userB);
  open.run(userB, userA);
}

// ── Get messages between two users ─────────────────────────────────────────────
// Fetches `limit` messages, optionally only those created before `before` (ISO string).
// Returns them in chronological (oldest-first) order.

function getMessages(userA, userB, limit = 50, before = null) {
  if (before) {
    const beforeCursor = toSqliteUtc(before);
    // Fetch the `limit` messages immediately before `before`, newest-first, then reverse
    const rows = db.prepare(`
      SELECT message_id, sender_id, receiver_id, content, reply_to_message_id, edited_at, created_at, expires_at, pinned_at, pinned_by, suppressed_embeds
      FROM messages
      WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        AND created_at < ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
      ORDER BY created_at DESC, rowid DESC
      LIMIT ?
    `).all(userA, userB, userB, userA, beforeCursor, limit);
    return rows.reverse(); // put back in chronological order
  }
  // No cursor - return the most recent `limit` messages in chronological order
  const rows = db.prepare(`
    SELECT message_id, sender_id, receiver_id, content, reply_to_message_id, edited_at, created_at, expires_at, pinned_at, pinned_by, suppressed_embeds
    FROM messages
    WHERE ((sender_id = ? AND receiver_id = ?)
       OR (sender_id = ? AND receiver_id = ?))
      AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY created_at DESC, rowid DESC
    LIMIT ?
  `).all(userA, userB, userB, userA, limit);
  return rows.reverse();
}

function getMessageById(messageId) {
  return db.prepare(`
    SELECT message_id, sender_id, receiver_id, content, reply_to_message_id, edited_at, created_at, expires_at, pinned_at, pinned_by, suppressed_embeds
    FROM messages
    WHERE message_id = ?
  `).get(messageId);
}

function updateMessageContent({ messageId, senderId, receiverId, content }) {
  // Editing changes the content, so any previously-suppressed embed indices are
  // stale - clear them and let the new text's embeds render fresh.
  db.prepare(`
    UPDATE messages
    SET content = ?, edited_at = datetime('now'), suppressed_embeds = NULL
    WHERE message_id = ?
      AND sender_id = ?
      AND receiver_id = ?
  `).run(content, messageId, senderId, receiverId);

  return getMessageById(messageId);
}

// Add an embed index to a message's suppressed set (dedup + clamp 0..1). Returns
// the new array. The caller authorizes; this just records the suppression.
function addSuppressedEmbed(messageId, index) {
  const row = db.prepare("SELECT suppressed_embeds FROM messages WHERE message_id = ?").get(messageId);
  if (!row) return null;
  let list = [];
  try { list = JSON.parse(row.suppressed_embeds || "[]"); } catch { list = []; }
  const idx = Math.max(0, Math.min(1, Math.trunc(Number(index))));
  if (!Number.isFinite(idx)) return list;
  if (!list.includes(idx)) list.push(idx);
  list.sort((a, b) => a - b);
  db.prepare("UPDATE messages SET suppressed_embeds = ? WHERE message_id = ?").run(JSON.stringify(list), messageId);
  return list;
}

function deleteMessage({ messageId, senderId, receiverId }) {
  const result = db.prepare(`
    DELETE FROM messages
    WHERE message_id = ?
      AND sender_id = ?
      AND receiver_id = ?
  `).run(messageId, senderId, receiverId);

  if (result.changes) {
    db.prepare(`
      DELETE FROM message_reactions
      WHERE message_id = ?
    `).run(messageId);
  }

  return result.changes || 0;
}

// ── Pinned messages (Discord-style) ────────────────────────────────────────────
// A nullable pinned_at timestamp on the message row. Either DM participant may
// pin/unpin (DMs have no roles). Capped per conversation; listed newest-first.
const MAX_DM_PINS = 50;

// Pin a message that belongs to THIS conversation (either direction). Returns
// { ok } or { ok:false, reason }.
function pinMessage({ messageId, userA, userB, pinnedBy }) {
  const row = db.prepare(`
    SELECT message_id, pinned_at FROM messages
    WHERE message_id = ?
      AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
  `).get(messageId, userA, userB, userB, userA);
  if (!row) return { ok: false, reason: "not_found" };
  if (row.pinned_at) return { ok: true }; // idempotent
  const count = db.prepare(`
    SELECT COUNT(*) AS n FROM messages
    WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
      AND pinned_at IS NOT NULL
  `).get(userA, userB, userB, userA).n;
  if (count >= MAX_DM_PINS) return { ok: false, reason: "limit" };
  db.prepare("UPDATE messages SET pinned_at = datetime('now'), pinned_by = ? WHERE message_id = ?")
    .run(pinnedBy, messageId);
  return { ok: true };
}

function unpinMessage({ messageId, userA, userB }) {
  const result = db.prepare(`
    UPDATE messages SET pinned_at = NULL, pinned_by = NULL
    WHERE message_id = ?
      AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
  `).run(messageId, userA, userB, userB, userA);
  return { ok: Boolean(result.changes) };
}

// Pinned messages between two users, newest-pinned first (skips expired).
function getPinnedMessages(userA, userB) {
  return db.prepare(`
    SELECT message_id, sender_id, receiver_id, content, reply_to_message_id, edited_at, created_at, expires_at, pinned_at, pinned_by, suppressed_embeds
    FROM messages
    WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
      AND pinned_at IS NOT NULL
      AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY pinned_at DESC, rowid DESC
    LIMIT ${MAX_DM_PINS}
  `).all(userA, userB, userB, userA);
}

function getReactionsForMessages(messageIds, currentUserId) {
  const ids = [...new Set((messageIds || []).filter(Boolean))];
  if (ids.length === 0) return {};

  const placeholders = ids.map(() => "?").join(",");
  const rows = db.prepare(`
    SELECT
      message_id,
      emoji,
      COUNT(*) AS count,
      MAX(CASE WHEN user_id = ? THEN 1 ELSE 0 END) AS me,
      MIN(created_at) AS first_created_at
    FROM message_reactions
    WHERE message_id IN (${placeholders})
    GROUP BY message_id, emoji
    ORDER BY first_created_at ASC, emoji ASC
  `).all(currentUserId, ...ids);

  return rows.reduce((map, row) => {
    if (!map[row.message_id]) map[row.message_id] = [];
    map[row.message_id].push({
      emoji: row.emoji,
      count: row.count,
      me: Boolean(row.me),
    });
    return map;
  }, {});
}

function toggleReaction({ messageId, userId, emoji }) {
  const existing = db.prepare(`
    SELECT 1
    FROM message_reactions
    WHERE message_id = ?
      AND user_id = ?
      AND emoji = ?
  `).get(messageId, userId, emoji);

  if (existing) {
    db.prepare(`
      DELETE FROM message_reactions
      WHERE message_id = ?
        AND user_id = ?
        AND emoji = ?
    `).run(messageId, userId, emoji);
    return { action: "removed", blocked: false };
  }

  const distinct = db.prepare(`
    SELECT COUNT(DISTINCT emoji) AS count
    FROM message_reactions
    WHERE message_id = ?
  `).get(messageId);

  if ((distinct?.count || 0) >= MAX_REACTION_EMOJIS) {
    return { action: "blocked", blocked: true };
  }

  db.prepare(`
    INSERT INTO message_reactions (message_id, user_id, emoji)
    VALUES (?, ?, ?)
  `).run(messageId, userId, emoji);

  return { action: "added", blocked: false };
}

// ── Get active conversation partners for a user ────────────────────────────────
// Returns an array of { userId, lastMessageAt } sorted newest-first.

function getActiveConversations(userId) {
  return db.prepare(`
    WITH conversation_messages AS (
      SELECT
        CASE
          WHEN sender_id = ? THEN receiver_id
          ELSE sender_id
        END AS partner_id,
        message_id,
        created_at
      FROM messages
      WHERE sender_id = ? OR receiver_id = ?
    ),
    explicit_conversations AS (
      SELECT
        partner_id,
        opened_at,
        last_read_at,
        pinned_at
      FROM dm_conversations
      WHERE user_id = ?
    ),
    conversation_partners AS (
      SELECT
        partner_id,
        MAX(created_at) AS last_message_at,
        NULL AS opened_at,
        NULL AS last_read_at,
        NULL AS pinned_at
      FROM conversation_messages
      GROUP BY partner_id

      UNION ALL

      SELECT
        partner_id,
        NULL AS last_message_at,
        opened_at,
        last_read_at,
        pinned_at
      FROM explicit_conversations
    )
    SELECT
      cp.partner_id,
      COALESCE(MAX(cp.last_message_at), MAX(cp.opened_at)) AS last_message_at,
      MAX(cp.last_read_at) AS last_read_at,
      MAX(cp.pinned_at) AS pinned_at,
      (
        SELECT cm2.message_id
        FROM conversation_messages cm2
        WHERE cm2.partner_id = cp.partner_id
        ORDER BY cm2.created_at DESC, cm2.message_id DESC
        LIMIT 1
      ) AS last_message_id
    FROM conversation_partners cp
    GROUP BY cp.partner_id
    ORDER BY
      CASE WHEN MAX(cp.pinned_at) IS NOT NULL THEN 0 ELSE 1 END ASC,
      last_message_at DESC
    LIMIT 50
  `).all(userId, userId, userId, userId)
    .map((r) => ({
      userId: r.partner_id,
      lastMessageAt: r.last_message_at,
      lastMessageId: r.last_message_id,
      lastReadAt: r.last_read_at,
      pinnedAt: r.pinned_at,
    }));
}

// Record that `userId` has read the conversation with `partnerId` up to now.
// Upserts the row so a never-messaged conversation can still carry a read marker.
function markConversationRead(userId, partnerId) {
  db.prepare(`
    INSERT INTO dm_conversations (user_id, partner_id, last_read_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(user_id, partner_id) DO UPDATE SET last_read_at = datetime('now')
  `).run(userId, partnerId);
}

async function purgeConversation(userA, userB) {
  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN messages m ON m.message_id = mr.message_id
      WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
      LIMIT ${DELETE_BATCH_SIZE})
  `, [userA, userB, userB, userA]);
  await deleteInBatches(`
    DELETE FROM messages WHERE rowid IN (
      SELECT rowid FROM messages
      WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
      LIMIT ${DELETE_BATCH_SIZE})
  `, [userA, userB, userB, userA]);
}

// Wipe every DM message (and its reactions) the user is part of - sent OR
// received - in capped batches, WITHOUT closing the conversations. The
// dm_conversations rows are left alone, so the threads stay listed (just
// emptied). Used by the forgot-password reset, where the user's E2E-encrypted
// DMs can no longer be decrypted, so the ciphertext is purged rather than left
// as unreadable junk. NOTE: rows are shared, so this also clears the history for
// the people they were talking to.
async function deleteAllDmMessagesForUser(userId) {
  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN messages m ON m.message_id = mr.message_id
      WHERE m.sender_id = ? OR m.receiver_id = ?
      LIMIT ${DELETE_BATCH_SIZE})
  `, [userId, userId]);
  await deleteInBatches(`
    DELETE FROM messages WHERE rowid IN (
      SELECT rowid FROM messages
      WHERE sender_id = ? OR receiver_id = ?
      LIMIT ${DELETE_BATCH_SIZE})
  `, [userId, userId]);
}

// Close (un-list) every DM thread for this user by dropping their own
// dm_conversations rows. Only the user's side is removed, so the threads
// disappear from THEIR sidebar; the other person keeps their own copy.
function closeAllConversationsForUser(userId) {
  db.prepare("DELETE FROM dm_conversations WHERE user_id = ?").run(userId);
}

// Close the open DM thread between two users (both directions). Drops only the
// dm_conversations rows - message history is kept. Used when a friendship ends
// so the "open thread" bypass no longer lets the removed person message past
// the recipient's DM privacy.
function closeConversationPair(userA, userB) {
  const close = db.prepare("DELETE FROM dm_conversations WHERE user_id = ? AND partner_id = ?");
  close.run(userA, userB);
  close.run(userB, userA);
}

function getConversationPartnerIds(userId) {
  return db.prepare(`
    SELECT DISTINCT partner_id
    FROM (
      SELECT receiver_id AS partner_id FROM messages WHERE sender_id = ?
      UNION
      SELECT sender_id AS partner_id FROM messages WHERE receiver_id = ?
      UNION
      SELECT partner_id FROM dm_conversations WHERE user_id = ?
    )
    WHERE partner_id IS NOT NULL
  `).all(userId, userId, userId).map((row) => row.partner_id);
}

// Whether an opened DM thread already exists between these two (either direction).
// Used so privacy rules gate only NEW conversations, never replies in an open one.
function conversationExists(userA, userB) {
  return Boolean(db.prepare(
    "SELECT 1 FROM dm_conversations WHERE user_id = ? AND partner_id = ? LIMIT 1"
  ).get(userA, userB));
}

module.exports = {
  conversationExists,
  saveMessage,
  openConversationPair,
  getMessages,
  getMessageById,
  updateMessageContent,
  addSuppressedEmbed,
  deleteMessage,
  getReactionsForMessages,
  toggleReaction,
  pinMessage,
  unpinMessage,
  getPinnedMessages,
  getActiveConversations,
  markConversationRead,
  getConversationPartnerIds,
  closeAllConversationsForUser,
  closeConversationPair,
  purgeConversation,
  deleteAllDmMessagesForUser,
  hasAutoDeleteNoticeSince,
  listAutoDeleteNoticeReceivers,
  getLatestAutoDeleteNotice,
  deleteAutoDeleteNotices,
  clearPendingExpiry,
  getConversationAutoDeleteExempt,
  setConversationAutoDeleteExempt,
  setConversationPinned,
  getPinnedConversationIds,
  sweepExpiredMessages,
};
