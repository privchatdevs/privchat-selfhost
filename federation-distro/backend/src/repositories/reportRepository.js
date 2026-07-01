const { randomUUID } = require("crypto");
const adminDb = require("../config/adminDb");

const VALID_REASONS = new Set(["automated", "csam", "profile", "other"]);

function createReport({ reporterId, reportedUserId, reason, scope, messageId, serverId, channelId, messageExcerpt, recentMessages, details }) {
  const id = randomUUID();
  adminDb
    .prepare(`
      INSERT INTO reports
        (report_id, reporter_id, reported_user_id, reason, scope, message_id, server_id, channel_id, message_excerpt, recent_messages, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      id,
      reporterId,
      reportedUserId,
      reason,
      scope || null,
      messageId || null,
      serverId || null,
      channelId || null,
      messageExcerpt || null,
      recentMessages && recentMessages.length ? JSON.stringify(recentMessages) : null,
      details || null
    );
  return id;
}

// How many reports this user has filed in the last hour - powers the hidden
// "2 reports per hour" limit.
function countByReporterLastHour(reporterId) {
  const row = adminDb
    .prepare("SELECT COUNT(*) AS c FROM reports WHERE reporter_id = ? AND created_at >= datetime('now', '-1 hour')")
    .get(reporterId);
  return row?.c ?? 0;
}

function getTotalCount() {
  return adminDb.prepare("SELECT COUNT(*) AS c FROM reports").get()?.c ?? 0;
}

// ── Preserved messages (deleted while an automated report was open) ───────────
function idPlaceholders(ids) {
  return ids.map(() => "?").join(",");
}
function cleanIds(userIds) {
  return [...new Set((Array.isArray(userIds) ? userIds : [userIds]).filter(Boolean).map(String))];
}

// True if any of the given ids (a user's internal + public id) has an open
// "automated" report. Used to decide whether to keep a copy when they delete.
function hasOpenAutomatedReport(userIds) {
  const ids = cleanIds(userIds);
  if (!ids.length) return false;
  const row = adminDb
    .prepare(`SELECT 1 FROM reports WHERE reason = 'automated' AND reported_user_id IN (${idPlaceholders(ids)}) LIMIT 1`)
    .get(...ids);
  return Boolean(row);
}

// Keep our own copy of a message the reported user just deleted. Deduped by
// message_id (INSERT OR IGNORE on the unique index), so re-deletes are no-ops.
function preserveDeletedMessage({ reportedUserId, messageId, channelId, channelName, content, createdAt }) {
  adminDb
    .prepare(`
      INSERT OR IGNORE INTO preserved_messages
        (id, reported_user_id, message_id, channel_id, channel_name, content, message_created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(randomUUID(), String(reportedUserId), messageId || null, channelId || null, channelName || null, content || "", createdAt || null);
}

function getPreservedMessages(userIds) {
  const ids = cleanIds(userIds);
  if (!ids.length) return [];
  return adminDb
    .prepare(`
      SELECT content, message_created_at AS created_at, channel_name, deleted_at
      FROM preserved_messages
      WHERE reported_user_id IN (${idPlaceholders(ids)})
      ORDER BY message_created_at ASC, deleted_at ASC
    `)
    .all(...ids);
}

function clearPreservedMessages(userIds) {
  const ids = cleanIds(userIds);
  if (!ids.length) return;
  adminDb.prepare(`DELETE FROM preserved_messages WHERE reported_user_id IN (${idPlaceholders(ids)})`).run(...ids);
}

// How many reports still reference this user (used to decide whether clearing the
// preserved copies is safe - i.e. no other open report still needs them).
function countReportsForUser(userIds) {
  const ids = cleanIds(userIds);
  if (!ids.length) return 0;
  const row = adminDb
    .prepare(`SELECT COUNT(*) AS c FROM reports WHERE reported_user_id IN (${idPlaceholders(ids)})`)
    .get(...ids);
  return row?.c ?? 0;
}

function getCountLastHour() {
  return adminDb.prepare("SELECT COUNT(*) AS c FROM reports WHERE created_at >= datetime('now', '-1 hour')").get()?.c ?? 0;
}

module.exports = {
  VALID_REASONS,
  createReport,
  countByReporterLastHour,
  getTotalCount,
  getCountLastHour,
  hasOpenAutomatedReport,
  preserveDeletedMessage,
  getPreservedMessages,
  clearPreservedMessages,
  countReportsForUser,
};
