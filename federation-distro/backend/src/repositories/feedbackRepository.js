const { randomUUID } = require("crypto");
const adminDb = require("../config/adminDb");

// Suggestion / bug-report / catch-all from the in-app "Help Us" panel.
const VALID_KINDS = new Set(["suggestion", "bug", "other"]);

function createFeedback({ userId, publicId, username, kind, message }) {
  const id = randomUUID();
  adminDb
    .prepare(`
      INSERT INTO feedback (feedback_id, user_id, public_id, username, kind, message)
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .run(id, userId || null, publicId || null, username || null, kind, message);
  return id;
}

// How many notes this user has sent in the last 24h - powers a soft per-user cap
// so the inbox can't be flooded (limit: 2 suggestions per day per user).
function countByUserLastDay(userId) {
  const row = adminDb
    .prepare("SELECT COUNT(*) AS c FROM feedback WHERE user_id = ? AND created_at >= datetime('now', '-1 day')")
    .get(userId);
  return row?.c ?? 0;
}

module.exports = { VALID_KINDS, createFeedback, countByUserLastDay };
