const { randomUUID } = require("crypto");
const db = require("../config/db");

function createSession({ userId, tokenHash, expiresAt, ipAddress, userAgent }) {
  const sessionId = randomUUID();
  db.prepare(`
    INSERT INTO user_sessions (session_id, user_id, token_hash, expires_at, ip_address, user_agent)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    sessionId,
    userId,
    tokenHash,
    expiresAt.toISOString(),
    ipAddress,
    userAgent
  );
}

function revokeSession(tokenHash) {
  db.prepare(`
    UPDATE user_sessions
    SET revoked_at = datetime('now')
    WHERE token_hash = ?
  `).run(tokenHash);
}

// Revoke every other live session for a user, keeping the one making the request
// (its token hash) alive. Used after a password change so any other device - or a
// hijacked session - is signed out, without logging the current device out.
function revokeOtherSessions(userId, keepTokenHash) {
  const result = db.prepare(`
    UPDATE user_sessions
    SET revoked_at = datetime('now')
    WHERE user_id = ?
      AND token_hash != ?
      AND revoked_at IS NULL
  `).run(userId, keepTokenHash);
  return result.changes || 0;
}

// Revoke ALL live sessions for a user. Used after a forgot-password reset, where
// there's no trusted current device to keep signed in.
function revokeAllSessions(userId) {
  const result = db.prepare(`
    UPDATE user_sessions
    SET revoked_at = datetime('now')
    WHERE user_id = ? AND revoked_at IS NULL
  `).run(userId);
  return result.changes || 0;
}

// Removes dead session rows (logged-out or past their expiry). They're already
// rejected by findUserBySession, so deleting them is purely housekeeping.
function purgeExpiredSessions() {
  const result = db.prepare(`
    DELETE FROM user_sessions
    WHERE revoked_at IS NOT NULL
       OR datetime(expires_at) < datetime('now')
  `).run();
  return result.changes || 0;
}

function findUserBySession(tokenHash) {
  return db.prepare(`
    SELECT
      u.user_id,
      u.public_user_id,
      u.user_number,
      u.username,
      u.profile_alias,
      u.bio,
      u.profile_banner_mime,
      u.profile_banner_color,
      u.profile_style,
      u.app_theme,
      u.app_theme_image_mime,
      u.app_theme_config,
      u.email,
      u.last_login_at,
      u.created_at,
      u.updated_at,
      u.username_last_changed_at,
      u.two_factor_enabled,
      u.server_autodelete,
      u.autodelete_seconds,
      u.autodelete_dms,
      u.autodelete_dms_both,
      u.inactive_delete_months,
      u.dm_privacy,
      u.friend_request_privacy
    FROM user_sessions s
    INNER JOIN users u ON u.user_id = s.user_id
    WHERE
      s.token_hash = ?
      AND s.revoked_at IS NULL
      AND datetime(s.expires_at) > datetime('now')
    LIMIT 1
  `).get(tokenHash) || null;
}

module.exports = { createSession, findUserBySession, revokeSession, revokeOtherSessions, revokeAllSessions, purgeExpiredSessions };
