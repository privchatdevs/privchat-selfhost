const { randomInt, randomUUID } = require("crypto");
const db = require("../config/db");

function randomIdPart() {
  const alphabet = "0123456789";
  let result = "";

  for (let index = 0; index < 10; index += 1) {
    result += alphabet[randomInt(alphabet.length)];
  }

  return result;
}

function createPublicUserId({ createdAt, userNumber }) {
  return `${createdAt.getTime()}${String(userNumber).padStart(4, "0")}${randomIdPart()}`;
}

function findByEmail(email) {
  return db.prepare(`
    SELECT user_id, public_user_id, user_number, username, profile_alias, bio, email, password_hash,
           profile_banner_mime,
           public_key, encrypted_private_key, key_salt, email_verified,
           two_factor_enabled, server_autodelete,
           failed_login_count, locked_until, last_login_at, created_at, updated_at
    FROM users
    WHERE email_normalized = ?
    LIMIT 1
  `).get(email.toLowerCase()) || null;
}

function findByUsername(username) {
  return db.prepare(`
    SELECT user_id, public_user_id, user_number, username, profile_alias, bio, email, password_hash,
           profile_banner_mime,
           public_key, encrypted_private_key, key_salt, email_verified,
           two_factor_enabled, server_autodelete,
           failed_login_count, locked_until, last_login_at, created_at, updated_at
    FROM users
    WHERE username_normalized = ?
    LIMIT 1
  `).get(username.toLowerCase()) || null;
}

function createUser({ username, email, passwordHash, publicKey = null, encryptedPrivateKey = null, keySalt = null }) {
  const userId = randomUUID();
  const createdAt = new Date();
  let publicUserId;
  let userNumber;

  db.exec("BEGIN");
  try {
    userNumber = db.prepare("SELECT COALESCE(MAX(user_number), 0) + 1 AS next_user_number FROM users").get().next_user_number;
    publicUserId = createPublicUserId({ createdAt, userNumber });

    // No avatar is stored on signup - a default initial-letter SVG is generated
    // on the fly when the picture is requested (see authService.getProfilePicture).
    // New accounts get email 2FA ON by default (two_factor_enabled = 1); they can
    // turn it off in Security settings.
    db.prepare(`
      INSERT INTO users (
        user_id, public_user_id, user_number, username, username_normalized, email, email_normalized,
        password_hash, public_key, encrypted_private_key, key_salt, two_factor_enabled, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).run(
      userId,
      publicUserId,
      userNumber,
      username,
      username.toLowerCase(),
      email,
      email.toLowerCase(),
      passwordHash,
      publicKey,
      encryptedPrivateKey,
      keySalt,
      createdAt.toISOString(),
      createdAt.toISOString()
    );

    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }

  return db.prepare(`
    SELECT user_id, public_user_id, user_number, username, profile_alias, bio, email, profile_banner_mime, public_key, encrypted_private_key, key_salt, last_login_at, created_at, updated_at FROM users WHERE user_id = ?
  `).get(userId);
}

function setEmailVerification({ userId, code, expiresAt }) {
  db.prepare(`
    UPDATE users
    SET email_verify_code = ?,
        email_verify_expires = ?,
        email_verify_sent_at = datetime('now')
    WHERE user_id = ?
  `).run(code, expiresAt, userId);
}

function getVerificationByEmail(email) {
  return db.prepare(`
    SELECT user_id, public_user_id, email, email_verified, email_verify_code, email_verify_expires, email_verify_sent_at
    FROM users
    WHERE email_normalized = ?
    LIMIT 1
  `).get(email.toLowerCase()) || null;
}

function markEmailVerified(userId) {
  db.prepare(`
    UPDATE users
    SET email_verified = 1,
        email_verify_code = NULL,
        email_verify_expires = NULL
    WHERE user_id = ?
  `).run(userId);
}

// Security settings: pass only the fields you want to change.
function updateSecuritySettings({ userId, twoFactorEnabled, serverAutodelete, autodeleteSeconds, autodeleteDms, autodeleteDmsBoth, inactiveDeleteMonths }) {
  if (typeof inactiveDeleteMonths === "number") {
    db.prepare("UPDATE users SET inactive_delete_months = ?, updated_at = datetime('now') WHERE user_id = ?")
      .run(inactiveDeleteMonths, userId);
  }
  if (typeof twoFactorEnabled === "boolean") {
    db.prepare("UPDATE users SET two_factor_enabled = ?, updated_at = datetime('now') WHERE user_id = ?")
      .run(twoFactorEnabled ? 1 : 0, userId);
  }
  if (typeof serverAutodelete === "boolean") {
    db.prepare("UPDATE users SET server_autodelete = ?, updated_at = datetime('now') WHERE user_id = ?")
      .run(serverAutodelete ? 1 : 0, userId);
  }
  if (typeof autodeleteSeconds === "number") {
    db.prepare("UPDATE users SET autodelete_seconds = ?, updated_at = datetime('now') WHERE user_id = ?")
      .run(autodeleteSeconds, userId);
  }
  if (typeof autodeleteDms === "boolean") {
    const current = db.prepare("SELECT autodelete_dms FROM users WHERE user_id = ?").get(userId);
    const wasOn = Boolean(current?.autodelete_dms);
    if (autodeleteDms && !wasOn) {
      // Off → on: stamp the moment so we can post a one-time notice per chat.
      db.prepare("UPDATE users SET autodelete_dms = 1, autodelete_dms_since = datetime('now'), updated_at = datetime('now') WHERE user_id = ?")
        .run(userId);
    } else if (!autodeleteDms) {
      db.prepare("UPDATE users SET autodelete_dms = 0, autodelete_dms_since = NULL, updated_at = datetime('now') WHERE user_id = ?")
        .run(userId);
    }
    // Already on (e.g. just changing the duration): leave the "since" stamp alone.
  }
  if (typeof autodeleteDmsBoth === "boolean") {
    db.prepare("UPDATE users SET autodelete_dms_both = ?, updated_at = datetime('now') WHERE user_id = ?")
      .run(autodeleteDmsBoth ? 1 : 0, userId);
  }
}

// Who may DM / friend-request this user (anyone | mutual_servers | friends_of_friends).
function getPrivacySettings(userId) {
  const row = db.prepare(
    "SELECT dm_privacy, friend_request_privacy FROM users WHERE user_id = ?"
  ).get(userId);
  return {
    // Nullish (not ||) so an explicit empty set ("nobody new") is preserved.
    dmPrivacy: row?.dm_privacy ?? "mutual_servers",
    friendRequestPrivacy: row?.friend_request_privacy ?? "anyone",
  };
}

function updatePrivacySettings({ userId, dmPrivacy, friendRequestPrivacy }) {
  if (typeof dmPrivacy === "string") {
    db.prepare("UPDATE users SET dm_privacy = ?, updated_at = datetime('now') WHERE user_id = ?").run(dmPrivacy, userId);
  }
  if (typeof friendRequestPrivacy === "string") {
    db.prepare("UPDATE users SET friend_request_privacy = ?, updated_at = datetime('now') WHERE user_id = ?").run(friendRequestPrivacy, userId);
  }
}

// Lightweight read of just a user's auto-delete config (used at message-send time
// for both the sender and the recipient).
function getAutoDeleteSettings(userId) {
  const row = db.prepare(
    "SELECT autodelete_seconds, autodelete_dms, autodelete_dms_both, autodelete_dms_since, server_autodelete FROM users WHERE user_id = ?"
  ).get(userId);
  return {
    seconds: row?.autodelete_seconds || 86400,
    dms: Boolean(row?.autodelete_dms),
    dmsBoth: Boolean(row?.autodelete_dms_both),
    dmsSince: row?.autodelete_dms_since || null,
    servers: Boolean(row?.server_autodelete),
  };
}

function updateProfile({ userId, alias, bio }) {
  db.prepare(`
    UPDATE users
    SET profile_alias = ?,
        bio = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(alias || null, bio || null, userId);
}

// Returns the B2 object reference (or null key) for the avatar. The default
// initial-letter SVG is generated by the caller when there is no key.
function getProfilePictureRef(userId) {
  return db.prepare(`
    SELECT username, profile_picture_key, profile_picture_mime
    FROM users
    WHERE user_id = ?
    LIMIT 1
  `).get(userId);
}

function updateProfilePicture({ userId, key, mimeType }) {
  db.prepare(`
    UPDATE users
    SET profile_picture_key = ?,
        profile_picture_mime = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(key, mimeType, userId);
}

function getProfileBannerRef(userId) {
  return db.prepare(`
    SELECT profile_banner_key, profile_banner_mime
    FROM users
    WHERE user_id = ?
    LIMIT 1
  `).get(userId);
}

function updateProfileBanner({ userId, key, mimeType }) {
  // An uploaded image banner wins over a solid color, so clear any color choice.
  db.prepare(`
    UPDATE users
    SET profile_banner_key = ?,
        profile_banner_mime = ?,
        profile_banner_color = NULL,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(key, mimeType, userId);
}

// Pick a solid-color banner. Clears any uploaded image banner so the color shows
// (color is null when the user resets back to the style default).
function updateProfileBannerColor({ userId, color }) {
  db.prepare(`
    UPDATE users
    SET profile_banner_color = ?,
        profile_banner_key = NULL,
        profile_banner_mime = NULL,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(color || null, userId);
}

function updateProfileStyle({ userId, style }) {
  db.prepare(`
    UPDATE users
    SET profile_style = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(style, userId);
}

// ── App theme (whole-client recolor, only the owner sees it) ──────────────────
function getAppThemeRef(userId) {
  return db.prepare(`
    SELECT app_theme, app_theme_image_key, app_theme_image_mime, app_theme_config
    FROM users
    WHERE user_id = ?
    LIMIT 1
  `).get(userId);
}

// Save the chosen theme + its config JSON. The custom theme's image is uploaded
// separately (updateAppThemeImage) so the key/mime are left untouched here.
function updateAppTheme({ userId, theme, config }) {
  db.prepare(`
    UPDATE users
    SET app_theme = ?,
        app_theme_config = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(theme, config || null, userId);
}

function updateAppThemeImage({ userId, key, mimeType }) {
  db.prepare(`
    UPDATE users
    SET app_theme_image_key = ?,
        app_theme_image_mime = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(key, mimeType, userId);
}

function recordFailedLogin({ userId, lockAttempts, lockMinutes }) {
  db.prepare(`
    UPDATE users
    SET
      failed_login_count = failed_login_count + 1,
      locked_until = CASE
        WHEN failed_login_count + 1 >= ?
        THEN datetime('now', '+' || ? || ' minutes')
        ELSE locked_until
      END,
      updated_at = datetime('now')
    WHERE user_id = ?
  `).run(lockAttempts, lockMinutes, userId);
}

function recordSuccessfulLogin(userId) {
  db.prepare(`
    UPDATE users
    SET failed_login_count = 0,
        locked_until = NULL,
        last_login_at = datetime('now'),
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(userId);
}

function writeAuditLog({ userId = null, email, success, ipAddress, userAgent }) {
  db.prepare(`
    INSERT INTO login_audit_log (user_id, email, success, ip_address, user_agent)
    VALUES (?, ?, ?, ?, ?)
  `).run(userId, email, success ? 1 : 0, ipAddress, userAgent);
}

/**
 * Count failed login attempts within a sliding window.
 * Counts by email identifier OR by IP address (whichever produces a higher count),
 * so both per-account and per-IP brute-force attacks are caught.
 *
 * @param {object} opts
 * @param {string} opts.identifier - The email/username used in the login attempt.
 * @param {string} opts.ipAddress  - The client IP address.
 * @param {number} opts.windowSeconds - Size of the sliding window in seconds.
 * @returns {number} The highest count (by email or by IP).
 */
function countFailedLoginsInWindow({ identifier, ipAddress, windowSeconds }) {
  const byEmail = db.prepare(`
    SELECT COUNT(*) AS cnt
    FROM login_audit_log
    WHERE success = 0
      AND email = ?
      AND datetime(created_at) >= datetime('now', '-' || ? || ' seconds')
  `).get(identifier.toLowerCase(), windowSeconds);

  const byIp = db.prepare(`
    SELECT COUNT(*) AS cnt
    FROM login_audit_log
    WHERE success = 0
      AND ip_address = ?
      AND datetime(created_at) >= datetime('now', '-' || ? || ' seconds')
  `).get(ipAddress, windowSeconds);

  return Math.max(byEmail?.cnt ?? 0, byIp?.cnt ?? 0);
}

// Failed login attempts from one IP within a sliding window, regardless of which
// identifier was tried. Powers the per-IP throttle on USERNAME sign-ins (which
// never lock the account), so an attacker rotating usernames is still capped.
function countFailedLoginsByIpInWindow({ ipAddress, windowSeconds }) {
  const row = db.prepare(`
    SELECT COUNT(*) AS cnt
    FROM login_audit_log
    WHERE success = 0
      AND ip_address = ?
      AND datetime(created_at) >= datetime('now', '-' || ? || ' seconds')
  `).get(ipAddress, windowSeconds);
  return row?.cnt ?? 0;
}

function findById(userId) {
  return db.prepare(`
    SELECT user_id, public_user_id, user_number, username, profile_alias, bio, email, password_hash,
           profile_banner_mime, profile_banner_color, profile_style,
           app_theme, app_theme_image_mime, app_theme_config,
           public_key, encrypted_private_key, key_salt,
           two_factor_enabled, server_autodelete,
           autodelete_seconds, autodelete_dms, autodelete_dms_both,
           inactive_delete_months,
           dm_privacy, friend_request_privacy,
           failed_login_count, locked_until, last_login_at, last_seen_at, presence_status, created_at, updated_at, username_last_changed_at
    FROM users
    WHERE user_id = ?
    LIMIT 1
  `).get(userId) || null;
}

// Internal user_ids of accounts that have gone inactive past their own configured
// threshold (inactive_delete_months > 0). "Active" = the most recent of
// last_seen_at (heartbeat), last_login_at, or created_at. The month modifier is
// built per-row from the column so each account uses its own setting. Capped so a
// big backlog is cleared over several sweeps rather than in one heavy pass.
function getAccountsInactiveBeyondThreshold(limit = 50) {
  return db.prepare(`
    SELECT user_id FROM users
    WHERE inactive_delete_months > 0
      AND datetime(COALESCE(last_seen_at, last_login_at, created_at))
          < datetime('now', '-' || inactive_delete_months || ' months')
    LIMIT ?
  `).all(limit).map((row) => row.user_id);
}

// Among a set of member ids, return the ones currently online (active within the
// last 10 minutes), ordered by name and paginated. One query - used for large
// servers where we only show online members and page them in. Returns
// { total, ids }. (server_members lives in data.db and last_seen_at in auth.db,
// so this is the cross-DB online filter the controller can't do with a join.)
function filterOnlineMemberIds(userIds, limit, offset) {
  if (!Array.isArray(userIds) || userIds.length === 0) return { total: 0, ids: [] };
  const placeholders = userIds.map(() => "?").join(",");
  const where = `user_id IN (${placeholders}) AND last_seen_at IS NOT NULL AND datetime(last_seen_at) >= datetime('now', '-10 minutes')`;
  const total = db.prepare(`SELECT COUNT(*) AS c FROM users WHERE ${where}`).get(...userIds).c;
  const ids = db.prepare(
    `SELECT user_id FROM users WHERE ${where} ORDER BY username_normalized LIMIT ? OFFSET ?`
  ).all(...userIds, limit, offset).map((row) => row.user_id);
  return { total, ids };
}

function findByAnyId(id) {
  return db.prepare(`
    SELECT user_id, public_user_id, user_number, extra_badges, username, profile_alias, bio, email, profile_banner_mime, profile_banner_color, profile_style, last_login_at, last_seen_at, presence_status, public_key, created_at, updated_at
    FROM users
    WHERE user_id = ? OR public_user_id = ?
    LIMIT 1
  `).get(id, id) || null;
}

// People search: among a candidate set of internal ids, return those whose
// username/alias matches `query` (matched literally - % _ \ escaped). Ordered by
// name, capped. Cross-DB: the caller gathers ids from data.db (friends, DMs,
// shared servers); the profiles live here in auth.db.
function searchPeopleByIds(userIds, query, limit = 20) {
  if (!Array.isArray(userIds) || userIds.length === 0) return [];
  const ids = userIds.slice(0, 900);
  const placeholders = ids.map(() => "?").join(",");
  const like = `%${String(query).replace(/[\\%_]/g, "\\$&")}%`;
  return db.prepare(`
    SELECT user_id, public_user_id, username, profile_alias, last_seen_at, presence_status, updated_at
    FROM users
    WHERE user_id IN (${placeholders})
      AND (username LIKE ? ESCAPE '\\' OR profile_alias LIKE ? ESCAPE '\\')
    ORDER BY username_normalized
    LIMIT ?
  `).all(...ids, like, like, limit);
}

// Basic public profiles for a set of internal ids (no query filter) - used to
// attach the sender's name + avatar to message search results. Batched (one query).
function getProfilesByIds(userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return [];
  const ids = [...new Set(userIds)].slice(0, 200);
  const placeholders = ids.map(() => "?").join(",");
  return db.prepare(`
    SELECT user_id, public_user_id, username, profile_alias, updated_at
    FROM users
    WHERE user_id IN (${placeholders})
  `).all(...ids);
}

function updateUsername({ userId, username }) {
  // Users without a custom avatar get a default initial-letter SVG generated at
  // serve time, so it follows the new username automatically - nothing to do here.
  db.prepare(`
    UPDATE users
    SET username = ?,
        username_normalized = ?,
        username_last_changed_at = datetime('now'),
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(username, username.toLowerCase(), userId);
}

// Change the account password. Because the E2E private key is encrypted with a
// key derived from the password, the caller re-encrypts it under the new
// password and passes the new blob + salt so cross-device login keeps working.
// (If the client couldn't re-encrypt - e.g. no local key - those are omitted and
// only the password hash changes.)
function updatePassword({ userId, passwordHash, encryptedPrivateKey = null, keySalt = null }) {
  if (encryptedPrivateKey && keySalt) {
    db.prepare(`
      UPDATE users
      SET password_hash = ?,
          encrypted_private_key = ?,
          key_salt = ?,
          updated_at = datetime('now')
      WHERE user_id = ?
    `).run(passwordHash, encryptedPrivateKey, keySalt, userId);
    return;
  }
  db.prepare(`
    UPDATE users
    SET password_hash = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(passwordHash, userId);
}

// Reset the password from the "forgot password" flow, where the OLD password is
// unknown. The password-derived E2E key material is now unrecoverable, so it's
// cleared (the client regenerates fresh keys on next login). Also clears any
// failed-login lockout, since a successful reset proves email control.
function updatePasswordResetKeys({ userId, passwordHash }) {
  db.prepare(`
    UPDATE users
    SET password_hash = ?,
        encrypted_private_key = NULL,
        key_salt = NULL,
        public_key = NULL,
        failed_login_count = 0,
        locked_until = NULL,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(passwordHash, userId);
}

// Change the email tied to the account. The account stays verified - control was
// just re-confirmed via a code sent to the *current* email before this runs.
function updateEmail({ userId, email }) {
  db.prepare(`
    UPDATE users
    SET email = ?,
        email_normalized = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(email, email.toLowerCase(), userId);
}

function updateLastSeen(userId, presenceStatus = null) {
  if (presenceStatus) {
    db.prepare(`
      UPDATE users
      SET last_seen_at = datetime('now'),
          presence_status = ?,
          updated_at = datetime('now')
      WHERE user_id = ?
    `).run(presenceStatus, userId);
    return;
  }
  db.prepare(`
    UPDATE users
    SET last_seen_at = datetime('now'),
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(userId);
}

function updatePresenceStatus(userId, presenceStatus) {
  db.prepare(`
    UPDATE users
    SET presence_status = ?
    WHERE user_id = ?
  `).run(presenceStatus, userId);
}

// Force a user offline NOW (their last socket closed): backdate last_seen_at just
// past the 10-minute "online" window so every online check reads offline right
// away, instead of waiting out the heartbeat staleness. Only moves it backward
// (no-op if already older), and leaves the day/week/month activity windows +
// updated_at untouched, so analytics and inactivity sweeps stay accurate.
function markUserOffline(userId) {
  db.prepare(`
    UPDATE users
    SET last_seen_at = datetime('now', '-11 minutes'),
        presence_status = 'offline'
    WHERE user_id = ?
      AND (last_seen_at IS NULL OR last_seen_at > datetime('now', '-11 minutes'))
  `).run(userId);
}

function updateKeys({ userId, publicKey, encryptedPrivateKey, keySalt }) {
  db.prepare(`
    UPDATE users
    SET public_key = ?,
        encrypted_private_key = ?,
        key_salt = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `).run(publicKey, encryptedPrivateKey, keySalt, userId);
}

// Permanently remove the account from the auth DB. login_audit_log has a
// FOREIGN KEY to users with no ON DELETE rule (foreign_keys is ON), so its rows
// must go first or the users delete is rejected. user_sessions is ON DELETE
// CASCADE, so deleting the users row clears every active session automatically.
function deleteUserAccount(userId) {
  db.exec("BEGIN");
  try {
    // Hold the freed username for 7 days so a ban/deletion doesn't instantly free
    // it. Captured before the row goes; upsert in case it was reserved before.
    const owner = db.prepare("SELECT username_normalized FROM users WHERE user_id = ?").get(userId);
    if (owner?.username_normalized) {
      db.prepare(`
        INSERT INTO reserved_usernames (username_normalized, reserved_until)
        VALUES (?, datetime('now', '+7 days'))
        ON CONFLICT(username_normalized) DO UPDATE SET reserved_until = datetime('now', '+7 days')
      `).run(owner.username_normalized);
    }
    db.prepare("DELETE FROM login_audit_log WHERE user_id = ?").run(userId);
    db.prepare("DELETE FROM users WHERE user_id = ?").run(userId);
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

// Whether a username is currently held by a ban/deletion reservation (expired
// reservations don't count).
function isUsernameReserved(username) {
  if (!username) return false;
  const row = db.prepare(
    "SELECT 1 FROM reserved_usernames WHERE username_normalized = ? AND reserved_until > datetime('now') LIMIT 1"
  ).get(String(username).toLowerCase());
  return Boolean(row);
}

// Admin-assigned profile badges (CSV in users.extra_badges).
function getExtraBadges(userId) {
  const row = db.prepare("SELECT extra_badges FROM users WHERE user_id = ?").get(userId);
  return String(row?.extra_badges || "").split(",").map((b) => b.trim()).filter(Boolean);
}

function setExtraBadges(userId, badges) {
  const csv = Array.isArray(badges)
    ? [...new Set(badges.map((b) => String(b).trim()).filter(Boolean))].join(",")
    : "";
  db.prepare("UPDATE users SET extra_badges = ? WHERE user_id = ?").run(csv || null, userId);
}

// Badges the user has hidden from their profile (CSV in users.hidden_badges).
function getHiddenBadges(userId) {
  const row = db.prepare("SELECT hidden_badges FROM users WHERE user_id = ?").get(userId);
  return String(row?.hidden_badges || "").split(",").map((b) => b.trim()).filter(Boolean);
}

function setHiddenBadges(userId, badges) {
  const csv = Array.isArray(badges)
    ? [...new Set(badges.map((b) => String(b).trim()).filter(Boolean))].join(",")
    : "";
  db.prepare("UPDATE users SET hidden_badges = ? WHERE user_id = ?").run(csv || null, userId);
}

// ── Banned emails ────────────────────────────────────────────────────────────
// An admin ban records the address here so it can never sign up again, even after
// the account row is gone.
function banEmail(email, passwordHash = null) {
  if (!email) return;
  // Keep the password hash so a sign-in with the matching credentials gets the
  // "disabled" message. Update it if the email is re-banned.
  db.prepare(`
    INSERT INTO banned_emails (email_normalized, password_hash) VALUES (?, ?)
    ON CONFLICT(email_normalized) DO UPDATE SET password_hash = excluded.password_hash
  `).run(String(email).toLowerCase(), passwordHash);
}

function isEmailBanned(email) {
  if (!email) return false;
  return Boolean(db.prepare(
    "SELECT 1 FROM banned_emails WHERE email_normalized = ?"
  ).get(String(email).toLowerCase()));
}

function getBannedEmail(email) {
  if (!email) return null;
  return db.prepare(
    "SELECT email_normalized, password_hash FROM banned_emails WHERE email_normalized = ?"
  ).get(String(email).toLowerCase()) || null;
}

// ── Admin "capture IP" ───────────────────────────────────────────────────────
function setCaptureIp(userId, enabled) {
  db.prepare(
    "UPDATE users SET capture_ip = ?, updated_at = datetime('now') WHERE user_id = ?"
  ).run(enabled ? 1 : 0, userId);
}

// On sign-in: if this user is flagged for IP capture, record the IP and clear the
// flag (one-shot). Returns true if it captured.
function recordIpIfCapturing(userId, ip) {
  if (!userId || !ip) return false;
  const row = db.prepare("SELECT capture_ip FROM users WHERE user_id = ?").get(userId);
  if (!row || !row.capture_ip) return false;
  db.prepare(`
    UPDATE users
    SET captured_ip = ?, captured_ip_at = datetime('now'), capture_ip = 0, updated_at = datetime('now')
    WHERE user_id = ?
  `).run(ip, userId);
  return true;
}

function getCaptureState(userId) {
  return db.prepare(
    "SELECT capture_ip, captured_ip, captured_ip_at FROM users WHERE user_id = ?"
  ).get(userId) || null;
}

module.exports = {
  countFailedLoginsInWindow,
  countFailedLoginsByIpInWindow,
  createUser,
  deleteUserAccount,
  isUsernameReserved,
  getExtraBadges,
  setExtraBadges,
  getHiddenBadges,
  setHiddenBadges,
  banEmail,
  isEmailBanned,
  getBannedEmail,
  setCaptureIp,
  recordIpIfCapturing,
  getCaptureState,
  findByEmail,
  findByUsername,
  findById,
  findByAnyId,
  searchPeopleByIds,
  getProfilesByIds,
  filterOnlineMemberIds,
  getVerificationByEmail,
  markEmailVerified,
  setEmailVerification,
  getProfileBannerRef,
  getProfilePictureRef,
  recordFailedLogin,
  recordSuccessfulLogin,
  updateEmail,
  updateLastSeen,
  updatePresenceStatus,
  markUserOffline,
  updatePassword,
  updatePasswordResetKeys,
  updateProfile,
  updateProfileBanner,
  updateProfileBannerColor,
  updateProfileStyle,
  getAppThemeRef,
  updateAppTheme,
  updateAppThemeImage,
  updateProfilePicture,
  updateSecuritySettings,
  getAccountsInactiveBeyondThreshold,
  getPrivacySettings,
  updatePrivacySettings,
  getAutoDeleteSettings,
  updateUsername,
  updateKeys,
  writeAuditLog,
};
