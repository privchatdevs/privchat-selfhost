const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { config } = require("./env");

const dbPath = config.dbPath;

// Ensure database directory exists
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new DatabaseSync(dbPath);

// Performance settings
db.exec("PRAGMA journal_mode = DELETE");
db.exec("PRAGMA foreign_keys = ON");

// Auto-create schema on first run
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    user_id             TEXT NOT NULL PRIMARY KEY,
    public_user_id      TEXT,
    user_number         INTEGER,
    username            TEXT NOT NULL,
    username_normalized TEXT NOT NULL,
    email               TEXT NOT NULL,
    email_normalized    TEXT NOT NULL,
    password_hash       TEXT NOT NULL,
    encrypted_profile   TEXT,
    profile_alias       TEXT,
    bio                 TEXT,
    profile_picture_key  TEXT,
    profile_picture_mime TEXT,
    profile_banner_key   TEXT,
    profile_banner_mime  TEXT,
    public_key          TEXT,
    encrypted_private_key TEXT,
    key_salt            TEXT,
    email_verified      INTEGER NOT NULL DEFAULT 0,
    email_verify_code   TEXT,
    email_verify_expires TEXT,
    email_verify_sent_at TEXT,
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    last_login_at       TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE UNIQUE INDEX IF NOT EXISTS UX_users_email_normalized
    ON users (email_normalized);

  CREATE UNIQUE INDEX IF NOT EXISTS UX_users_username_normalized
    ON users (username_normalized);

  CREATE TABLE IF NOT EXISTS user_sessions (
    session_id  TEXT    NOT NULL PRIMARY KEY,
    user_id     TEXT    NOT NULL,
    token_hash  BLOB    NOT NULL,
    expires_at  TEXT    NOT NULL,
    revoked_at  TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
  );

  CREATE UNIQUE INDEX IF NOT EXISTS UX_user_sessions_token_hash
    ON user_sessions (token_hash);

  CREATE INDEX IF NOT EXISTS IX_user_sessions_user_id_expires_at
    ON user_sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

  CREATE TABLE IF NOT EXISTS login_audit_log (
    audit_id    INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    email       TEXT,
    success     INTEGER NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  CREATE INDEX IF NOT EXISTS IX_login_audit_log_email_created_at
    ON login_audit_log (email, created_at DESC);

  -- Emails an admin has banned. Survives the account deletion so the same address
  -- can't register again. We also keep the account's password hash so a sign-in
  -- with the matching credentials gets a "disabled" message (not the generic one).
  CREATE TABLE IF NOT EXISTS banned_emails (
    email_normalized TEXT NOT NULL PRIMARY KEY,
    password_hash    TEXT,
    banned_at        TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// A username freed by a ban or account deletion is held here until reserved_until
// so it can't be instantly re-claimed. Its own exec() (not folded into the schema
// block above) to avoid the node:sqlite multi-statement quirk.
db.exec(`
  CREATE TABLE IF NOT EXISTS reserved_usernames (
    username_normalized TEXT NOT NULL PRIMARY KEY,
    reserved_until      TEXT NOT NULL
  );
`);

function randomIdPart() {
  const alphabet = "0123456789";
  let result = "";

  for (let index = 0; index < 10; index += 1) {
    result += alphabet[crypto.randomInt(alphabet.length)];
  }

  return result;
}

function createPublicUserId({ createdAt, userNumber }) {
  const createdAtText = createdAt || new Date().toISOString();
  const createdAtInput = /z$/i.test(createdAtText) ? createdAtText : `${createdAtText}Z`;
  const createdTime = new Date(createdAtInput).getTime();
  const createdDigits = Number.isFinite(createdTime) ? String(createdTime) : String(Date.now());
  return `${createdDigits}${String(userNumber).padStart(4, "0")}${randomIdPart()}`;
}

function columnExists(tableName, columnName) {
  return db.prepare(`PRAGMA table_info(${tableName})`).all().some((column) => column.name === columnName);
}

if (!columnExists("users", "public_user_id")) {
  db.exec("ALTER TABLE users ADD COLUMN public_user_id TEXT");
}

// banned_emails predates storing the password hash for the "disabled" sign-in
// message - add it for tables created by the first version of this feature.
if (!columnExists("banned_emails", "password_hash")) {
  db.exec("ALTER TABLE banned_emails ADD COLUMN password_hash TEXT");
}

// Admin "capture IP": normally we don't surface a user's IP. When an admin flags
// a user (capture_ip = 1), their NEXT successful sign-in records the IP here and
// clears the flag (one-shot capture).
if (!columnExists("users", "capture_ip")) {
  db.exec("ALTER TABLE users ADD COLUMN capture_ip INTEGER NOT NULL DEFAULT 0");
}
if (!columnExists("users", "captured_ip")) {
  db.exec("ALTER TABLE users ADD COLUMN captured_ip TEXT");
}
if (!columnExists("users", "captured_ip_at")) {
  db.exec("ALTER TABLE users ADD COLUMN captured_ip_at TEXT");
}

if (!columnExists("users", "user_number")) {
  db.exec("ALTER TABLE users ADD COLUMN user_number INTEGER");
}

// Admin-assigned profile badges (comma-separated ids, e.g. "staff"). Set only via
// the admin panel; the derived badges (like first_10k) are computed separately.
if (!columnExists("users", "extra_badges")) {
  db.exec("ALTER TABLE users ADD COLUMN extra_badges TEXT");
}

// Badges the user has chosen to hide from their profile (CSV of badge ids). The
// user manages this from Settings → Customization; hidden ids are filtered out of
// the public badge list everywhere (their own name, server members, friends, …).
if (!columnExists("users", "hidden_badges")) {
  db.exec("ALTER TABLE users ADD COLUMN hidden_badges TEXT");
}

// Media (avatars/banners) lives in Backblaze B2 - the DB only keeps the object
// key + mime type.
if (!columnExists("users", "profile_picture_key")) {
  db.exec("ALTER TABLE users ADD COLUMN profile_picture_key TEXT");
}

if (!columnExists("users", "profile_picture_mime")) {
  db.exec("ALTER TABLE users ADD COLUMN profile_picture_mime TEXT");
}

if (!columnExists("users", "profile_banner_key")) {
  db.exec("ALTER TABLE users ADD COLUMN profile_banner_key TEXT");
}

if (!columnExists("users", "profile_banner_mime")) {
  db.exec("ALTER TABLE users ADD COLUMN profile_banner_mime TEXT");
}

// A solid-color banner the user picked instead of uploading an image (hex string,
// e.g. "#5865f2"). Mutually exclusive with the image banner: setting a color
// clears the uploaded banner key, and uploading a banner clears the color.
if (!columnExists("users", "profile_banner_color")) {
  db.exec("ALTER TABLE users ADD COLUMN profile_banner_color TEXT");
}

// Named cosmetic style for the profile card. "default" is the standard gray
// backdrop; other styles (e.g. "black") recolor the no-banner backdrop and are
// gated to specific accounts server-side.
if (!columnExists("users", "profile_style")) {
  db.exec("ALTER TABLE users ADD COLUMN profile_style TEXT NOT NULL DEFAULT 'default'");
}

// App-wide theme (recolors the whole client, only the user themselves sees it).
// "default" is the standard look; "black" darkens the gray surfaces; "custom" is
// a theme derived from an uploaded image. Gated to specific accounts server-side.
if (!columnExists("users", "app_theme")) {
  db.exec("ALTER TABLE users ADD COLUMN app_theme TEXT NOT NULL DEFAULT 'default'");
}

// B2 object key + MIME of the image backing a "custom" theme (the wallpaper shown
// behind the messages area). Null unless the user uploaded one.
if (!columnExists("users", "app_theme_image_key")) {
  db.exec("ALTER TABLE users ADD COLUMN app_theme_image_key TEXT");
}

if (!columnExists("users", "app_theme_image_mime")) {
  db.exec("ALTER TABLE users ADD COLUMN app_theme_image_mime TEXT");
}

// JSON blob for the custom theme: { blur, darken, palette:{...hex} }. The palette
// is derived from the image on the client and validated server-side before saving.
if (!columnExists("users", "app_theme_config")) {
  db.exec("ALTER TABLE users ADD COLUMN app_theme_config TEXT");
}

if (!columnExists("users", "profile_alias")) {
  db.exec("ALTER TABLE users ADD COLUMN profile_alias TEXT");
}

if (!columnExists("users", "bio")) {
  db.exec("ALTER TABLE users ADD COLUMN bio TEXT");
}

if (!columnExists("users", "username_last_changed_at")) {
  db.exec("ALTER TABLE users ADD COLUMN username_last_changed_at TEXT");
}

if (!columnExists("users", "last_seen_at")) {
  db.exec("ALTER TABLE users ADD COLUMN last_seen_at TEXT");
}

if (!columnExists("users", "presence_status")) {
  db.exec("ALTER TABLE users ADD COLUMN presence_status TEXT NOT NULL DEFAULT 'online'");
}

if (!columnExists("users", "public_key")) {
  db.exec("ALTER TABLE users ADD COLUMN public_key TEXT");
}

if (!columnExists("users", "encrypted_private_key")) {
  db.exec("ALTER TABLE users ADD COLUMN encrypted_private_key TEXT");
}

if (!columnExists("users", "key_salt")) {
  db.exec("ALTER TABLE users ADD COLUMN key_salt TEXT");
}

if (!columnExists("users", "email_verified")) {
  db.exec("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0");
  // Existing accounts predate email verification - treat them as verified.
  db.exec("UPDATE users SET email_verified = 1");
}

if (!columnExists("users", "email_verify_code")) {
  db.exec("ALTER TABLE users ADD COLUMN email_verify_code TEXT");
}

if (!columnExists("users", "email_verify_expires")) {
  db.exec("ALTER TABLE users ADD COLUMN email_verify_expires TEXT");
}

if (!columnExists("users", "email_verify_sent_at")) {
  db.exec("ALTER TABLE users ADD COLUMN email_verify_sent_at TEXT");
}

// Security settings (added later): 2FA-on-login, and auto-deleting your own
// server messages after 24h.
if (!columnExists("users", "two_factor_enabled")) {
  db.exec("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0");
}

if (!columnExists("users", "server_autodelete")) {
  db.exec("ALTER TABLE users ADD COLUMN server_autodelete INTEGER NOT NULL DEFAULT 0");
}

// Privacy: who may DM / friend-request you. Values: anyone | mutual_servers |
// friends_of_friends. DM defaults to mutual_servers (the prior behaviour: friends
// or shared-server); friend requests default to anyone (also the prior behaviour).
if (!columnExists("users", "dm_privacy")) {
  db.exec("ALTER TABLE users ADD COLUMN dm_privacy TEXT NOT NULL DEFAULT 'mutual_servers'");
}
if (!columnExists("users", "friend_request_privacy")) {
  db.exec("ALTER TABLE users ADD COLUMN friend_request_privacy TEXT NOT NULL DEFAULT 'anyone'");
}

// Global auto-delete config: one duration (seconds) + per-scope toggles. DMs can
// also opt to delete the other person's messages in your conversations.
if (!columnExists("users", "autodelete_seconds")) {
  db.exec("ALTER TABLE users ADD COLUMN autodelete_seconds INTEGER NOT NULL DEFAULT 86400");
}
if (!columnExists("users", "autodelete_dms")) {
  db.exec("ALTER TABLE users ADD COLUMN autodelete_dms INTEGER NOT NULL DEFAULT 0");
}
if (!columnExists("users", "autodelete_dms_both")) {
  db.exec("ALTER TABLE users ADD COLUMN autodelete_dms_both INTEGER NOT NULL DEFAULT 0");
}
// When DM auto-delete was last turned on (NULL when off). Used to post the
// one-time "enabled auto-delete" notice into a conversation the first time you
// message someone after enabling it.
if (!columnExists("users", "autodelete_dms_since")) {
  db.exec("ALTER TABLE users ADD COLUMN autodelete_dms_since TEXT");
}
// Telegram-style inactive-account self-destruct: delete the whole account after
// this many months with no activity (last_seen_at / last_login_at / created_at).
// 0 = never. Default 6 months - applies to new and existing accounts alike.
if (!columnExists("users", "inactive_delete_months")) {
  db.exec("ALTER TABLE users ADD COLUMN inactive_delete_months INTEGER NOT NULL DEFAULT 6");
}

db.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS UX_users_public_user_id
    ON users (public_user_id)
    WHERE public_user_id IS NOT NULL;

  CREATE UNIQUE INDEX IF NOT EXISTS UX_users_user_number
    ON users (user_number)
    WHERE user_number IS NOT NULL;
`);

const usersMissingPublicIds = db.prepare(`
  SELECT user_id, user_number, created_at
  FROM users
  WHERE public_user_id IS NULL
    OR public_user_id = ''
    OR public_user_id GLOB '*[^0-9]*'
    OR user_number IS NULL
  ORDER BY datetime(created_at), user_id
`).all();

if (usersMissingPublicIds.length > 0) {
  const nextUserNumber = db.prepare("SELECT COALESCE(MAX(user_number), 0) + 1 AS next_user_number FROM users");
  const updatePublicId = db.prepare(`
    UPDATE users
    SET user_number = ?,
        public_user_id = ?,
        updated_at = datetime('now')
    WHERE user_id = ?
  `);

  db.exec("BEGIN");
  try {
    for (const user of usersMissingPublicIds) {
      const userNumber = user.user_number || nextUserNumber.get().next_user_number;
      updatePublicId.run(
        userNumber,
        createPublicUserId({ createdAt: user.created_at, userNumber }),
        user.user_id
      );
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

module.exports = db;
