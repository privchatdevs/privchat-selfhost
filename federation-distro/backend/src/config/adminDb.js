const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const fs = require("fs");
const { config } = require("./env");

// admin.db holds admin-only operational data that doesn't belong in the user
// app DBs (auth.db / data.db). First table: user-submitted message reports.
const dbPath = config.adminDbPath;

const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const adminDb = new DatabaseSync(dbPath);

adminDb.exec("PRAGMA journal_mode = DELETE");
adminDb.exec("PRAGMA foreign_keys = OFF");

// One row per submitted report. reason is 'automated' | 'csam'. message_excerpt
// is a short snapshot of what the reporter saw (DMs are E2E, so the client sends
// the plaintext it had) - capped client- and server-side. No comment markers
// inside this exec(): node:sqlite silently drops the statement after an inline
// "--" comment in a multi-statement exec.
adminDb.exec(`
  CREATE TABLE IF NOT EXISTS reports (
    report_id        TEXT PRIMARY KEY,
    reporter_id      TEXT NOT NULL,
    reported_user_id TEXT NOT NULL,
    reason           TEXT NOT NULL,
    scope            TEXT,
    message_id       TEXT,
    server_id        TEXT,
    channel_id       TEXT,
    message_excerpt  TEXT,
    recent_messages  TEXT,
    details          TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS IX_reports_created_at ON reports (created_at);
  CREATE INDEX IF NOT EXISTS IX_reports_reporter_created ON reports (reporter_id, created_at);
`);

// recent_messages (a JSON snapshot of the reported user's last messages, captured
// at report time) was added later - backfill the column on existing tables.
const reportCols = adminDb.prepare("PRAGMA table_info(reports)").all();
if (!reportCols.some((column) => column.name === "recent_messages")) {
  adminDb.exec("ALTER TABLE reports ADD COLUMN recent_messages TEXT");
}
// details (free-text the reporter wrote for an "Other" report, ≤2000 chars) was
// also added later - backfill it on existing tables.
if (!reportCols.some((column) => column.name === "details")) {
  adminDb.exec("ALTER TABLE reports ADD COLUMN details TEXT");
}

// Messages the reported user deleted WHILE an automated report against them was
// still open. The message vanishes for everyone normally, but we keep our own
// copy here so the reviewer can still see what was scrubbed. Cleared once the
// report is actioned (ban) or dismissed. Keyed by the reported user's id (the
// same value stored in reports.reported_user_id) and deduped by message_id.
adminDb.exec(`
  CREATE TABLE IF NOT EXISTS preserved_messages (
    id               TEXT PRIMARY KEY,
    reported_user_id TEXT NOT NULL,
    message_id       TEXT,
    channel_id       TEXT,
    channel_name     TEXT,
    content          TEXT,
    message_created_at TEXT,
    deleted_at       TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE UNIQUE INDEX IF NOT EXISTS UX_preserved_message ON preserved_messages (message_id);
  CREATE INDEX IF NOT EXISTS IX_preserved_user ON preserved_messages (reported_user_id);
`);

// User-submitted feedback from the in-app "Help Us" panel: suggestions and bug
// reports. The admin panel's "Other" section lists these and can praise (keep +
// flag as recognized) or dismiss (delete) each. We store the sender's id +
// username so a praised contributor can be rewarded later. status is
// 'open' | 'praised' (dismissed rows are deleted outright).
adminDb.exec(`
  CREATE TABLE IF NOT EXISTS feedback (
    feedback_id  TEXT PRIMARY KEY,
    user_id      TEXT,
    public_id    TEXT,
    username     TEXT,
    kind         TEXT NOT NULL,
    message      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS IX_feedback_created ON feedback (created_at);
`);

module.exports = adminDb;
