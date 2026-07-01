"use strict";

// Per-user bandwidth accounting. Attributes bytes moved by this Node process to
// individual signed-in users (the WebSocket layer records through it too).
// It is an HONEST SUBSET - only
// traffic this Node process actually moves and can tie to a user:
//   • HTTP request + response bytes (API calls, proxied media up/downloads)
//   • WebSocket frames in + out (realtime messages, presence, call signaling)
// It does NOT include WebRTC voice/video media (peer-to-peer / TURN, off this
// process) or traffic from logged-out clients. So it's "tracked HTTP+WS bandwidth
// per user", never total wire bandwidth - the admin UI labels it that way.
//
// Design mirrors serverMetrics: accumulate the current minute in RAM, flush one
// row per active user per minute to admin.db, prune to the last 8 hours. RAM stays
// flat - it only ever holds the users active in the current minute.

const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const { config } = require("../config/env");

const MINUTE_MS = 60 * 1000;
const RETENTION_MS = 8 * 60 * 60 * 1000; // keep the last 8 hours of samples
const HOUR_MS = 60 * MINUTE_MS;
const SESSION_CACHE_TTL_MS = 60 * 1000; // how long a token->userId resolution is reused

// userId -> { in, out } bytes accumulated toward the current (unflushed) minute.
let minute = new Map();
let minuteStartedAt = Date.now();
let tableReady = false;

// token hash -> { userId, exp }. Avoids a sessions-table lookup on every request;
// for a user hammering the API it collapses to one lookup per minute.
const sessionCache = new Map();

function getDb() {
  try { return require("../config/adminDb"); } catch { return null; }
}

function ensureTable() {
  const db = getDb();
  if (!db) return null;
  if (tableReady) return db;
  try {
    // ts = epoch ms at the end of the minute window. One row per (minute, user).
    // Separate exec() calls (not one multi-statement string) to dodge the
    // node:sqlite gotcha where a statement after an inline "--" comment is dropped.
    db.exec("CREATE TABLE IF NOT EXISTS user_bandwidth_samples (ts INTEGER NOT NULL, user_id TEXT NOT NULL, ingress INTEGER NOT NULL DEFAULT 0, egress INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (ts, user_id))");
    db.exec("CREATE INDEX IF NOT EXISTS IX_user_bw_ts ON user_bandwidth_samples (ts)");
    db.exec("CREATE INDEX IF NOT EXISTS IX_user_bw_user_ts ON user_bandwidth_samples (user_id, ts)");
    tableReady = true;
    return db;
  } catch {
    return null;
  }
}

// Persist the minute's per-user tallies (one row each) inside a single
// transaction, then drop anything older than the 8-hour window. Best-effort: a DB
// hiccup just loses that one minute.
function flush(now = Date.now()) {
  const pending = minute;
  minute = new Map();
  minuteStartedAt = now;

  const db = ensureTable();
  if (!db) return;
  try {
    if (pending.size > 0) {
      const stmt = db.prepare(
        "INSERT INTO user_bandwidth_samples (ts, user_id, ingress, egress) VALUES (?, ?, ?, ?) " +
        "ON CONFLICT(ts, user_id) DO UPDATE SET ingress = ingress + excluded.ingress, egress = egress + excluded.egress"
      );
      db.exec("BEGIN");
      try {
        for (const [userId, b] of pending) {
          stmt.run(now, userId, Math.round(b.in || 0), Math.round(b.out || 0));
        }
        db.exec("COMMIT");
      } catch (err) {
        try { db.exec("ROLLBACK"); } catch { /* ignore */ }
        throw err;
      }
    }
    db.prepare("DELETE FROM user_bandwidth_samples WHERE ts < ?").run(now - RETENTION_MS);
  } catch { /* persistence is best-effort */ }
}

function maybeFlush() {
  if (Date.now() - minuteStartedAt >= MINUTE_MS) flush();
}

// Add bytes for a user toward the current minute. ingress = bytes received from
// them, egress = bytes sent to them. No-ops without a user or with nothing to add.
function record(userId, { ingress = 0, egress = 0 } = {}) {
  if (!userId || (ingress <= 0 && egress <= 0)) return;
  const cur = minute.get(userId) || { in: 0, out: 0 };
  if (ingress > 0) cur.in += ingress;
  if (egress > 0) cur.out += egress;
  minute.set(userId, cur);
  maybeFlush();
}

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}

// Resolve the signed-in user's internal id for a request, cached by token hash so
// the sessions table isn't hit on every request. Returns null when not signed in
// (those bytes simply aren't attributed to anyone).
function resolveUserId(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  let hash;
  try { hash = hashSessionToken(token); } catch { return null; }
  const now = Date.now();
  const cached = sessionCache.get(hash);
  if (cached && cached.exp > now) return cached.userId;
  let userId = null;
  try { userId = sessionRepository.findUserBySession(hash)?.user_id || null; } catch { userId = null; }
  sessionCache.set(hash, { userId, exp: now + SESSION_CACHE_TTL_MS });
  if (sessionCache.size > 5000) {
    for (const [k, v] of sessionCache) { if (v.exp <= now) sessionCache.delete(k); }
  }
  return userId;
}

// Express middleware: count this request's wire bytes (headers + body, BOTH
// directions) via the socket's cumulative counters, attributing them to the
// signed-in user once the response finishes. WebSocket upgrades never reach here
// (handled on server "upgrade"), so HTTP and WS are counted independently with no
// overlap. nginx terminates TLS, so these are plaintext content bytes - exactly
// the throughput we care about.
function httpMiddleware(req, res, next) {
  const socket = req.socket;
  if (socket) {
    const startRead = socket.bytesRead || 0;
    const startWritten = socket.bytesWritten || 0;
    let done = false;
    const finalize = () => {
      if (done) return;
      done = true;
      const ingress = Math.max(0, (socket.bytesRead || 0) - startRead);
      const egress = Math.max(0, (socket.bytesWritten || 0) - startWritten);
      const userId = resolveUserId(req);
      if (userId) record(userId, { ingress, egress });
    };
    res.on("finish", finalize);
    res.on("close", finalize);
  }
  next();
}

// Fold the in-RAM current minute into a userId -> {in,out} map so live reads
// include the not-yet-flushed minute (matching serverMetrics' behaviour).
function mergeCurrentMinute(map, filter) {
  for (const [userId, b] of minute) {
    if (filter && !filter.has(userId)) continue;
    const cur = map.get(userId) || { in: 0, out: 0 };
    cur.in += b.in;
    cur.out += b.out;
    map.set(userId, cur);
  }
}

// Top users by total tracked bytes over the window. -> [{ userId, ingress, egress, total }]
function getTopUsers(windowMs = HOUR_MS, limit = 15) {
  const since = Date.now() - windowMs;
  const map = new Map();
  const db = ensureTable();
  if (db) {
    try {
      for (const r of db.prepare(
        "SELECT user_id, SUM(ingress) AS i, SUM(egress) AS o FROM user_bandwidth_samples WHERE ts >= ? GROUP BY user_id"
      ).all(since)) {
        map.set(r.user_id, { in: r.i || 0, out: r.o || 0 });
      }
    } catch { /* fall through */ }
  }
  mergeCurrentMinute(map, null);
  return [...map.entries()]
    .map(([userId, b]) => ({ userId, ingress: b.in, egress: b.out, total: b.in + b.out }))
    .sort((a, b) => b.total - a.total)
    .slice(0, limit);
}

// Per-user totals over the window for a specific set of internal ids (used to fill
// the Top-senders Bandwidth column). -> Map userId -> { ingress, egress, total }
function getUserTotals(userIds, windowMs = HOUR_MS) {
  const ids = [...new Set((userIds || []).filter(Boolean))];
  const out = new Map();
  if (ids.length === 0) return out;
  const since = Date.now() - windowMs;
  const db = ensureTable();
  if (db) {
    try {
      const ph = ids.map(() => "?").join(",");
      for (const r of db.prepare(
        `SELECT user_id, SUM(ingress) AS i, SUM(egress) AS o FROM user_bandwidth_samples WHERE ts >= ? AND user_id IN (${ph}) GROUP BY user_id`
      ).all(since, ...ids)) {
        out.set(r.user_id, { ingress: r.i || 0, egress: r.o || 0, total: (r.i || 0) + (r.o || 0) });
      }
    } catch { /* fall through */ }
  }
  const filter = new Set(ids);
  for (const [userId, b] of minute) {
    if (!filter.has(userId)) continue;
    const cur = out.get(userId) || { ingress: 0, egress: 0, total: 0 };
    cur.ingress += b.in;
    cur.egress += b.out;
    cur.total += b.in + b.out;
    out.set(userId, cur);
  }
  return out;
}

// Server-wide attributed totals over the window.
function getServerTotals(windowMs = HOUR_MS) {
  const since = Date.now() - windowMs;
  let ingress = 0;
  let egress = 0;
  const db = ensureTable();
  if (db) {
    try {
      const r = db.prepare(
        "SELECT COALESCE(SUM(ingress), 0) AS i, COALESCE(SUM(egress), 0) AS o FROM user_bandwidth_samples WHERE ts >= ?"
      ).get(since);
      ingress = r?.i || 0;
      egress = r?.o || 0;
    } catch { /* fall through */ }
  }
  for (const b of minute.values()) { ingress += b.in; egress += b.out; }
  return { ingress, egress, total: ingress + egress };
}

let timer = null;
function start() {
  if (timer) return;
  // Flush every minute even when idle, so the last minute lands and old rows are
  // pruned on a quiet server too.
  timer = setInterval(() => { try { flush(); } catch { /* ignore */ } }, MINUTE_MS);
  timer.unref?.();
}

start();

module.exports = {
  record,
  httpMiddleware,
  resolveUserId,
  getTopUsers,
  getUserTotals,
  getServerTotals,
  flush,
  HOUR_MS,
};
