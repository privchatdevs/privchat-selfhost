const { parseUtcTimestamp } = require("../utils/time");

const ONLINE_WINDOW_MS = 10 * 60 * 1000;
const PUBLIC_STATUSES = new Set(["online", "idle", "dnd", "offline"]);
const OWN_STATUSES = new Set(["online", "idle", "dnd", "invisible", "offline"]);

function normalizeOwnStatus(status) {
  const value = String(status || "online").toLowerCase();
  return OWN_STATUSES.has(value) ? value : "online";
}

function isRecentlyOnline(userRow) {
  const seen = parseUtcTimestamp(userRow?.last_seen_at);
  return Boolean(seen && Date.now() - seen.getTime() <= ONLINE_WINDOW_MS);
}

function publicPresenceStatus(userRow) {
  if (!isRecentlyOnline(userRow)) return "offline";
  const ownStatus = normalizeOwnStatus(userRow?.presence_status || "online");
  if (ownStatus === "invisible") return "offline";
  return PUBLIC_STATUSES.has(ownStatus) ? ownStatus : "online";
}

function isPublicOnline(userRow) {
  return publicPresenceStatus(userRow) !== "offline";
}

module.exports = {
  normalizeOwnStatus,
  publicPresenceStatus,
  isPublicOnline,
};
