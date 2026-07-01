// AutoMod - per-server automatic message moderation. Three filters (keyword, link,
// spam), each independently toggleable and each carrying its own punishment. The
// config is one JSON blob per server (serverRepository.server_automod); this module
// owns the schema, validation, and the actual message evaluation. The controller
// calls evaluate() on the send path and applies the returned action.
//
// Design notes:
//  - Filters run in a fixed priority (keyword -> link -> spam) and the FIRST match
//    wins, so a message is never punished twice for one send.
//  - The spam filter needs short-term per-user history. We keep that in memory
//    (cheap, self-pruning) rather than the DB - it's only ever a few timestamps.
//  - Punishment durations reuse the same allowed set as manual timeouts so the
//    controller's validation and the UI stay in lockstep.

const serverRepository = require("../repositories/serverRepository");

// Actions a filter can take when it matches. "delete" only blocks the message;
// the others also remove/punish the sender (the controller carries them out).
const ACTIONS = new Set(["delete", "timeout", "kick", "ban"]);
// Valid values for a filter's `action` in the config. "off" disables the filter
// (this replaces the old per-filter enable toggle AND the master switch - a
// filter simply runs when its action isn't "off").
const FILTER_ACTIONS = new Set(["off", "delete", "timeout", "kick", "ban"]);

// Allowed timeout durations (ms) - the >0 subset of the manual-timeout set so the
// controller can validate an AutoMod timeout the same way.
const TIMEOUT_OPTIONS = [
  { ms: 1800000, label: "30 minutes" },
  { ms: 3600000, label: "1 hour" },
  { ms: 21600000, label: "6 hours" },
  { ms: 43200000, label: "12 hours" },
  { ms: 86400000, label: "24 hours" },
  { ms: 259200000, label: "3 days" },
];
const TIMEOUT_MS_SET = new Set(TIMEOUT_OPTIONS.map((option) => option.ms));
const DEFAULT_TIMEOUT_MS = 3600000;

const MAX_KEYWORDS = 2000;
const MAX_KEYWORD_LENGTH = 60;
// Hard cap on the whole keyword list (matches the textarea's maxlength) so a
// tampered payload can't store an unbounded blob.
const MAX_KEYWORDS_TOTAL_CHARS = 10000;

// Spam = the same message sent repeatLimit times in a row (within a generous
// window so a stale repeat from long ago doesn't count). repeatLimit is per-server
// configurable; these bound it so it can't be set to something silly.
const SPAM_REPEAT_WINDOW_MS = 30000;
const SPAM_REPEAT_MIN = 2;
const SPAM_REPEAT_MAX = 20;
const DEFAULT_SPAM_REPEAT = 4;

// No master switch, no per-filter toggles: a filter is "on" when its action isn't
// "off". Each filter carries its own `exemptChannels` - channel ids where THAT
// rule is skipped - so you can (say) block keywords in #media but allow links
// there. Default: every active rule applies to every channel.
const MAX_EXEMPT_CHANNELS = 200;
const DEFAULT_CONFIG = {
  keyword: { action: "off", timeoutMs: DEFAULT_TIMEOUT_MS, words: [], exemptChannels: [] },
  link: { action: "off", timeoutMs: DEFAULT_TIMEOUT_MS, exemptChannels: [] },
  spam: { action: "off", timeoutMs: DEFAULT_TIMEOUT_MS, repeatLimit: DEFAULT_SPAM_REPEAT, exemptChannels: [] },
};

// Catches the common shapes of a link: a protocol, a bare "www." host, or a
// host.tld with a known-ish TLD. A heuristic by design - AutoMod errs toward
// flagging, and exempt (mod/owner) users never hit it anyway.
const LINK_RE = /(https?:\/\/[^\s]+)|(\bwww\.[^\s]+)|(\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|gg|me|co|xyz|app|dev|tv|gov|edu|info|biz|ru|uk|de|us|to|cc|link|site|online|store|fun|gl|gd|ly|sh|club|live|vip|win|top|pro)\b)/i;

function clampAction(raw, fallback) {
  return FILTER_ACTIONS.has(raw) ? raw : fallback;
}

function clampTimeout(raw) {
  const ms = Number(raw);
  return TIMEOUT_MS_SET.has(ms) ? ms : DEFAULT_TIMEOUT_MS;
}

function clampRepeat(raw) {
  const n = Math.round(Number(raw));
  if (!Number.isFinite(n)) return DEFAULT_SPAM_REPEAT;
  return Math.max(SPAM_REPEAT_MIN, Math.min(SPAM_REPEAT_MAX, n));
}

function cleanWords(raw) {
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const words = [];
  let totalChars = 0;
  for (const entry of raw) {
    if (typeof entry !== "string") continue;
    const word = entry.trim().toLowerCase().slice(0, MAX_KEYWORD_LENGTH);
    if (!word || seen.has(word)) continue;
    if (totalChars + word.length > MAX_KEYWORDS_TOTAL_CHARS) break;
    seen.add(word);
    words.push(word);
    totalChars += word.length;
    if (words.length >= MAX_KEYWORDS) break;
  }
  return words;
}

function cleanChannelIds(raw, extra = []) {
  const seen = new Set();
  const ids = [];
  for (const entry of [...(Array.isArray(raw) ? raw : []), ...extra]) {
    if (typeof entry !== "string") continue;
    const id = entry.trim().slice(0, 100);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
    if (ids.length >= MAX_EXEMPT_CHANNELS) break;
  }
  return ids;
}

// Normalise whatever the client (or storage) hands us into a known-good config.
// Always returns a fresh, fully-populated object - never trusts partial input.
function sanitizeConfig(raw) {
  const input = raw && typeof raw === "object" ? raw : {};
  const keyword = input.keyword && typeof input.keyword === "object" ? input.keyword : {};
  const link = input.link && typeof input.link === "object" ? input.link : {};
  const spam = input.spam && typeof input.spam === "object" ? input.spam : {};

  // Back-compat: configs saved before this redesign carried a master `enabled`
  // plus a per-filter `enabled`. Map those onto the new "off" action so an old
  // server's effective behaviour is preserved (nothing silently turns on).
  const masterOff = input.enabled === false;
  const deriveAction = (filterInput, fallback) => {
    const action = clampAction(filterInput.action, fallback);
    if (typeof filterInput.enabled === "boolean" && (masterOff || filterInput.enabled === false)) return "off";
    return action;
  };
  // A previous version had a single server-wide `ignoredChannels` (skip every
  // rule). Fold any of those into every filter's per-rule exempt list.
  const legacyIgnored = Array.isArray(input.ignoredChannels) ? input.ignoredChannels : [];

  return {
    keyword: {
      action: deriveAction(keyword, "off"),
      timeoutMs: clampTimeout(keyword.timeoutMs),
      words: cleanWords(keyword.words),
      exemptChannels: cleanChannelIds(keyword.exemptChannels, legacyIgnored),
    },
    link: {
      action: deriveAction(link, "off"),
      timeoutMs: clampTimeout(link.timeoutMs),
      exemptChannels: cleanChannelIds(link.exemptChannels, legacyIgnored),
    },
    spam: {
      action: deriveAction(spam, "off"),
      timeoutMs: clampTimeout(spam.timeoutMs),
      repeatLimit: clampRepeat(spam.repeatLimit),
      exemptChannels: cleanChannelIds(spam.exemptChannels, legacyIgnored),
    },
  };
}

function loadConfig(serverId) {
  const rawJson = serverRepository.getAutomodConfigRaw(serverId);
  if (!rawJson) return sanitizeConfig(DEFAULT_CONFIG);
  try {
    return sanitizeConfig(JSON.parse(rawJson));
  } catch {
    return sanitizeConfig(DEFAULT_CONFIG);
  }
}

function saveConfig(serverId, raw) {
  const clean = sanitizeConfig(raw);
  serverRepository.setAutomodConfigRaw(serverId, JSON.stringify(clean));
  return clean;
}

// ── Spam tracking (in-memory, self-pruning) ──────────────────────────────────
// key = `${serverId}:${userId}` -> { lastContent, repeat, lastAt }. Counts how many
// times in a row the SAME message was sent (a fresh message, or a gap longer than
// the window, resets the streak). Trips once the streak reaches repeatLimit.
const spamState = new Map();

function recordAndCheckRepeat(serverId, userId, content, repeatLimit) {
  const key = `${serverId}:${userId}`;
  const now = Date.now();
  const state = spamState.get(key) || { lastContent: null, repeat: 0, lastAt: 0 };

  const normalized = content.trim().toLowerCase();
  const continuesStreak = normalized && normalized === state.lastContent && (now - state.lastAt) < SPAM_REPEAT_WINDOW_MS;
  state.repeat = continuesStreak ? state.repeat + 1 : 1;
  state.lastContent = normalized;
  state.lastAt = now;

  spamState.set(key, state);

  // Opportunistic prune so the map can't grow unbounded across many servers.
  if (spamState.size > 5000) {
    for (const [k, v] of spamState) {
      if (now - v.lastAt > 60000) spamState.delete(k);
    }
  }

  return state.repeat >= repeatLimit;
}

function matchKeyword(words, content) {
  const haystack = content.toLowerCase();
  return words.find((word) => haystack.includes(word)) || null;
}

// Evaluate a single send. Returns null when nothing trips, otherwise a verdict the
// controller acts on: { filter, action, timeoutMs, userMessage, reason }.
function evaluate({ serverId, channelId, userId, content }) {
  const config = loadConfig(serverId);
  const text = typeof content === "string" ? content : "";
  // A rule runs here when its action isn't "off" AND this channel isn't on that
  // rule's exempt list - so each rule is independently on/off per channel.
  const active = (rule) => rule.action !== "off" && !(channelId && rule.exemptChannels.includes(channelId));

  if (active(config.keyword) && config.keyword.words.length) {
    const hit = matchKeyword(config.keyword.words, text);
    if (hit) {
      return verdict("keyword", config.keyword, "Your message was blocked by AutoMod (it contained a filtered word).");
    }
  }

  if (active(config.link) && LINK_RE.test(text)) {
    return verdict("link", config.link, "Your message was blocked by AutoMod (links aren't allowed here).");
  }

  // Spam is checked last; it records each send so the repeat streak stays accurate
  // even when the earlier filters didn't fire.
  if (active(config.spam)) {
    const isSpam = recordAndCheckRepeat(serverId, userId, text, config.spam.repeatLimit);
    if (isSpam) {
      return verdict("spam", config.spam, "Your message was blocked by AutoMod (you repeated the same message too many times).");
    }
  }

  return null;
}

function verdict(filter, rule, userMessage) {
  return {
    blocked: true,
    filter,
    action: rule.action,
    timeoutMs: rule.timeoutMs,
    userMessage,
    reason: `AutoMod: ${filter} filter`,
  };
}

module.exports = {
  ACTIONS,
  TIMEOUT_OPTIONS,
  TIMEOUT_MS_SET,
  DEFAULT_CONFIG,
  sanitizeConfig,
  loadConfig,
  saveConfig,
  evaluate,
};
