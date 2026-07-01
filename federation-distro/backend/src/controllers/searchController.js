const { config } = require("../config/env");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const friendRepository = require("../repositories/friendRepository");
const messageRepository = require("../repositories/messageRepository");
const serverRepository = require("../repositories/serverRepository");
const userRepository = require("../repositories/userRepository");
const { isPublicOnline, publicPresenceStatus } = require("../services/presence");

// Two read-only searches:
//   GET /api/search/people  - people you can reach: friends, past DMs, mutual-server
//                             members (NOT a global user directory).
//   GET /api/search         - global: servers/channels are resolved client-side;
//                             here we return matching channels + server-channel
//                             MESSAGE content the user is allowed to see. DMs and
//                             group chats are E2E and intentionally not searchable.

const MIN_QUERY = 2;
const PEOPLE_LIMIT = 20;
const CHANNEL_LIMIT = 20;
const MESSAGE_LIMIT = 30;
const SNIPPET_PAD = 60;

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}
async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

function pfpUrl(publicId, updatedAt) {
  return `/api/auth/profile-picture?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(updatedAt || "")}`;
}

// A short excerpt centred on the first (case-insensitive) match, with ellipses.
function makeSnippet(content, query) {
  const text = String(content || "").replace(/\s+/g, " ").trim();
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx < 0) return text.slice(0, SNIPPET_PAD * 2);
  const start = Math.max(0, idx - SNIPPET_PAD);
  const end = Math.min(text.length, idx + query.length + SNIPPET_PAD);
  return (start > 0 ? "…" : "") + text.slice(start, end) + (end < text.length ? "…" : "");
}

// People you can reach: friends + people you've DMed + people who share a server
// with you. Deduped on INTERNAL ids, self + blocked (either direction) removed,
// then resolved/filtered against auth.db in one batched query. Returns PUBLIC ids.
async function searchPeople(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ error: "Not authenticated." });
    const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
    if (q.length < MIN_QUERY) return res.json({ people: [] });

    const me = user.user_id;
    const ids = new Set();
    friendRepository.getFriends(me).forEach((f) => ids.add(f.user_id));
    messageRepository.getActiveConversations(me).forEach((c) => ids.add(c.userId));
    serverRepository.getSharedMemberIdsForUser(me).forEach((id) => ids.add(id));
    ids.delete(me);
    friendRepository.getBlockedIdsForUser(me).forEach((id) => ids.delete(id));

    const rows = userRepository.searchPeopleByIds([...ids], q, PEOPLE_LIMIT);
    const people = rows.map((u) => {
      const publicId = u.public_user_id || u.user_id;
      return {
        userId: publicId,
        username: u.username,
        alias: u.profile_alias || "",
        profilePictureUrl: pfpUrl(publicId, u.updated_at),
        isOnline: isPublicOnline(u),
        presenceStatus: publicPresenceStatus(u),
      };
    });
    return res.json({ people });
  } catch (err) {
    return next(err);
  }
}

// Global search: channels (by name) + server-channel messages (by content), both
// strictly limited to channels the user can view. Servers are matched client-side.
async function searchGlobal(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ error: "Not authenticated." });
    const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
    if (q.length < MIN_QUERY) return res.json({ channels: [], messages: [] });

    const viewable = serverRepository.getViewableTextChannelsForUser(user.user_id);
    const needle = q.toLowerCase();

    const channels = viewable
      .filter((c) => (c.channelName || "").toLowerCase().includes(needle))
      .slice(0, CHANNEL_LIMIT);

    const byChannel = new Map(viewable.map((c) => [c.channelId, c]));
    const rows = serverRepository.searchMessagesInChannels(
      viewable.map((c) => c.channelId),
      q,
      MESSAGE_LIMIT
    );
    // Attach each message's sender (name + avatar) - resolved in one batched query.
    const senders = new Map(
      userRepository.getProfilesByIds(rows.map((m) => m.sender_id)).map((u) => [u.user_id, u])
    );
    const messages = rows.map((m) => {
      const ch = byChannel.get(m.channel_id) || {};
      const u = senders.get(m.sender_id);
      const senderPublicId = u ? (u.public_user_id || u.user_id) : m.sender_id;
      return {
        messageId: m.message_id,
        channelId: m.channel_id,
        channelName: ch.channelName || "",
        serverId: ch.serverId || "",
        serverName: ch.serverName || "",
        senderId: senderPublicId,
        senderName: u ? (u.profile_alias || u.username || "Unknown") : "Unknown",
        senderAvatarUrl: pfpUrl(senderPublicId, u && u.updated_at),
        snippet: makeSnippet(m.content, q),
        createdAt: m.created_at,
      };
    });

    return res.json({ channels, messages });
  } catch (err) {
    return next(err);
  }
}

module.exports = { searchPeople, searchGlobal };
