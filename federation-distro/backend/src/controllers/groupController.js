const { config } = require("../config/env");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const userRepository = require("../repositories/userRepository");
const groupRepository = require("../repositories/groupRepository");
const groupService = require("../services/groupService");
const b2Storage = require("../services/b2Storage");
const { generateInitialProfilePicture } = require("../services/profilePicture");
const { broadcastToGroupMembers, broadcastToUser } = require("../services/websocketServer");
const { getUserBadges } = require("../services/badges");
const { toUtcIso } = require("../utils/time");
const { isPublicOnline, publicPresenceStatus } = require("../services/presence");

// Group content is an E2E ciphertext blob with one wrapped AES key per member, so
// it's much larger than a 1:1 DM blob - allow plenty of headroom (20 RSA-2048
// wrapped keys + ciphertext is well under this).
const MAX_GROUP_CONTENT = 200_000;
const MAX_GROUP_ICON_BYTES = 3 * 1024 * 1024; // 3 MB, same cap as server icons

// Magic-bytes image sniff (PNG / JPEG / WEBP), mirroring the server-icon check.
function detectImageMime(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) return "image/png";
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "image/jpeg";
  if (buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP") return "image/webp";
  return null;
}

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}
async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

function publicId(userRow) {
  return userRow.public_user_id || userRow.user_id;
}
// Public shape of one group member, including their RSA public key so the sender
// can wrap the per-message AES key to everyone.
function publicMember(internalId, ownerInternalId) {
  const u = userRepository.findById(internalId);
  if (!u) return { id: internalId, username: null, exists: false };
  const pid = publicId(u);
  const ad = userRepository.getAutoDeleteSettings(internalId);
  return {
    id: pid,
    username: u.username,
    alias: u.profile_alias || "",
    // bio / banner / badges so a co-member's click opens a full profile popout
    // without a separate (friend-gated) fetch. All three are already profile-public.
    bio: u.bio || "",
    avatarUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(pid)}&v=${encodeURIComponent(u.updated_at || u.created_at || "")}`,
    bannerUrl: u.profile_banner_mime
      ? `/api/auth/profile-banner?uid=${encodeURIComponent(pid)}&v=${encodeURIComponent(u.updated_at || Date.now())}`
      : "",
    badges: getUserBadges(u),
    // DM auto-delete state, so the member popout can show "has auto-delete enabled"
    // (their DM auto-delete now also vanishes their group messages).
    dmAutodelete: ad.dms,
    autodeleteSeconds: ad.seconds,
    publicKey: u.public_key || null,
    isOwner: internalId === ownerInternalId,
    isOnline: isPublicOnline(u),
    presenceStatus: publicPresenceStatus(u),
  };
}

function publicGroup(group, { withMembers = false, viewerInternalId = null } = {}) {
  const memberIds = groupRepository.getMemberIds(group.group_id);
  const owner = userRepository.findById(group.owner_id);
  const out = {
    id: group.group_id,
    name: group.name || "",
    ownerId: owner ? publicId(owner) : null,
    memberCount: memberIds.length,
    hasIcon: Boolean(group.icon_key),
    // Cache-bust on update so a changed icon refreshes. Served by GET /:id/icon.
    iconUrl: group.icon_key
      ? `/api/groups/${encodeURIComponent(group.group_id)}/icon?v=${encodeURIComponent(group.updated_at || "")}`
      : null,
    createdAt: toUtcIso(group.created_at),
    lastMessageAt: group.last_message_at ? toUtcIso(group.last_message_at) : null,
    lastReadAt: group.last_read_at ? toUtcIso(group.last_read_at) : null,
    // Server-computed unread count (messages from OTHERS since your last_read_at).
    // Only present from the group-list query; undefined elsewhere. Lets the client
    // show the real count after a refresh instead of defaulting to 1.
    unreadCount: typeof group.unread_count === "number" ? group.unread_count : undefined,
  };
  if (withMembers) {
    out.members = memberIds.map((id) => publicMember(id, group.owner_id));
  }
  if (viewerInternalId) {
    const m = groupRepository.getMembership(group.group_id, viewerInternalId);
    out.lastReadAt = m && m.last_read_at ? toUtcIso(m.last_read_at) : null;
  }
  return out;
}

// Safely parse a message row's suppressed_embeds JSON into an array of indices.
function parseSuppressedEmbeds(raw) {
  if (!raw) return [];
  try { const arr = JSON.parse(raw); return Array.isArray(arr) ? arr : []; } catch { return []; }
}

function publicMessage(row) {
  const sender = userRepository.findById(row.sender_id);
  const pinnedByUser = row.pinned_by ? userRepository.findById(row.pinned_by) : null;
  return {
    messageId: row.message_id,
    groupId: row.group_id,
    senderId: sender ? publicId(sender) : row.sender_id,
    content: row.content,
    replyToMessageId: row.reply_to_message_id || null,
    editedAt: row.edited_at ? toUtcIso(row.edited_at) : null,
    createdAt: toUtcIso(row.created_at),
    expiresAt: row.expires_at ? toUtcIso(row.expires_at) : null,
    pinnedAt: row.pinned_at ? toUtcIso(row.pinned_at) : null,
    pinnedBy: pinnedByUser ? publicId(pinnedByUser) : (row.pinned_by || null),
    suppressedEmbeds: parseSuppressedEmbeds(row.suppressed_embeds),
  };
}

// Load a group and confirm the caller is in it. Returns { group } or sends the
// response and returns null.
async function requireGroupMember(req, res) {
  const user = await requireAuth(req);
  if (!user) { res.status(401).json({ message: "Not signed in." }); return null; }
  const group = groupRepository.getGroup(req.params.id);
  if (!group) { res.status(404).json({ message: "Group not found." }); return null; }
  if (!groupRepository.isMember(group.group_id, user.user_id)) {
    res.status(403).json({ message: "You're not in this group chat." });
    return null;
  }
  return { user, group };
}

// POST /api/groups - create a group with at least one friend.
// Group-creation caps (in-memory rolling 1-hour window), counting only successful
// creates: 2 per hour per account, 4 per hour per IP. trust proxy is set, so
// req.ip is the real client address.
const GROUP_CREATE_WINDOW_MS = 60 * 60 * 1000;
const GROUP_CREATE_LIMITS = { account: 2, ip: 4 };
const groupCreateBuckets = { account: new Map(), ip: new Map() };

function groupCreateHits(kind, key) {
  const now = Date.now();
  const map = groupCreateBuckets[kind];
  const live = (map.get(key) || []).filter((t) => now - t < GROUP_CREATE_WINDOW_MS);
  map.set(key, live);
  return live;
}
function groupCreateLimitHit(userId, ip) {
  if (groupCreateHits("account", userId).length >= GROUP_CREATE_LIMITS.account) return "account";
  if (groupCreateHits("ip", ip).length >= GROUP_CREATE_LIMITS.ip) return "ip";
  return null;
}
function recordGroupCreate(userId, ip) {
  const now = Date.now();
  groupCreateHits("account", userId).push(now);
  groupCreateHits("ip", ip).push(now);
}

async function createGroup(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const ip = req.ip || "unknown";
    const limited = groupCreateLimitHit(user.user_id, ip);
    if (limited === "account") {
      return res.status(429).json({ message: "You can only create 2 group chats per hour. Try again later." });
    }
    if (limited === "ip") {
      return res.status(429).json({ message: "Too many group chats created from your network. Try again later." });
    }

    const { memberIds, name } = req.body || {};
    const result = groupService.createGroup({ owner: user, memberPublicIds: memberIds, name });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });

    const group = groupRepository.getGroup(result.groupId);
    const enriched = publicGroup(group, { withMembers: true });
    // Tell every member (including the people just added) to show the new group.
    broadcastToGroupMembers(group.group_id, { type: "group_created", group: enriched });
    recordGroupCreate(user.user_id, ip); // only successful creates count toward the caps
    return res.status(201).json({ group: enriched });
  } catch (err) {
    return next(err);
  }
}

// GET /api/groups - list my groups (sidebar).
async function listGroups(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const groups = groupRepository.listGroupsForUser(user.user_id).map((g) => publicGroup(g));
    return res.json({ groups });
  } catch (err) {
    return next(err);
  }
}

// GET /api/groups/:id - full detail incl. members + their public keys (for E2E).
async function getGroup(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    return res.json({ group: publicGroup(access.group, { withMembers: true, viewerInternalId: access.user.user_id }) });
  } catch (err) {
    return next(err);
  }
}

// GET /api/groups/:id/messages - post-join history, newest page (paginates up).
async function getMessages(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const before = typeof req.query.before === "string" ? req.query.before : null;
    // Members see the FULL history, including messages sent before they joined
    // (Discord-style). Plaintext messages render directly; any that were E2E-
    // encrypted to an older member set simply can't be decrypted on their device.
    const rows = groupRepository.getMessages(access.group.group_id, null, 50, before);
    // The caller's join time lets the client show a "you can't see pre-join
    // messages" disclaimer (and hide the undecryptable wall) only to people who
    // joined after some history already existed.
    const membership = groupRepository.getMembership(access.group.group_id, access.user.user_id);
    return res.json({
      messages: rows.map(publicMessage),
      hasMore: rows.length === 50,
      joinedAt: membership?.joined_at ? toUtcIso(membership.joined_at) : null,
    });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/messages - store an E2E ciphertext blob, broadcast it.
async function sendMessage(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const { content, replyToMessageId } = req.body || {};
    if (typeof content !== "string" || !content.trim()) {
      return res.status(400).json({ message: "Message can't be empty." });
    }
    if (content.length > MAX_GROUP_CONTENT) {
      return res.status(413).json({ message: "Message too large." });
    }
    // Auto-delete: the sender's DM auto-delete setting also vanishes their group
    // messages after the same interval (parity with how it works in DMs/servers).
    const senderAd = userRepository.getAutoDeleteSettings(access.user.user_id);
    const ttlSeconds = senderAd.dms ? senderAd.seconds : 0;
    const row = groupService.sendMessage({
      groupId: access.group.group_id,
      senderInternalId: access.user.user_id,
      content,
      replyToMessageId,
      ttlSeconds,
    });
    // Sending implies you've read up to your own message, so advance YOUR last_read_at.
    // Without this, a refetch would see your own latest message as "unread" and ping
    // you for a message you sent (lastMessageAt > your stale lastReadAt).
    groupRepository.updateLastRead(access.group.group_id, access.user.user_id);
    const message = publicMessage(row);
    broadcastToGroupMembers(access.group.group_id, { type: "group_message", groupId: access.group.group_id, message });
    return res.status(201).json({ message });
  } catch (err) {
    return next(err);
  }
}

// PATCH /api/groups/:id/messages/:messageId - author edits their own message.
// Group messages are E2E ciphertext, so the client re-encrypts the new text to all
// members and sends the fresh blob; we swap content + stamp edited_at, then broadcast.
async function editMessage(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const { content } = req.body || {};
    if (typeof content !== "string" || !content.trim()) {
      return res.status(400).json({ message: "Message can't be empty." });
    }
    if (content.length > MAX_GROUP_CONTENT) {
      return res.status(413).json({ message: "Message too large." });
    }
    const row = groupRepository.getMessageById(req.params.messageId);
    if (!row || row.group_id !== access.group.group_id) {
      return res.status(404).json({ message: "Message not found." });
    }
    if (row.sender_id !== access.user.user_id) {
      return res.status(403).json({ message: "You can only edit your own messages." });
    }
    const updated = groupRepository.editMessage(row.message_id, content);
    const message = publicMessage(updated);
    broadcastToGroupMembers(access.group.group_id, {
      type: "group_message_update",
      groupId: access.group.group_id,
      message,
    });
    return res.json({ message });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/groups/:id/messages/:messageId - author deletes their own message.
async function deleteMessage(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const row = groupRepository.getMessageById(req.params.messageId);
    if (!row || row.group_id !== access.group.group_id) {
      return res.status(404).json({ message: "Message not found." });
    }
    if (row.sender_id !== access.user.user_id) {
      return res.status(403).json({ message: "You can only delete your own messages." });
    }
    groupRepository.deleteMessage(row.message_id);
    broadcastToGroupMembers(access.group.group_id, {
      type: "group_message_delete",
      groupId: access.group.group_id,
      messageId: row.message_id,
    });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/messages/:messageId/suppress-embed - author hides one embed
// (by index) on their own message. Persisted + broadcast so it hides for everyone.
async function suppressEmbed(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const row = groupRepository.getMessageById(req.params.messageId);
    if (!row || row.group_id !== access.group.group_id) {
      return res.status(404).json({ message: "Message not found." });
    }
    if (row.sender_id !== access.user.user_id) {
      return res.status(403).json({ message: "You can only hide embeds on your own messages." });
    }
    const index = Number(req.body?.index);
    if (!Number.isInteger(index) || index < 0 || index > 1) {
      return res.status(400).json({ message: "Invalid embed index." });
    }
    const suppressedEmbeds = groupRepository.addSuppressedEmbed(row.message_id, index);
    if (!suppressedEmbeds) return res.status(404).json({ message: "Message not found." });
    broadcastToGroupMembers(access.group.group_id, {
      type: "group_message_embed_suppressed",
      groupId: access.group.group_id,
      messageId: row.message_id,
      suppressedEmbeds,
    });
    return res.json({ suppressedEmbeds });
  } catch (err) {
    return next(err);
  }
}

// GET /api/groups/:id/pins - pinned messages (newest pin first). Filtered to the
// caller's post-join window, same as the message list, so they never get a pin
// they have no key for.
async function getGroupPins(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    // Full history is visible to all members now, so pins aren't filtered by join date.
    const rows = groupRepository.getPinnedMessages(access.group.group_id);
    return res.json({ messages: rows.map(publicMessage) });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/messages/:messageId/pin - any member can pin. Posts a
// one-time "X pinned a message" notice and broadcasts the pin live.
async function pinGroupMessage(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const row = groupRepository.getMessageById(req.params.messageId);
    if (!row || row.group_id !== access.group.group_id) {
      return res.status(404).json({ message: "Message not found." });
    }
    const wasPinned = Boolean(row.pinned_at);
    const ok = groupRepository.pinMessage(row.message_id, access.user.user_id);
    if (!ok) return res.status(409).json({ message: "This group has reached the pin limit (50)." });
    broadcastToGroupMembers(access.group.group_id, { type: "group_pin", groupId: access.group.group_id, messageId: row.message_id, pinned: true });
    if (!wasPinned) {
      const notice = groupRepository.saveMessage({
        groupId: access.group.group_id,
        senderId: access.user.user_id,
        content: JSON.stringify({
          _gsys: 1, kind: "pin",
          by: publicId(access.user),
          byName: access.user.profile_alias || access.user.username || "Someone",
          target: row.message_id,
        }),
      });
      broadcastToGroupMembers(access.group.group_id, { type: "group_message", groupId: access.group.group_id, message: publicMessage(notice) });
    }
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/groups/:id/messages/:messageId/pin - unpin (any member).
async function unpinGroupMessage(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const row = groupRepository.getMessageById(req.params.messageId);
    if (!row || row.group_id !== access.group.group_id) {
      return res.status(404).json({ message: "Message not found." });
    }
    groupRepository.unpinMessage(row.message_id);
    broadcastToGroupMembers(access.group.group_id, { type: "group_pin", groupId: access.group.group_id, messageId: row.message_id, pinned: false });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/members - add more friends.
async function addMembers(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const result = groupService.addMembers({ group: access.group, actor: access.user, memberPublicIds: req.body?.memberIds });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });

    const group = groupRepository.getGroup(access.group.group_id);
    const enriched = publicGroup(group, { withMembers: true });
    // Existing members get a refresh; new members get the whole group to render.
    broadcastToGroupMembers(group.group_id, { type: "group_update", group: enriched });
    // The "<actor> added <names>" notice shows in the chat live for everyone.
    if (result.systemMessage) {
      broadcastToGroupMembers(group.group_id, {
        type: "group_message",
        groupId: group.group_id,
        message: publicMessage(result.systemMessage),
      });
    }
    result.addedInternalIds.forEach((id) => {
      const u = userRepository.findById(id);
      if (u) broadcastToUser(id, { type: "group_created", group: enriched });
    });
    return res.json({ group: enriched });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/groups/:id/members/me - leave the group.
async function leaveGroup(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const result = groupService.removeMember({ group: access.group, actor: access.user, targetInternalId: access.user.user_id });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });
    // The leaver drops the group; everyone left sees an updated roster.
    broadcastToUser(access.user.user_id, { type: "group_removed", groupId: access.group.group_id });
    if (!result.deleted) {
      const group = groupRepository.getGroup(access.group.group_id);
      if (result.systemMessage) {
        broadcastToGroupMembers(group.group_id, { type: "group_message", groupId: group.group_id, message: publicMessage(result.systemMessage) });
      }
      broadcastToGroupMembers(group.group_id, { type: "group_update", group: publicGroup(group, { withMembers: true }) });
    }
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/groups/:id/members/:userId - owner removes someone.
async function removeMember(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const target = userRepository.findByAnyId(req.params.userId);
    if (!target) return res.status(404).json({ message: "User not found." });
    const result = groupService.removeMember({ group: access.group, actor: access.user, targetInternalId: target.user_id });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });
    broadcastToUser(target.user_id, { type: "group_removed", groupId: access.group.group_id });
    if (!result.deleted) {
      const group = groupRepository.getGroup(access.group.group_id);
      if (result.systemMessage) {
        broadcastToGroupMembers(group.group_id, { type: "group_message", groupId: group.group_id, message: publicMessage(result.systemMessage) });
      }
      broadcastToGroupMembers(group.group_id, { type: "group_update", group: publicGroup(group, { withMembers: true }) });
    }
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/purge - owner wipes all messages (keeps the group + members).
async function purgeGroupMessages(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const result = await groupService.purgeGroupMessages({ group: access.group, actor: access.user });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });
    // Every member clears their open message list (and pins) for this group.
    result.memberIds.forEach((id) => broadcastToUser(id, { type: "group_purged", groupId: access.group.group_id }));
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/owner/:userId - owner hands ownership to another member.
async function transferOwnership(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const target = userRepository.findByAnyId(req.params.userId);
    if (!target) return res.status(404).json({ message: "User not found." });
    const result = groupService.transferOwnership({ group: access.group, actor: access.user, targetInternalId: target.user_id });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });
    const group = groupRepository.getGroup(access.group.group_id);
    const enriched = publicGroup(group, { withMembers: true });
    broadcastToGroupMembers(group.group_id, { type: "group_update", group: enriched });
    return res.json({ group: enriched });
  } catch (err) {
    return next(err);
  }
}

// PATCH /api/groups/:id - rename.
async function renameGroup(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const result = groupService.rename({ group: access.group, actor: access.user, name: req.body?.name });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });
    const group = groupRepository.getGroup(access.group.group_id);
    const enriched = publicGroup(group, { withMembers: true });
    broadcastToGroupMembers(group.group_id, { type: "group_update", group: enriched });
    return res.json({ group: enriched });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/groups/:id - owner deletes the whole group for everyone.
async function deleteGroup(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const result = groupService.deleteGroup({ group: access.group, actor: access.user });
    if (!result.ok) return res.status(result.status || 400).json({ message: result.error });
    // Tell every member (including the owner) to drop the group from their UI.
    result.memberIds.forEach((id) => broadcastToUser(id, { type: "group_removed", groupId: access.group.group_id }));
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/read - mark the group read on this account.
async function markRead(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    groupRepository.updateLastRead(access.group.group_id, access.user.user_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// POST /api/groups/:id/icon - set the group's picture (raw image body, ≤3 MB).
// Any member can change it (group DMs have no roles), matching Discord.
async function uploadGroupIcon(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ message: "Choose a group picture to upload." });
    }
    if (req.body.length > MAX_GROUP_ICON_BYTES) {
      return res.status(413).json({ message: "Group picture cannot be over 3 MB." });
    }
    const mime = detectImageMime(req.body);
    if (!mime) return res.status(400).json({ message: "Picture must be a PNG, JPEG, or WEBP image." });

    const previousKey = access.group.icon_key || null;
    const iconKey = await b2Storage.uploadMedia({
      ownerId: access.user.public_user_id || access.user.user_id,
      buffer: req.body,
      contentType: mime,
      metadata: { "group-id": access.group.group_id },
    });
    groupRepository.updateIcon(access.group.group_id, iconKey, mime);
    if (previousKey && previousKey !== iconKey) b2Storage.deleteMedia(previousKey).catch(() => {});

    const group = groupRepository.getGroup(access.group.group_id);
    const enriched = publicGroup(group, { withMembers: true });
    broadcastToGroupMembers(group.group_id, { type: "group_update", group: enriched });
    return res.json({ group: enriched });
  } catch (err) {
    return next(err);
  }
}

// DELETE /api/groups/:id/icon - clear the custom group picture (back to the
// generated/stacked-avatar default). Any member can do it, like upload.
async function removeGroupIcon(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const previousKey = access.group.icon_key || null;
    groupRepository.updateIcon(access.group.group_id, null, null);
    if (previousKey) b2Storage.deleteMedia(previousKey).catch(() => {});

    const group = groupRepository.getGroup(access.group.group_id);
    const enriched = publicGroup(group, { withMembers: true });
    broadcastToGroupMembers(group.group_id, { type: "group_update", group: enriched });
    return res.json({ group: enriched });
  } catch (err) {
    return next(err);
  }
}

// GET /api/groups/:id/icon - serve the group picture (or a generated fallback).
async function getGroupIcon(req, res, next) {
  try {
    const access = await requireGroupMember(req, res);
    if (!access) return undefined;
    const icon = groupRepository.getIcon(access.group.group_id);
    if (icon && icon.icon_key) {
      try {
        const media = await b2Storage.getMedia(icon.icon_key);
        res.setHeader("Content-Type", media.contentType || icon.icon_mime || "application/octet-stream");
        res.setHeader("Cache-Control", "private, max-age=60");
        return res.send(media.body);
      } catch {
        // Object missing - fall through to the generated default.
      }
    }
    const fallback = generateInitialProfilePicture(icon?.name || "Group");
    res.setHeader("Content-Type", fallback.mimeType);
    res.setHeader("Cache-Control", "private, max-age=60");
    return res.send(fallback.data);
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  createGroup,
  listGroups,
  getGroup,
  getMessages,
  sendMessage,
  editMessage,
  deleteMessage,
  suppressEmbed,
  getGroupPins,
  pinGroupMessage,
  unpinGroupMessage,
  addMembers,
  leaveGroup,
  removeMember,
  deleteGroup,
  purgeGroupMessages,
  transferOwnership,
  renameGroup,
  markRead,
  uploadGroupIcon,
  removeGroupIcon,
  getGroupIcon,
  publicGroup,
};
