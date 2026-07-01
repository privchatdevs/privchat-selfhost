const ws = require("ws");
const { config } = require("../config/env");
const cookieParser = require("cookie-parser");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const userRepository = require("../repositories/userRepository");
const friendRepository = require("../repositories/friendRepository");
const messageService = require("./messageService");
const messageRepository = require("../repositories/messageRepository");
const wsCipher = require("../security/wsCipher");
const bandwidthTracker = require("./bandwidthTracker");
const { toUtcIso } = require("../utils/time");
const { normalizeOwnStatus, isPublicOnline, publicPresenceStatus } = require("./presence");

// Track active WebSocket connections: userId -> Set of WS client instances
const clients = new Map();
// 128 KB: must exceed the largest single signal - a voice_screen_offer whose SDP
// can be ~64 KB (audio + screen + camera on one peer) plus its JSON wrapper.
// Kept in step with validateSessionDescription's 64 KB SDP cap, with headroom.
const MAX_WS_PAYLOAD_BYTES = 128 * 1024;
// Voice call setup trickles a burst of ICE candidates (one message each), so
// this must comfortably exceed a WebRTC negotiation's worth of signals.
const MAX_WS_MESSAGES_PER_WINDOW = 150;
const MAX_WS_SOCKETS_PER_USER = 5;
const WS_RATE_WINDOW_MS = 10000;
const ALLOWED_CLIENT_MESSAGE_TYPES = new Set([
  "get_conversations",
  "voice_call",
  "voice_answer",
  "voice_reject",
  "voice_hangup",
  "voice_ice_candidate",
  "voice_state",
  "voice_screen_offer",
  "voice_screen_answer",
  "voice_screen_state",
  "voice_camera_state",
  "vc_join",
  "vc_leave",
  "vc_media_state",
  "vc_signal",
  "vc_move",
  "vc_disconnect",
  "vc_voice_moderate",
  "gvc_join",
  "gvc_leave",
  "gvc_media_state",
  "gvc_signal",
  "status_update",
  "typing",
  "server_channel_read",
]);
const VOICE_SIGNAL_TYPES = new Set([
  "voice_call",
  "voice_answer",
  "voice_reject",
  "voice_hangup",
  "voice_ice_candidate",
  "voice_state",
  "voice_screen_offer",
  "voice_screen_answer",
  "voice_screen_state",
  "voice_camera_state",
]);
// Server voice-channel (group) messages, handled separately from 1:1 DM calls.
const VC_MESSAGE_TYPES = new Set(["vc_join", "vc_leave", "vc_media_state", "vc_signal", "vc_move", "vc_disconnect", "vc_voice_moderate"]);
// Group-chat voice-call (group DM) messages - a full-mesh call scoped to a group.
const GVC_MESSAGE_TYPES = new Set(["gvc_join", "gvc_leave", "gvc_media_state", "gvc_signal"]);
const UNANSWERED_CALL_TIMEOUT_MS = 3 * 60 * 1000;
const activeVoiceCalls = new Map();

// Server voice-channel presence (separate from the 1:1 activeVoiceCalls above).
// userId -> { serverId, channelId } - a user is connected to at most one VC.
const voiceMembership = new Map();
// channelId -> Map<userId, { muted, deafened, sharing }>
const voiceRooms = new Map();

// Group-chat voice-call presence (a group DM call). Same full-mesh model as
// server voice channels, but keyed by groupId and authorized by group membership.
// userId -> { groupId } - a user is connected to at most one group call.
const groupVoiceMembership = new Map();
// groupId -> Map<userId, { muted, deafened, sharing }>
const groupVoiceRooms = new Map();

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(";").forEach((cookie) => {
    const parts = cookie.split("=");
    list[parts.shift().trim()] = decodeURIComponent(parts.join("="));
  });
  return list;
}

function getSessionTokenFromCookie(cookieHeader) {
  const cookies = parseCookies(cookieHeader);
  const token = cookies[config.cookieNames.session];
  if (!token) return null;
  return cookieParser.signedCookie(token, config.cookieSecret);
}

async function authenticateSocket(req) {
  const token = getSessionTokenFromCookie(req.headers.cookie);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

function isAllowedOrigin(req) {
  const origin = req.headers.origin;
  // Reject a missing Origin too. Real browsers always send it on a WS handshake, so
  // an absent header means a non-browser client; combined with the session-cookie
  // auth below, this is just defense-in-depth on top of the SameSite=Strict cookie
  // (which already stops cross-site WS hijacking).
  if (!origin) return false;

  try {
    return config.appOrigins.includes(new URL(origin).origin);
  } catch {
    return false;
  }
}

function getPayloadByteLength(message) {
  if (Buffer.isBuffer(message)) return message.length;
  if (Array.isArray(message)) return message.reduce((total, part) => total + getPayloadByteLength(part), 0);
  if (message instanceof ArrayBuffer) return message.byteLength;
  return Buffer.byteLength(String(message));
}

function createSocketRateLimiter() {
  let windowStart = Date.now();
  let count = 0;

  return function isRateLimited() {
    const now = Date.now();
    if (now - windowStart > WS_RATE_WINDOW_MS) {
      windowStart = now;
      count = 0;
    }

    count += 1;
    return count > MAX_WS_MESSAGES_PER_WINDOW;
  };
}

function parseClientMessage(message) {
  if (getPayloadByteLength(message) > MAX_WS_PAYLOAD_BYTES) {
    return { error: "Payload too large.", closeCode: 1009 };
  }

  let payload;
  try {
    payload = JSON.parse(String(message));
  } catch {
    return { error: "Invalid websocket message.", closeCode: 1007 };
  }

  if (!payload || typeof payload !== "object" || typeof payload.type !== "string") {
    return { error: "Invalid websocket message.", closeCode: 1007 };
  }

  if (!ALLOWED_CLIENT_MESSAGE_TYPES.has(payload.type)) {
    return { error: "Unsupported websocket message.", closeCode: 1008 };
  }

  return { payload };
}

function canDirectMessageForProfile(userId, targetUserId) {
  if (friendRepository.getBlockBetween(userId, targetUserId)) return false;
  const friendship = friendRepository.getFriendship(userId, targetUserId);
  if (friendship && friendship.status === "accepted") return true;
  const serverRepository = require("../repositories/serverRepository");
  return serverRepository.shareServer(userId, targetUserId);
}

async function getEnrichedConversations(userId) {
  const conversations = await messageService.getActiveConversations(userId);
  const enriched = conversations.map(({ userId: partnerId, lastMessageAt, lastMessageId, lastReadAt, pinnedAt }) => {
    const partner = userRepository.findByAnyId(partnerId);
    if (!partner) return null;

    const publicId = partner.public_user_id || partner.user_id;
    const canExposePresence = canDirectMessageForProfile(userId, partner.user_id);

    return {
      userId: publicId,
      username: partner.username,
      alias: partner.profile_alias || "",
      bio: partner.bio || "",
      profilePictureUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(partner.updated_at || partner.created_at || "")}`,
      profileBannerUrl: partner.profile_banner_mime
        ? `/api/auth/profile-banner?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(partner.updated_at || Date.now())}`
        : "",
      lastMessageAt: toUtcIso(lastMessageAt),
      lastMessageId,
      lastReadAt: lastReadAt ? toUtcIso(lastReadAt) : null,
      pinned: Boolean(pinnedAt),
      pinnedAt: pinnedAt ? toUtcIso(pinnedAt) : null,
      isOnline: canExposePresence ? isPublicOnline(partner) : null,
      presenceStatus: canExposePresence ? publicPresenceStatus(partner) : null,
      publicKey: partner.public_key || null,
    };
  });
  return enriched.filter(Boolean);
}

function broadcastToUser(userId, payload) {
  const userSockets = clients.get(userId);
  if (userSockets) {
    const messageStr = JSON.stringify(payload);
    userSockets.forEach((socket) => {
      if (socket.readyState === ws.OPEN) {
        socket.send(messageStr);
      }
    });
  }
}

// A user's online dot lives in each conversation partner's sidebar (the
// "conversations" payload carries it). When this user connects or fully
// disconnects, re-push that payload to every ONLINE partner so their dot flips
// live - instead of waiting out the 10-minute heartbeat window or a manual
// refresh. Bounded to online partners, so it's cheap.
function broadcastPresenceToPartners(userId) {
  let partnerIds = [];
  try { partnerIds = messageRepository.getConversationPartnerIds(userId) || []; } catch { partnerIds = []; }
  partnerIds.forEach((partnerId) => {
    if (!clients.has(partnerId)) return; // only an online partner can receive the update
    getEnrichedConversations(partnerId)
      .then((conversations) => broadcastToUser(partnerId, { type: "conversations", conversations }))
      .catch((err) => console.error("WS presence push error:", err));
  });
}

function broadcastPresenceUpdate(userId) {
  const user = userRepository.findById(userId);
  if (!user) return;
  const payload = {
    type: "presence_update",
    userId: getPublicUserId(user),
    isOnline: isPublicOnline(user),
    presenceStatus: publicPresenceStatus(user),
  };
  const recipients = new Set([userId]);
  try { friendRepository.getFriends(userId).forEach((friend) => recipients.add(friend.user_id)); } catch { /* best effort */ }
  try {
    messageRepository.getConversationPartnerIds(userId).forEach((partnerId) => {
      if (canDirectMessageForProfile(userId, partnerId)) recipients.add(partnerId);
    });
  } catch { /* best effort */ }
  try {
    const serverRepository = require("../repositories/serverRepository");
    serverRepository.getSharedMemberIdsForUser(userId).forEach((memberId) => recipients.add(memberId));
  } catch { /* best effort */ }
  try {
    const groupRepository = require("../repositories/groupRepository");
    groupRepository.getGroupIdsForUser(userId).forEach((groupId) => {
      groupRepository.getMemberIds(groupId).forEach((memberId) => recipients.add(memberId));
    });
  } catch { /* best effort */ }
  recipients.forEach((recipientId) => {
    if (clients.has(recipientId)) broadcastToUser(recipientId, payload);
  });
}

function broadcastToServerMembers(serverId, payload) {
  // Required lazily to avoid loading the repository before the DB is ready.
  const serverRepository = require("../repositories/serverRepository");
  const messageStr = JSON.stringify(payload);
  serverRepository.getMemberIds(serverId).forEach((memberId) => {
    const userSockets = clients.get(memberId);
    if (userSockets) {
      userSockets.forEach((socket) => {
        if (socket.readyState === ws.OPEN) {
          socket.send(messageStr);
        }
      });
    }
  });
}

// Push a payload to everyone currently in a group chat. Optionally include extra
// recipient ids (e.g. someone just removed, so their client can drop the group).
function broadcastToGroupMembers(groupId, payload, extraUserIds = []) {
  const groupRepository = require("../repositories/groupRepository");
  const messageStr = JSON.stringify(payload);
  const recipients = new Set([...groupRepository.getMemberIds(groupId), ...extraUserIds]);
  recipients.forEach((memberId) => {
    const userSockets = clients.get(memberId);
    if (userSockets) {
      userSockets.forEach((socket) => {
        if (socket.readyState === ws.OPEN) {
          socket.send(messageStr);
        }
      });
    }
  });
}

// ── Typing indicators ────────────────────────────────────────────────────────
// Ephemeral, fire-and-forget. The client emits a "typing" ping at most every few
// seconds while composing; recipients show "X is typing…" and auto-expire it.
// There's no explicit "stopped" signal - the indicator times out on the client
// and is cleared the instant a real message from that sender arrives. We never
// echo to the sender, and we authorize delivery so typing can't be spoofed into
// a chat the sender has no access to. (The "hide typing" privacy setting is
// enforced client-side: a hidden user simply never emits these.)
function handleTypingSignal({ user, payload }) {
  const scope = payload && payload.scope;
  if (scope === "dm") {
    const targetPublicId = payload.targetUserId;
    if (!targetPublicId || typeof targetPublicId !== "string") return;
    const target = userRepository.findByAnyId(targetPublicId);
    if (!target) return;
    // Only deliver to people you're actually allowed to DM (friends / shared server).
    if (!canDirectMessageForProfile(user.user_id, target.user_id)) return;
    // Respect the recipient's per-server "no DMs" block (Manage Privacy): if they
    // blocked DMs from a server you're in, don't leak a typing indicator either.
    // Friends are always allowed (mirrors friendService.canDirectMessage).
    const dmFriendship = friendRepository.getFriendship(user.user_id, target.user_id);
    if (!(dmFriendship && dmFriendship.status === "accepted")) {
      const serverPrivacyRepository = require("../repositories/serverPrivacyRepository");
      if (serverPrivacyRepository.isSenderBlockedByServer(target.user_id, user.user_id, "block_dms")) return;
    }
    broadcastToUser(target.user_id, {
      type: "typing",
      scope: "dm",
      senderId: getPublicUserId(user),
    });
    return;
  }
  if (scope === "server") {
    const { serverId, channelId } = payload;
    if (!serverId || !channelId || typeof serverId !== "string" || typeof channelId !== "string") return;
    const serverRepository = require("../repositories/serverRepository");
    if (!serverRepository.isMember(serverId, user.user_id)) return;
    const channel = serverRepository.getChannel(channelId);
    if (!channel || channel.server_id !== serverId) return;
    broadcastToServerMembers(serverId, {
      type: "typing",
      scope: "server",
      serverId,
      channelId,
      senderId: getPublicUserId(user),
      username: user.username,
    });
  }
}

// A user read a server channel on one device - mirror that to their OTHER devices/
// tabs so the channel's "unread" (white) state clears everywhere live, without a
// refresh. Pure relay between the same user's sockets: no DB, no persistence, and
// it never leaves the user's own session set, so it can't be used to probe others.
function handleChannelRead({ userId, payload, wsConn }) {
  const serverId = typeof payload.serverId === "string" ? payload.serverId.slice(0, 100) : null;
  const channelId = typeof payload.channelId === "string" ? payload.channelId.slice(0, 100) : null;
  if (!serverId || !channelId) return;
  const userSockets = clients.get(userId);
  if (!userSockets) return;
  const out = JSON.stringify({ type: "server_channel_read", serverId, channelId });
  userSockets.forEach((socket) => {
    if (socket !== wsConn && socket.readyState === ws.OPEN) socket.send(out);
  });
}

function getPublicUserId(user) {
  return user.public_user_id || user.user_id;
}

function getVoicePeer(userId, targetUserId) {
  if (!targetUserId || typeof targetUserId !== "string" || targetUserId.length > 80) {
    return { error: "Invalid call target." };
  }

  const target = userRepository.findByAnyId(targetUserId);
  if (!target || target.user_id === userId) {
    return { error: "User not found." };
  }

  const block = friendRepository.getBlockBetween(userId, target.user_id);
  if (block) {
    return { error: "Voice calls are blocked between these users." };
  }

  // Friends can always call; non-friends can call if they share a server.
  const friendship = friendRepository.getFriendship(userId, target.user_id);
  const areFriends = friendship && friendship.status === "accepted";
  if (!areFriends) {
    const serverRepository = require("../repositories/serverRepository");
    if (!serverRepository.shareServer(userId, target.user_id)) {
      return { error: "You can only call friends or people who share a server with you." };
    }
  }

  return { target };
}

function validateCallId(callId) {
  return typeof callId === "string" && callId.length >= 6 && callId.length <= 80;
}

function validateSessionDescription(description) {
  if (!description || typeof description !== "object") return false;
  if (!["offer", "answer"].includes(description.type)) return false;
  // 64 KB cap (was 32 KB): a DM puts voice + screen + camera on ONE peer, so an
  // offer with all three media sections (each listing every codec/rtx/fec) can
  // exceed 32 KB and was being rejected as an "Invalid screen share offer." 64 KB
  // comfortably fits a 3-track SDP while still bounding signaling payload size.
  return typeof description.sdp === "string" && description.sdp.length > 0 && description.sdp.length <= 65536;
}

function validateIceCandidate(candidate) {
  if (!candidate || typeof candidate !== "object") return false;
  if (typeof candidate.candidate !== "string" || candidate.candidate.length > 3000) return false;
  if (candidate.sdpMid != null && typeof candidate.sdpMid !== "string") return false;
  if (candidate.sdpMLineIndex != null && typeof candidate.sdpMLineIndex !== "number") return false;
  return true;
}

function buildVoiceSignal({ payload, sender, target }) {
  const base = {
    type: payload.type,
    callId: payload.callId,
    senderId: getPublicUserId(sender),
    senderName: sender.profile_alias || sender.username || "",
    senderUsername: sender.username || "",
    senderAvatarUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(getPublicUserId(sender))}&v=${encodeURIComponent(sender.updated_at || sender.created_at || "")}`,
    targetUserId: getPublicUserId(target),
  };

  if (payload.description) {
    base.description = {
      type: payload.description.type,
      sdp: payload.description.sdp,
    };
  }
  if (payload.type === "voice_call" && payload.rejoin) {
    base.rejoin = true;
  }

  if (payload.candidate) {
    base.candidate = {
      candidate: payload.candidate.candidate,
      sdpMid: payload.candidate.sdpMid ?? null,
      sdpMLineIndex: payload.candidate.sdpMLineIndex ?? null,
      usernameFragment: typeof payload.candidate.usernameFragment === "string"
        ? payload.candidate.usernameFragment.slice(0, 256)
        : null,
    };
  }

  if (payload.type === "voice_state") {
    base.muted = Boolean(payload.muted);
    base.deafened = Boolean(payload.deafened);
  }

  if (payload.type === "voice_screen_state") {
    base.sharing = Boolean(payload.sharing);
  }

  if (payload.type === "voice_camera_state") {
    base.cameraOn = Boolean(payload.cameraOn);
    // The camera's MediaStream id, so the peer can tell camera video from screen.
    base.camId = typeof payload.camId === "string" ? payload.camId.slice(0, 100) : "";
  }

  if (payload.reason && typeof payload.reason === "string") {
    base.reason = payload.reason.slice(0, 80);
  }

  return base;
}

function buildVoiceCallContent({ callId, status, startedAt, endedAt = null, durationMs = null }) {
  return JSON.stringify({
    system: true,
    kind: "voice_call",
    callId,
    status,
    startedAt,
    endedAt,
    durationMs,
  });
}

function buildMessagePayload({ row, sender, receiver, type = "message" }) {
  return {
    type,
    messageId: row.message_id,
    senderId: getPublicUserId(sender),
    receiverId: getPublicUserId(receiver),
    content: row.content,
    createdAt: toUtcIso(row.created_at),
    editedAt: row.edited_at ? toUtcIso(row.edited_at) : null,
    replyToMessageId: row.reply_to_message_id || null,
    reactions: [],
  };
}

function pushConversationRefresh(userA, userB) {
  getEnrichedConversations(userA)
    .then((conversations) => broadcastToUser(userA, { type: "conversations", conversations }))
    .catch((err) => console.error("WS voice conversation push error:", err));
  getEnrichedConversations(userB)
    .then((conversations) => broadcastToUser(userB, { type: "conversations", conversations }))
    .catch((err) => console.error("WS voice conversation push error:", err));
}

async function createVoiceCallMessage({ call, starter, receiver }) {
  if (!call || call.messageId) return;
  const row = await messageService.saveMessage({
    senderId: call.starterId,
    receiverId: call.targetId,
    content: buildVoiceCallContent({ callId: call.callId, status: "started", startedAt: call.startedAt }),
  });
  call.messageId = row.message_id;
  const payload = buildMessagePayload({ row, sender: starter, receiver });
  broadcastToUser(call.starterId, payload);
  broadcastToUser(call.targetId, payload);
  pushConversationRefresh(call.starterId, call.targetId);
}

async function deleteVoiceCallMessage({ call }) {
  if (!call) return;
  if (call.messagePromise) {
    await call.messagePromise.catch((err) => console.error("Failed to finish voice call message creation:", err));
  }
  if (!call.messageId) return;
  await messageService.deleteMessage({
    messageId: call.messageId,
    senderId: call.starterId,
    receiverId: call.targetId,
  });
  broadcastToUser(call.starterId, { type: "message_delete", messageId: call.messageId });
  broadcastToUser(call.targetId, { type: "message_delete", messageId: call.messageId });
  pushConversationRefresh(call.starterId, call.targetId);
  call.messageId = null;
}

function registerPendingVoiceCall({ sender, target, payload, offerSignal }) {
  const callId = payload.callId;
  const existing = activeVoiceCalls.get(callId);
  if (existing?.timeout) clearTimeout(existing.timeout);

  const startedAt = new Date().toISOString();

  const timeout = setTimeout(() => {
    const call = activeVoiceCalls.get(callId);
    if (!call || call.answeredAt) return;
    const hangup = {
      type: "voice_hangup",
      callId,
      senderId: getPublicUserId(target),
      targetUserId: getPublicUserId(sender),
      reason: "timeout",
    };
    broadcastToUser(sender.user_id, hangup);
    broadcastToUser(target.user_id, { ...hangup, senderId: getPublicUserId(sender), targetUserId: getPublicUserId(target) });
    deleteVoiceCallMessage({ call })
      .catch((err) => console.error("Failed to delete unanswered voice call message:", err))
      .finally(() => activeVoiceCalls.delete(callId));
  }, UNANSWERED_CALL_TIMEOUT_MS);

  const call = {
    callId,
    starterId: sender.user_id,
    targetId: target.user_id,
    messageId: null,
    startedAt,
    answeredAt: null,
    participants: new Set([sender.user_id]),
    timeout,
    aloneTimeout: null,
    messagePromise: null,
    offerSignal,
    lastOffererId: sender.user_id,
    iceCandidates: {
      [sender.user_id]: [],
      [target.user_id]: [],
    },
  };
  activeVoiceCalls.set(callId, call);
  call.messagePromise = createVoiceCallMessage({ call, starter: sender, receiver: target })
    .catch((err) => console.error("Failed to create voice call message:", err));
}

function findActiveVoiceCallForUser(userId) {
  for (const call of activeVoiceCalls.values()) {
    if (call.starterId === userId || call.targetId === userId) return call;
  }
  return null;
}

function buildVoiceResumeSignal({ call, user }) {
  const peerId = call.starterId === user.user_id ? call.targetId : call.starterId;
  const peer = userRepository.findByAnyId(peerId);
  if (!peer) return null;
  const peerPublicId = getPublicUserId(peer);
  return {
    type: "voice_resume",
    callId: call.callId,
    senderId: peerPublicId,
    senderName: peer.profile_alias || peer.username || "",
    senderUsername: peer.username || "",
    senderAvatarUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(peerPublicId)}&v=${encodeURIComponent(peer.updated_at || peer.created_at || "")}`,
    alone: call.participants?.size === 1,
  };
}

function sendActiveVoiceCallsToSocket(user, wsConn) {
  if (!wsConn || wsConn.readyState !== ws.OPEN) return;
  const userId = user.user_id;
  for (const call of activeVoiceCalls.values()) {
    if (call.targetId !== userId || !call.offerSignal || call.answeredAt) continue;
    wsConn.send(JSON.stringify(call.offerSignal));
    (call.iceCandidates?.[call.starterId] || []).forEach((signal) => {
      wsConn.send(JSON.stringify(signal));
    });
  }
  const activeCall = findActiveVoiceCallForUser(userId);
  if (activeCall?.answeredAt) {
    if (activeCall.participants?.has(userId)) {
      const resumeSignal = buildVoiceResumeSignal({ call: activeCall, user });
      if (resumeSignal) wsConn.send(JSON.stringify(resumeSignal));
    } else {
      // The user left this call but the other party is still in it - restore
      // the "in a call alone" chip so they can rejoin after a refresh.
      const occupantId = activeCall.starterId === userId ? activeCall.targetId : activeCall.starterId;
      if (activeCall.participants?.has(occupantId)) {
        const occupant = userRepository.findByAnyId(occupantId);
        if (occupant) {
          wsConn.send(JSON.stringify(buildVoiceAloneSignal({ call: activeCall, occupant })));
        }
      }
    }
  }
}

function isRejoinVoiceCall({ call, sender, target }) {
  if (!call || call.answeredAt == null) return false;
  if (call.participants?.has(sender.user_id)) return false;
  if (!call.participants?.has(target.user_id)) return false;
  return (
    (call.starterId === sender.user_id && call.targetId === target.user_id) ||
    (call.starterId === target.user_id && call.targetId === sender.user_id)
  );
}

function isReconnectVoiceCall({ call, sender, target }) {
  if (!call || call.answeredAt == null) return false;
  if (!call.participants?.has(sender.user_id)) return false;
  if (!call.participants?.has(target.user_id)) return false;
  return (
    (call.starterId === sender.user_id && call.targetId === target.user_id) ||
    (call.starterId === target.user_id && call.targetId === sender.user_id)
  );
}

function buildVoiceAloneSignal({ call, occupant }) {
  return {
    type: "voice_alone",
    callId: call.callId,
    senderId: getPublicUserId(occupant),
    senderName: occupant.profile_alias || occupant.username || "",
    senderUsername: occupant.username || "",
    senderAvatarUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(getPublicUserId(occupant))}&v=${encodeURIComponent(occupant.updated_at || occupant.created_at || "")}`,
  };
}

async function updateVoiceCallMessage({ callId, sender, target, status = "ended" }) {
  const call = activeVoiceCalls.get(callId);
  if (!call) return;
  clearTimeout(call.timeout);

  if (status !== "ended" || !call.answeredAt) {
    deleteVoiceCallMessage({ call })
      .catch((err) => console.error("Failed to delete unanswered voice call message:", err))
      .finally(() => activeVoiceCalls.delete(callId));
    return;
  }

  call.participants?.delete(sender.user_id);
  if (call.participants && call.participants.size > 0) {
    if (call.aloneTimeout) clearTimeout(call.aloneTimeout);
    call.aloneTimeout = setTimeout(() => {
      const latest = activeVoiceCalls.get(callId);
      if (!latest || latest.participants?.size !== 1) return;
      const remainingId = [...latest.participants][0];
      const remaining = userRepository.findByAnyId(remainingId);
      const other = remainingId === latest.starterId
        ? userRepository.findByAnyId(latest.targetId)
        : userRepository.findByAnyId(latest.starterId);
      if (remaining && other) {
        const hangup = {
          type: "voice_hangup",
          callId,
          senderId: getPublicUserId(remaining),
          targetUserId: getPublicUserId(other),
          reason: "alone_timeout",
        };
        broadcastToUser(remaining.user_id, hangup);
        broadcastToUser(other.user_id, { ...hangup, senderId: getPublicUserId(other), targetUserId: getPublicUserId(remaining) });
        updateVoiceCallMessage({ callId, sender: remaining, target: other, status: "ended" })
          .catch((err) => console.error("Failed to auto-end alone voice call:", err));
      }
    }, UNANSWERED_CALL_TIMEOUT_MS);
    broadcastToUser(sender.user_id, buildVoiceAloneSignal({ call, occupant: target }));
    return;
  }

  if (call.aloneTimeout) clearTimeout(call.aloneTimeout);

  // The call must leave the active map even if the DB work below throws,
  // otherwise it blocks both users from ever calling again.
  try {
    if (call.messagePromise) {
      await call.messagePromise.catch((err) => console.error("Failed to finish voice call message creation:", err));
    }

    if (!call.messageId) return;

    const endedAt = new Date().toISOString();
    const durationMs = Math.max(1000, new Date(endedAt).getTime() - new Date(call.answeredAt).getTime());
    const row = await messageService.updateMessageContent({
      messageId: call.messageId,
      senderId: call.starterId,
      receiverId: call.targetId,
      content: buildVoiceCallContent({
        callId: call.callId,
        status: "ended",
        startedAt: call.startedAt,
        endedAt,
        durationMs,
      }),
    });

    if (row) {
      const starter = call.starterId === sender.user_id ? sender : target;
      const receiver = call.targetId === target.user_id ? target : sender;
      const payload = buildMessagePayload({ row, sender: starter, receiver, type: "message_update" });
      broadcastToUser(call.starterId, payload);
      broadcastToUser(call.targetId, payload);
      pushConversationRefresh(call.starterId, call.targetId);
    }
  } finally {
    activeVoiceCalls.delete(call.callId);
    activeVoiceCalls.delete(callId);
  }
}

// A dropped last socket while mid-call would otherwise leave the user in the call's
// participants forever, so the other person keeps seeing a ghost. Treat it like a
// hangup on the dropped user's behalf: this decrements participants and (with one
// person left) starts the alone-timeout, so the call ends and the ghost clears if
// they don't return. The existing voice_alone/voice_resume path on reconnect still
// lets them rejoin within that window after a refresh.
function leaveCurrentDmVoice(userId) {
  const call = findActiveVoiceCallForUser(userId);
  if (!call || !call.answeredAt || !call.participants?.has(userId)) return;
  const otherId = call.starterId === userId ? call.targetId : call.starterId;
  const leaver = userRepository.findByAnyId(userId);
  const other = userRepository.findByAnyId(otherId);
  if (!leaver || !other) return;
  updateVoiceCallMessage({ callId: call.callId, sender: leaver, target: other, status: "ended" })
    .catch((err) => console.error("Failed to clean up DM voice call on disconnect:", err));
}

function validateVoiceSignal(payload) {
  if (!validateCallId(payload.callId)) return "Invalid call id.";
  if (payload.type === "voice_call") {
    if (!validateSessionDescription(payload.description) || payload.description.type !== "offer") {
      return "Invalid call offer.";
    }
  }
  if (payload.type === "voice_answer") {
    if (!validateSessionDescription(payload.description) || payload.description.type !== "answer") {
      return "Invalid call answer.";
    }
  }
  if (payload.type === "voice_screen_offer") {
    if (!validateSessionDescription(payload.description) || payload.description.type !== "offer") {
      return "Invalid screen share offer.";
    }
  }
  if (payload.type === "voice_screen_answer") {
    if (!validateSessionDescription(payload.description) || payload.description.type !== "answer") {
      return "Invalid screen share answer.";
    }
  }
  if (payload.type === "voice_ice_candidate" && !validateIceCandidate(payload.candidate)) {
    return "Invalid call candidate.";
  }
  return null;
}

function relayVoiceSignal({ sender, payload, wsConn }) {
  const validationError = validateVoiceSignal(payload);
  if (validationError) {
    wsConn.send(JSON.stringify({
      type: "error",
      scope: "voice",
      callId: payload.callId,
      message: validationError,
    }));
    return;
  }

  const { target, error } = getVoicePeer(sender.user_id, payload.targetUserId);
  if (error) {
    wsConn.send(JSON.stringify({
      type: "error",
      scope: "voice",
      callId: payload.callId,
      message: error,
    }));
    return;
  }

  if (payload.type.startsWith("voice_screen_")) {
    const call = activeVoiceCalls.get(payload.callId);
    const validActiveCall = call
      && call.participants?.has(sender.user_id)
      && call.participants?.has(target.user_id);
    if (!validActiveCall) {
      wsConn.send(JSON.stringify({
        type: "error",
        scope: "voice",
        callId: payload.callId,
        message: "Invalid screen share call.",
      }));
      return;
    }
  }

  if (payload.type === "voice_call") {
    const senderCall = findActiveVoiceCallForUser(sender.user_id);
    const targetCall = findActiveVoiceCallForUser(target.user_id);
    const rejoinCall = senderCall || targetCall;
    if (
      isRejoinVoiceCall({ call: rejoinCall, sender, target }) ||
      isReconnectVoiceCall({ call: rejoinCall, sender, target })
    ) {
      if (rejoinCall.aloneTimeout) {
        clearTimeout(rejoinCall.aloneTimeout);
        rejoinCall.aloneTimeout = null;
      }
      // A rejoining client may have generated a fresh call id (e.g. after a
      // page refresh) - re-key the call so answers/ICE for the new id match.
      if (rejoinCall.callId !== payload.callId) {
        activeVoiceCalls.delete(rejoinCall.callId);
        rejoinCall.callId = payload.callId;
        activeVoiceCalls.set(payload.callId, rejoinCall);
      }
      rejoinCall.offerSignal = buildVoiceSignal({ payload, sender, target });
      rejoinCall.lastOffererId = sender.user_id;
      rejoinCall.iceCandidates = {
        ...rejoinCall.iceCandidates,
        [sender.user_id]: [],
      };
      broadcastToUser(target.user_id, rejoinCall.offerSignal);
      return;
    }
    if (senderCall) {
      wsConn.send(JSON.stringify({
        type: "error",
        scope: "voice",
        callId: payload.callId,
        message: "You are already in a call.",
      }));
      return;
    }
    if (targetCall) {
      wsConn.send(JSON.stringify({
        type: "error",
        scope: "voice",
        callId: payload.callId,
        message: "This user is already in a call.",
      }));
      return;
    }
    registerPendingVoiceCall({
      sender,
      target,
      payload,
      offerSignal: buildVoiceSignal({ payload, sender, target }),
    });
  } else if (payload.type === "voice_answer") {
    const call = activeVoiceCalls.get(payload.callId);
    const isOriginalAnswer = call && call.starterId === target.user_id && call.targetId === sender.user_id;
    const isRejoinAnswer = call && call.lastOffererId === target.user_id && call.participants?.has(sender.user_id);
    if (!call || (!isOriginalAnswer && !isRejoinAnswer)) {
      wsConn.send(JSON.stringify({
        type: "error",
        scope: "voice",
        callId: payload.callId,
        message: "Invalid call answer.",
      }));
      return;
    }
    call.answeredAt = new Date().toISOString();
    call.participants = new Set([call.starterId, call.targetId]);
    clearTimeout(call.timeout);
    if (call.aloneTimeout) {
      clearTimeout(call.aloneTimeout);
      call.aloneTimeout = null;
    }
    const starter = call.starterId === sender.user_id ? sender : target;
    const receiver = call.targetId === sender.user_id ? sender : target;
    call.messagePromise = createVoiceCallMessage({ call, starter, receiver })
      .catch((err) => console.error("Failed to create voice call message:", err));
    (call.iceCandidates?.[call.lastOffererId || call.starterId] || []).forEach((signal) => {
      wsConn.send(JSON.stringify(signal));
    });
  } else if (payload.type === "voice_ice_candidate") {
    const call = activeVoiceCalls.get(payload.callId);
    if (call && (call.starterId === sender.user_id || call.targetId === sender.user_id)) {
      const signal = buildVoiceSignal({ payload, sender, target });
      if (!call.iceCandidates) call.iceCandidates = {};
      if (!call.iceCandidates[sender.user_id]) call.iceCandidates[sender.user_id] = [];
      call.iceCandidates[sender.user_id].push(signal);
      if (call.iceCandidates[sender.user_id].length > 64) {
        call.iceCandidates[sender.user_id] = call.iceCandidates[sender.user_id].slice(-64);
      }
    }
  } else if (payload.type === "voice_hangup") {
    const call = activeVoiceCalls.get(payload.callId);
    if (call && (call.starterId === sender.user_id || call.targetId === sender.user_id)) {
      updateVoiceCallMessage({
        callId: payload.callId,
        sender,
        target,
        status: "ended",
      }).catch((err) => console.error("Failed to update voice call message:", err));
    }
  } else if (payload.type === "voice_reject") {
    // Clean up the pending call so the caller isn't stuck "already in a call"
    // until the unanswered timeout fires.
    const call = activeVoiceCalls.get(payload.callId);
    if (
      call && !call.answeredAt &&
      (call.starterId === sender.user_id || call.targetId === sender.user_id)
    ) {
      updateVoiceCallMessage({
        callId: payload.callId,
        sender,
        target,
        status: "rejected",
      }).catch((err) => console.error("Failed to clean up rejected voice call:", err));
    }
  }

  broadcastToUser(target.user_id, buildVoiceSignal({ payload, sender, target }));
}

// ── Server voice channels (group, full-mesh) ─────────────────────────────────

function buildVoiceRoster(channelId) {
  const room = voiceRooms.get(channelId);
  if (!room) return [];
  const serverRepository = require("../repositories/serverRepository");
  const channel = serverRepository.getChannel(channelId);
  const roster = [];
  for (const [memberId, state] of room) {
    const member = userRepository.findByAnyId(memberId);
    if (!member) continue;
    const publicId = getPublicUserId(member);
    // Voice permissions ride along so each client can self-enforce (mic off when
    // it can't Speak, no screen/camera when it can't share). The full-mesh can't
    // gate media server-side, exactly like moderator server-mute.
    const vperms = channel ? serverRepository.channelPermissionsFor(channel.server_id, channel, memberId) : 0;
    roster.push({
      userId: publicId,
      username: member.username || "",
      name: member.profile_alias || member.username || "",
      avatarUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(member.updated_at || member.created_at || "")}`,
      muted: Boolean(state.muted),
      deafened: Boolean(state.deafened),
      sharing: Boolean(state.sharing),
      cameraOn: Boolean(state.cameraOn),
      // Stream ids so peers can route each incoming video to screen vs camera.
      scrId: state.scrId || "",
      camId: state.camId || "",
      serverMuted: Boolean(state.serverMuted),
      serverDeafened: Boolean(state.serverDeafened),
      canSpeak: serverRepository.hasPermission(vperms, serverRepository.PERMISSIONS.SPEAK),
      canVideo: serverRepository.hasPermission(vperms, serverRepository.PERMISSIONS.VIDEO),
    });
  }
  return roster;
}

// Can this user see (and thus join) a voice channel? Public channels are open to
// all members; private ones are owner/admin-only - mirrors canViewChannel.
function canUserViewVoiceChannel(channel, userId) {
  const serverRepository = require("../repositories/serverRepository");
  // Honours per-channel View Channel overwrites (and legacy is_private).
  return serverRepository.hasPermission(
    serverRepository.channelPermissionsFor(channel.server_id, channel, userId),
    serverRepository.PERMISSIONS.VIEW_CHANNEL
  );
}

function broadcastVoiceRoster(serverId, channelId) {
  const serverRepository = require("../repositories/serverRepository");
  const payload = {
    type: "vc_roster",
    serverId,
    channelId,
    participants: buildVoiceRoster(channelId),
  };
  const channel = serverRepository.getChannel(channelId);
  // For a private voice channel, only people who can see it get the roster -
  // otherwise its occupancy would leak over the wire to everyone.
  if (channel && channel.is_private) {
    serverRepository.getMemberIds(serverId).forEach((memberId) => {
      if (!canUserViewVoiceChannel(channel, memberId)) return;
      const sockets = clients.get(memberId);
      sockets?.forEach((socket) => {
        if (socket.readyState === ws.OPEN) socket.send(JSON.stringify(payload));
      });
    });
    return;
  }
  broadcastToServerMembers(serverId, payload);
}

function leaveCurrentVoice(userId, { broadcast = true } = {}) {
  const membership = voiceMembership.get(userId);
  if (!membership) return;
  voiceMembership.delete(userId);
  const room = voiceRooms.get(membership.channelId);
  if (room) {
    room.delete(userId);
    if (room.size === 0) voiceRooms.delete(membership.channelId);
  }
  if (broadcast) broadcastVoiceRoster(membership.serverId, membership.channelId);
}

// On (re)connect, replay the rosters of every occupied voice channel in the
// servers this user belongs to, so a fresh page load sees who is connected.
function sendVoiceRostersToSocket(user, wsConn) {
  if (!wsConn || wsConn.readyState !== ws.OPEN) return;
  const serverRepository = require("../repositories/serverRepository");
  for (const [channelId, room] of voiceRooms) {
    if (room.size === 0) continue;
    const channel = serverRepository.getChannel(channelId);
    if (!channel || !serverRepository.isMember(channel.server_id, user.user_id)) continue;
    if (!canUserViewVoiceChannel(channel, user.user_id)) continue; // hide private VC presence
    wsConn.send(JSON.stringify({
      type: "vc_roster",
      serverId: channel.server_id,
      channelId,
      participants: buildVoiceRoster(channelId),
    }));
  }
}

function sanitizeVcSignal(signal) {
  if (!signal || typeof signal !== "object") return null;
  if (signal.kind === "offer" || signal.kind === "answer") {
    if (!validateSessionDescription(signal.description) || signal.description.type !== signal.kind) return null;
    return { kind: signal.kind, description: { type: signal.description.type, sdp: signal.description.sdp } };
  }
  if (signal.kind === "ice") {
    if (!validateIceCandidate(signal.candidate)) return null;
    return {
      kind: "ice",
      candidate: {
        candidate: signal.candidate.candidate,
        sdpMid: signal.candidate.sdpMid ?? null,
        sdpMLineIndex: signal.candidate.sdpMLineIndex ?? null,
        usernameFragment: typeof signal.candidate.usernameFragment === "string"
          ? signal.candidate.usernameFragment.slice(0, 256)
          : null,
      },
    };
  }
  return null;
}

function relayVcSignal(sender, payload) {
  const membership = voiceMembership.get(sender.user_id);
  if (!membership || membership.channelId !== payload.channelId) return;
  const target = userRepository.findByAnyId(payload.targetUserId);
  if (!target) return;
  const targetMembership = voiceMembership.get(target.user_id);
  if (!targetMembership || targetMembership.channelId !== payload.channelId) return;
  const signal = sanitizeVcSignal(payload.signal);
  if (!signal) return;
  broadcastToUser(target.user_id, {
    type: "vc_signal",
    channelId: payload.channelId,
    senderId: getPublicUserId(sender),
    signal,
  });
}

function handleVoiceChannelMessage({ user, payload, wsConn }) {
  const serverRepository = require("../repositories/serverRepository");

  if (payload.type === "vc_join") {
    const channel = serverRepository.getChannel(payload.channelId);
    if (!channel || channel.type !== "voice" || !serverRepository.isMember(channel.server_id, user.user_id)) {
      wsConn.send(JSON.stringify({ type: "error", scope: "vc", message: "You cannot join this voice channel." }));
      return;
    }
    // Private voice channels: only the owner or admins may join (so a crafted
    // vc_join can't bypass the hidden-in-the-UI channel).
    if (channel.is_private && !canUserViewVoiceChannel(channel, user.user_id)) {
      wsConn.send(JSON.stringify({ type: "error", scope: "vc", message: "You cannot join this voice channel." }));
      return;
    }
    // Per-channel voice permissions (Join / Speak / Screen Share). Owner + admin
    // bypass via channelPermissionsFor. CONNECT is hard-enforced here; SPEAK is
    // clamped into the roster below (no SPEAK ⇒ forced muted).
    const vperms = serverRepository.channelPermissionsFor(channel.server_id, channel, user.user_id);
    if (!serverRepository.hasPermission(vperms, serverRepository.PERMISSIONS.CONNECT)) {
      wsConn.send(JSON.stringify({ type: "error", scope: "vc", message: "You don't have permission to join this voice channel." }));
      return;
    }
    const canSpeak = serverRepository.hasPermission(vperms, serverRepository.PERMISSIONS.SPEAK);
    // A user occupies one VC at a time - drop any previous membership first.
    leaveCurrentVoice(user.user_id);

    let room = voiceRooms.get(channel.channel_id);
    if (!room) {
      room = new Map();
      voiceRooms.set(channel.channel_id, room);
    }
    // The newcomer initiates mesh offers to everyone already connected.
    const peers = [...room.keys()]
      .map((id) => userRepository.findByAnyId(id))
      .filter(Boolean)
      .map((u) => getPublicUserId(u));
    room.set(user.user_id, { muted: !canSpeak || Boolean(payload.muted), deafened: Boolean(payload.deafened), sharing: false, cameraOn: false, scrId: "", camId: "" });
    voiceMembership.set(user.user_id, { serverId: channel.server_id, channelId: channel.channel_id });

    wsConn.send(JSON.stringify({ type: "vc_joined", serverId: channel.server_id, channelId: channel.channel_id, peers }));
    broadcastVoiceRoster(channel.server_id, channel.channel_id);
    return;
  }

  if (payload.type === "vc_leave") {
    leaveCurrentVoice(user.user_id);
    return;
  }

  if (payload.type === "vc_media_state") {
    const membership = voiceMembership.get(user.user_id);
    if (!membership) return;
    const room = voiceRooms.get(membership.channelId);
    const state = room?.get(user.user_id);
    if (!state) return;
    // Clamp the reported state to this user's voice permissions: no SPEAK ⇒ stays
    // muted, no VIDEO ⇒ can't share screen/camera. (channelPermissionsFor honours
    // owner/admin, so they're never clamped.)
    const channel = serverRepository.getChannel(membership.channelId);
    const vperms = channel ? serverRepository.channelPermissionsFor(membership.serverId, channel, user.user_id) : 0;
    const canSpeak = serverRepository.hasPermission(vperms, serverRepository.PERMISSIONS.SPEAK);
    const canVideo = serverRepository.hasPermission(vperms, serverRepository.PERMISSIONS.VIDEO);
    state.muted = canSpeak ? Boolean(payload.muted) : true;
    state.deafened = Boolean(payload.deafened);
    state.sharing = canVideo ? Boolean(payload.sharing) : false;
    state.cameraOn = canVideo ? Boolean(payload.cameraOn) : false;
    state.scrId = canVideo && typeof payload.scrId === "string" ? payload.scrId.slice(0, 100) : "";
    state.camId = canVideo && typeof payload.camId === "string" ? payload.camId.slice(0, 100) : "";
    broadcastVoiceRoster(membership.serverId, membership.channelId);
    return;
  }

  if (payload.type === "vc_signal") {
    relayVcSignal(user, payload);
    return;
  }

  if (payload.type === "vc_move") {
    const destChannel = serverRepository.getChannel(payload.channelId);
    if (!destChannel || destChannel.type !== "voice") return;
    // The mover needs the DRAG_USERS permission (owner/admin implied) in the
    // destination channel's server.
    const mask = serverRepository.getMemberPermissions(destChannel.server_id, user.user_id);
    if (!serverRepository.hasPermission(mask, serverRepository.PERMISSIONS.DRAG_USERS)) {
      wsConn.send(JSON.stringify({ type: "error", scope: "vc", message: "You don't have permission to manage voice chat." }));
      return;
    }
    const target = userRepository.findByAnyId(payload.userId);
    if (!target) return;
    const targetMembership = voiceMembership.get(target.user_id);
    if (!targetMembership || targetMembership.channelId === destChannel.channel_id) return;
    // The target must currently be in a voice channel of the same server.
    const currentChannel = serverRepository.getChannel(targetMembership.channelId);
    if (!currentChannel || currentChannel.server_id !== destChannel.server_id) return;
    // Tell the target's client to switch - it re-runs the normal join flow.
    broadcastToUser(target.user_id, {
      type: "vc_force_move",
      serverId: destChannel.server_id,
      channelId: destChannel.channel_id,
      channelName: destChannel.name,
    });
  }

  if (payload.type === "vc_disconnect") {
    // Force-disconnect another member from voice. Same DRAG_USERS gate as moving.
    const target = userRepository.findByAnyId(payload.userId);
    if (!target || target.user_id === user.user_id) return;
    const targetMembership = voiceMembership.get(target.user_id);
    if (!targetMembership) return;
    const currentChannel = serverRepository.getChannel(targetMembership.channelId);
    if (!currentChannel) return;
    const mask = serverRepository.getMemberPermissions(currentChannel.server_id, user.user_id);
    if (!serverRepository.hasPermission(mask, serverRepository.PERMISSIONS.DRAG_USERS)) {
      wsConn.send(JSON.stringify({ type: "error", scope: "vc", message: "You don't have permission to disconnect members." }));
      return;
    }
    // Drop them server-side, then tell their client to tear down its local call.
    leaveCurrentVoice(target.user_id);
    broadcastToUser(target.user_id, { type: "vc_force_disconnect", channelId: targetMembership.channelId });
  }

  if (payload.type === "vc_voice_moderate") {
    // Server mute / deafen another member (same DRAG_USERS gate as disconnect).
    // The flags live in the in-memory room state and ride along in the roster;
    // the target's client reads its own entry and force-disables mic/audio.
    const target = userRepository.findByAnyId(payload.userId);
    if (!target || target.user_id === user.user_id) return;
    const targetMembership = voiceMembership.get(target.user_id);
    if (!targetMembership) return;
    const currentChannel = serverRepository.getChannel(targetMembership.channelId);
    if (!currentChannel) return;
    const mask = serverRepository.getMemberPermissions(currentChannel.server_id, user.user_id);
    if (!serverRepository.hasPermission(mask, serverRepository.PERMISSIONS.DRAG_USERS)) {
      wsConn.send(JSON.stringify({ type: "error", scope: "vc", message: "You don't have permission to mute members." }));
      return;
    }
    const room = voiceRooms.get(targetMembership.channelId);
    const state = room?.get(target.user_id);
    if (!state) return;
    if (typeof payload.serverMuted === "boolean") state.serverMuted = payload.serverMuted;
    if (typeof payload.serverDeafened === "boolean") state.serverDeafened = payload.serverDeafened;
    broadcastVoiceRoster(targetMembership.serverId, targetMembership.channelId);
  }
}

// ── Group-chat voice calls (group DM, full-mesh) ─────────────────────────────
// Mirrors the server voice-channel mesh above, but scoped to a group chat and
// authorized purely by group membership. No moderation (no server-mute / drag).

function buildGroupVoiceRoster(groupId) {
  const room = groupVoiceRooms.get(groupId);
  if (!room) return [];
  const roster = [];
  for (const [memberId, state] of room) {
    const member = userRepository.findByAnyId(memberId);
    if (!member) continue;
    const publicId = getPublicUserId(member);
    roster.push({
      userId: publicId,
      username: member.username || "",
      name: member.profile_alias || member.username || "",
      avatarUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(member.updated_at || member.created_at || "")}`,
      muted: Boolean(state.muted),
      deafened: Boolean(state.deafened),
      sharing: Boolean(state.sharing),
      cameraOn: Boolean(state.cameraOn),
      // Stream ids so peers can route each incoming video to screen vs camera.
      scrId: state.scrId || "",
      camId: state.camId || "",
    });
  }
  return roster;
}

// Broadcast the call roster to every member of the group, so even people not in
// the call see that it's active (a "Join" affordance) and who's connected.
function broadcastGroupVoiceRoster(groupId) {
  broadcastToGroupMembers(groupId, {
    type: "gvc_roster",
    groupId,
    participants: buildGroupVoiceRoster(groupId),
  });
}

function leaveCurrentGroupVoice(userId, { broadcast = true } = {}) {
  const membership = groupVoiceMembership.get(userId);
  if (!membership) return;
  groupVoiceMembership.delete(userId);
  const room = groupVoiceRooms.get(membership.groupId);
  if (room) {
    room.delete(userId);
    if (room.size === 0) groupVoiceRooms.delete(membership.groupId);
  }
  if (broadcast) broadcastGroupVoiceRoster(membership.groupId);
}

// On (re)connect, replay the roster of every active group call in the groups
// this user belongs to, so a fresh page load sees who is connected.
function sendGroupVoiceRostersToSocket(user, wsConn) {
  if (!wsConn || wsConn.readyState !== ws.OPEN) return;
  const groupRepository = require("../repositories/groupRepository");
  for (const [groupId, room] of groupVoiceRooms) {
    if (room.size === 0) continue;
    if (!groupRepository.isMember(groupId, user.user_id)) continue;
    wsConn.send(JSON.stringify({
      type: "gvc_roster",
      groupId,
      participants: buildGroupVoiceRoster(groupId),
    }));
  }
}

function relayGroupVcSignal(sender, payload) {
  const membership = groupVoiceMembership.get(sender.user_id);
  if (!membership || membership.groupId !== payload.groupId) return;
  const target = userRepository.findByAnyId(payload.targetUserId);
  if (!target) return;
  const targetMembership = groupVoiceMembership.get(target.user_id);
  if (!targetMembership || targetMembership.groupId !== payload.groupId) return;
  const signal = sanitizeVcSignal(payload.signal);
  if (!signal) return;
  broadcastToUser(target.user_id, {
    type: "gvc_signal",
    groupId: payload.groupId,
    senderId: getPublicUserId(sender),
    signal,
  });
}

function handleGroupVoiceMessage({ user, payload, wsConn }) {
  const groupRepository = require("../repositories/groupRepository");

  if (payload.type === "gvc_join") {
    if (!payload.groupId || !groupRepository.isMember(payload.groupId, user.user_id)) {
      wsConn.send(JSON.stringify({ type: "error", scope: "gvc", message: "You cannot join this call." }));
      return;
    }
    // A user occupies one group call at a time - drop any previous membership.
    leaveCurrentGroupVoice(user.user_id);

    let room = groupVoiceRooms.get(payload.groupId);
    if (!room) {
      room = new Map();
      groupVoiceRooms.set(payload.groupId, room);
    }
    // The newcomer initiates mesh offers to everyone already connected.
    const peers = [...room.keys()]
      .map((id) => userRepository.findByAnyId(id))
      .filter(Boolean)
      .map((u) => getPublicUserId(u));
    room.set(user.user_id, { muted: Boolean(payload.muted), deafened: Boolean(payload.deafened), sharing: false, cameraOn: false, scrId: "", camId: "" });
    groupVoiceMembership.set(user.user_id, { groupId: payload.groupId });

    wsConn.send(JSON.stringify({ type: "gvc_joined", groupId: payload.groupId, peers }));
    broadcastGroupVoiceRoster(payload.groupId);
    return;
  }

  if (payload.type === "gvc_leave") {
    leaveCurrentGroupVoice(user.user_id);
    return;
  }

  if (payload.type === "gvc_media_state") {
    const membership = groupVoiceMembership.get(user.user_id);
    if (!membership) return;
    const room = groupVoiceRooms.get(membership.groupId);
    const state = room?.get(user.user_id);
    if (!state) return;
    state.muted = Boolean(payload.muted);
    state.deafened = Boolean(payload.deafened);
    state.sharing = Boolean(payload.sharing);
    state.cameraOn = Boolean(payload.cameraOn);
    state.scrId = typeof payload.scrId === "string" ? payload.scrId.slice(0, 100) : "";
    state.camId = typeof payload.camId === "string" ? payload.camId.slice(0, 100) : "";
    broadcastGroupVoiceRoster(membership.groupId);
    return;
  }

  if (payload.type === "gvc_signal") {
    relayGroupVcSignal(user, payload);
  }
}

function initWebSocketServer(server) {
  const wss = new ws.Server({ noServer: true });
  const heartbeatInterval = setInterval(() => {
    wss.clients.forEach((client) => {
      if (client.isAlive === false) {
        client.terminate();
        return;
      }

      client.isAlive = false;
      client.ping();
    });
  }, 30000);

  wss.on("close", () => {
    clearInterval(heartbeatInterval);
  });

  server.on("upgrade", async (request, socket, head) => {
    const pathname = new URL(request.url, `http://${request.headers.host}`).pathname;
    if (pathname !== "/api/messages/ws") {
      // Ignore upgrade requests not matching our messages websocket route
      return;
    }

    if (!isAllowedOrigin(request)) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    // Authenticate
    const user = await authenticateSocket(request);
    if (!user) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    wss.handleUpgrade(request, socket, head, (wsConn) => {
      wss.emit("connection", wsConn, request, user);
    });
  });

  wss.on("connection", async (wsConn, request, user) => {
    const userId = user.user_id;
    const existingUserSockets = clients.get(userId);
    if (existingUserSockets && existingUserSockets.size >= MAX_WS_SOCKETS_PER_USER) {
      wsConn.close(1013, "Too many websocket connections.");
      return;
    }

    const isRateLimited = createSocketRateLimiter();
    wsConn.isAlive = true;
    wsConn.on("pong", () => {
      wsConn.isAlive = true;
    });

    // First live socket for this user → they just came online. Stamp last_seen now
    // (so they read online before their first heartbeat) and tell online partners.
    const cameOnline = !existingUserSockets || existingUserSockets.size === 0;
    if (!clients.has(userId)) {
      clients.set(userId, new Set());
    }
    clients.get(userId).add(wsConn);
    if (cameOnline) {
      try { userRepository.updateLastSeen(userId); } catch { /* never block the connection */ }
      broadcastPresenceToPartners(userId);
      broadcastPresenceUpdate(userId);
    }

    // ── Encrypt this connection's frames with a per-connection AES-256-GCM key ──
    // WSS/TLS already protects the transport; this is a second, app-level cipher
    // on top. The key is handed to the client in the first (plaintext) frame over
    // the already-TLS-encrypted socket, then EVERY subsequent frame - both
    // directions - is AES-256-GCM. We wrap wsConn.send so every existing sender
    // (including broadcastToUser / broadcastToServerMembers) encrypts
    // automatically; secure_init must go out raw, before the wrapper is in place.
    // This runs synchronously before the first await, so nothing can send to this
    // socket in plaintext in between.
    wsConn.aesKey = wsCipher.generateKey();
    const rawSend = wsConn.send.bind(wsConn);
    const initFrame = JSON.stringify({ type: "secure_init", key: wsConn.aesKey.toString("base64") });
    rawSend(initFrame);
    bandwidthTracker.record(userId, { egress: Buffer.byteLength(initFrame) });
    wsConn.send = (data, ...args) => {
      try {
        const plaintext = typeof data === "string" ? data : data.toString();
        const frame = JSON.stringify({ enc: wsCipher.encryptFrame(wsConn.aesKey, plaintext) });
        // Count the encrypted wire frame as egress for this connection's user.
        bandwidthTracker.record(userId, { egress: Buffer.byteLength(frame) });
        return rawSend(frame, ...args);
      } catch (err) {
        console.error("WS frame encryption failed:", err);
        return undefined;
      }
    };

    // Immediately push initial conversations list upon connect
    try {
      const conversations = await getEnrichedConversations(userId);
      wsConn.send(JSON.stringify({ type: "conversations", conversations }));
      sendActiveVoiceCallsToSocket(user, wsConn);
      sendVoiceRostersToSocket(user, wsConn);
      sendGroupVoiceRostersToSocket(user, wsConn);
    } catch (err) {
      console.error("Failed to push initial conversations sidebar:", err);
    }

    wsConn.on("message", async (rawFrame) => {
      try {
        // Count the inbound wire frame as ingress for this connection's user.
        bandwidthTracker.record(userId, { ingress: getPayloadByteLength(rawFrame) });
        if (isRateLimited()) {
          wsConn.close(1008, "Websocket rate limit exceeded.");
          return;
        }

        // Every client frame is AES-256-GCM after the secure_init handshake.
        // Bound the encrypted frame first (base64 + envelope inflate ~1.4x), then
        // decrypt and validate the plaintext as before.
        if (getPayloadByteLength(rawFrame) > MAX_WS_PAYLOAD_BYTES * 2) {
          wsConn.close(1009, "Payload too large.");
          return;
        }
        let decrypted;
        try {
          const outer = JSON.parse(typeof rawFrame === "string" ? rawFrame : rawFrame.toString());
          if (!outer || typeof outer.enc !== "string") {
            wsConn.close(1008, "Unencrypted frame.");
            return;
          }
          decrypted = wsCipher.decryptFrame(wsConn.aesKey, outer.enc);
        } catch {
          wsConn.close(1007, "Bad encrypted frame.");
          return;
        }

        const { payload, error, closeCode } = parseClientMessage(decrypted);
        if (error) {
          wsConn.send(JSON.stringify({ type: "error", message: error }));
          wsConn.close(closeCode, error);
          return;
        }

        if (payload.type === "get_conversations") {
          const conversations = await getEnrichedConversations(userId);
          wsConn.send(JSON.stringify({ type: "conversations", conversations }));
          sendActiveVoiceCallsToSocket(user, wsConn);
          sendVoiceRostersToSocket(user, wsConn);
          sendGroupVoiceRostersToSocket(user, wsConn);
        } else if (VOICE_SIGNAL_TYPES.has(payload.type)) {
          relayVoiceSignal({ sender: user, payload, wsConn });
        } else if (VC_MESSAGE_TYPES.has(payload.type)) {
          handleVoiceChannelMessage({ user, payload, wsConn });
        } else if (GVC_MESSAGE_TYPES.has(payload.type)) {
          handleGroupVoiceMessage({ user, payload, wsConn });
        } else if (payload.type === "status_update") {
          const status = normalizeOwnStatus(payload.status);
          try { userRepository.updateLastSeen(userId, status); } catch { /* best effort */ }
          broadcastPresenceToPartners(userId);
          broadcastPresenceUpdate(userId);
        } else if (payload.type === "typing") {
          handleTypingSignal({ user, payload });
        } else if (payload.type === "server_channel_read") {
          handleChannelRead({ userId, payload, wsConn });
        }
      } catch (err) {
        console.error("Error processing WS message:", err);
        wsConn.send(JSON.stringify({ type: "error", message: "Failed to process message." }));
      }
    });

    wsConn.on("close", () => {
      const userSockets = clients.get(userId);
      if (userSockets) {
        userSockets.delete(wsConn);
        if (userSockets.size === 0) {
          clients.delete(userId);
          // Last tab closed - drop the user from any voice channel / group call / 1:1 call.
          leaveCurrentVoice(userId);
          leaveCurrentGroupVoice(userId);
          leaveCurrentDmVoice(userId);
          // ...and mark them offline now + flip the online dot in their partners'
          // sidebars, instead of leaving them "online" until last_seen goes stale.
          try { userRepository.markUserOffline(userId); } catch { /* best-effort */ }
          broadcastPresenceToPartners(userId);
          broadcastPresenceUpdate(userId);
        }
      }
    });
  });

  return wss;
}

// Number of distinct users with at least one live socket (for admin stats only).
function getOnlineUserCount() {
  return clients.size;
}

module.exports = { initWebSocketServer, broadcastToUser, broadcastToServerMembers, broadcastToGroupMembers, getEnrichedConversations, getOnlineUserCount };
