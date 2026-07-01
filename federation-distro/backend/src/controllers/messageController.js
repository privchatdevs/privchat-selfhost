const { config } = require("../config/env");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const userRepository = require("../repositories/userRepository");
const friendRepository = require("../repositories/friendRepository");
const friendService = require("../services/friendService");
const serverRepository = require("../repositories/serverRepository");
const messageRepository = require("../repositories/messageRepository");
const messageService = require("../services/messageService");
const groupService = require("../services/groupService");
const groupRepository = require("../repositories/groupRepository");
const { publicGroup } = require("./groupController");
const assetService = require("../services/assetService");
const { broadcastToUser, broadcastToGroupMembers, getEnrichedConversations } = require("../services/websocketServer");
const { toUtcIso } = require("../utils/time");
const { isPublicOnline, publicPresenceStatus } = require("../services/presence");
const emojiCatalog = require("../config/emojiCatalog.json");

const MAX_MESSAGE_LENGTH = 2000;
const MAX_E2EE_PAYLOAD_LENGTH = 10000;
const EMOJI_CATALOG = new Set(emojiCatalog);

// Track active EventSource response streams: userId -> array of res objects
const clients = new Map();

// New-conversation rate limit: an account can START at most this many brand-new DM
// conversations per rolling hour. Replying inside a thread that already exists
// (either direction) is unlimited. In-memory sliding window keyed by user id - a
// restart just resets the window, which is fine for a soft anti-spam guard.
const NEW_CONVO_LIMIT = 3;
const NEW_CONVO_WINDOW_MS = 60 * 60 * 1000;
const newConvoStarts = new Map(); // userId -> number[] (start timestamps in the window)

// Returns true if the user is already at/over the limit (records nothing); otherwise
// records this start and returns false. Synchronous, so it's atomic per request.
function hitNewConversationLimit(userId) {
  const now = Date.now();
  const recent = (newConvoStarts.get(userId) || []).filter((t) => now - t < NEW_CONVO_WINDOW_MS);
  if (recent.length >= NEW_CONVO_LIMIT) {
    newConvoStarts.set(userId, recent); // keep the pruned window
    return true;
  }
  recent.push(now);
  newConvoStarts.set(userId, recent);
  return false;
}

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}

async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

function validateMessageContent(content, plaintextLength) {
  if (!content || typeof content !== "string" || content.trim().length === 0) {
    return "Message cannot be empty.";
  }

  const trimmed = content.trim();
  try {
    const parsed = JSON.parse(trimmed);
    if (parsed?.e2ee === true) {
      if (!Number.isInteger(plaintextLength) || plaintextLength < 1 || plaintextLength > MAX_MESSAGE_LENGTH) {
        return `Message cannot exceed ${MAX_MESSAGE_LENGTH} characters.`;
      }
      if (trimmed.length > MAX_E2EE_PAYLOAD_LENGTH) {
        return "Encrypted message payload is too large.";
      }
      return null;
    }
  } catch {
    // Plaintext messages are validated below.
  }

  if (trimmed.length > MAX_MESSAGE_LENGTH) {
    return `Message cannot exceed ${MAX_MESSAGE_LENGTH} characters.`;
  }
  return null;
}

function validateReactionEmoji(emoji) {
  if (!emoji || typeof emoji !== "string") return "Choose an emoji.";
  const trimmed = emoji.trim();
  if (!EMOJI_CATALOG.has(trimmed)) return "That emoji is not available.";
  return null;
}

function publicDmProfile(row, { includePresence = false, lastMessageAt = null, lastMessageId = null, lastReadAt = null, pinnedAt = null } = {}) {
  const publicId = row.public_user_id || row.user_id;
  return {
    userId: publicId,
    username: row.username,
    alias: row.profile_alias || "",
    bio: row.bio || "",
    profilePictureUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(row.updated_at || row.created_at || "")}`,
    profileBannerUrl: row.profile_banner_mime
      ? `/api/auth/profile-banner?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(row.updated_at || Date.now())}`
      : "",
    lastMessageAt: lastMessageAt ? toUtcIso(lastMessageAt) : null,
    lastMessageId,
    lastReadAt: lastReadAt ? toUtcIso(lastReadAt) : null,
    pinned: Boolean(pinnedAt),
    pinnedAt: pinnedAt ? toUtcIso(pinnedAt) : null,
    isOnline: includePresence ? isPublicOnline(row) : null,
    presenceStatus: includePresence ? publicPresenceStatus(row) : null,
    publicKey: row.public_key || null,
  };
}

/**
 * GET /api/messages/conversations
 * Returns the list of users the current user has messaged (for the sidebar).
 */
async function getConversations(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const conversations = await messageService.getActiveConversations(user.user_id);

    // Enrich each conversation with the partner's public profile info
    const enriched = conversations.map(({ userId: partnerId, lastMessageAt, lastMessageId, lastReadAt, pinnedAt }) => {
      const partner = userRepository.findByAnyId(partnerId);
      if (!partner) return null;

      return publicDmProfile(partner, {
        includePresence: friendService.canViewConversation(user.user_id, partner.user_id),
        lastMessageAt,
        lastMessageId,
        lastReadAt,
        pinnedAt,
      });
    });

    return res.json({ conversations: enriched.filter(Boolean) });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/messages/conversation-pins
 * Returns DM sidebar pins for the signed-in account.
 */
async function getDmConversationPins(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const ids = messageService.getPinnedConversationIds(user.user_id)
      .map((partnerId) => userRepository.findByAnyId(partnerId))
      .filter(Boolean)
      .map((partner) => partner.public_user_id || partner.user_id);
    return res.json({ pinnedConversations: ids });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST/DELETE /api/messages/:userId/conversation-pin
 * Pins or unpins a DM thread for the signed-in account.
 */
async function setDmConversationPin(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partner = userRepository.findByAnyId(req.params.userId);
    if (!partner || partner.user_id === user.user_id) {
      return res.status(404).json({ message: "User not found." });
    }
    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only pin conversations you can view." });
    }

    const pinned = req.method !== "DELETE";
    const row = messageService.setConversationPinned(user.user_id, partner.user_id, pinned);
    const pinnedAt = pinned ? toUtcIso(row?.pinned_at) : null;
    const partnerPublicId = partner.public_user_id || partner.user_id;
    const payload = { type: "conversation_pin_update", partnerId: partnerPublicId, pinned, pinnedAt };
    broadcastToUser(user.user_id, payload);
    getEnrichedConversations(user.user_id)
      .then((conversations) => broadcastToUser(user.user_id, { type: "conversations", conversations }))
      .catch(() => {});
    return res.json({ ok: true, pinned, pinnedAt });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST /api/messages/:userId/read
 * Marks the conversation with :userId read (server-side), so every signed-in
 * device clears its unread. Pushes the refreshed list to the user's sessions.
 */
async function markRead(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partner = userRepository.findByAnyId(req.params.userId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    messageService.markConversationRead(user.user_id, partner.user_id);
    getEnrichedConversations(user.user_id)
      .then((conversations) => broadcastToUser(user.user_id, { type: "conversations", conversations }))
      .catch(() => {});
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/messages/profiles/:userId
 * Returns a DM partner profile only when the current user may DM that user.
 */
async function getMessageProfile(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partner = userRepository.findByAnyId(req.params.userId);
    if (!partner || partner.user_id === user.user_id) {
      return res.status(404).json({ message: "User not found." });
    }

    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only view DM profiles for friends or people who share a server with you." });
    }

    // Nicknames this person goes by in servers you both share ("aka" line).
    const aka = serverRepository.getSharedServerNicknames(user.user_id, partner.user_id, 5);
    return res.json({ user: { ...publicDmProfile(partner, { includePresence: true }), aka } });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/messages/:userId
 * Returns the message history between the current user and the given user.
 */
async function getMessages(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partnerPublicId = req.params.userId;
    const partner = userRepository.findByAnyId(partnerPublicId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    // Viewing history stays open for any thread you've talked in (even after an
    // unfriend); only SENDING is gated by current privacy.
    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only view conversations with friends or people who share a server with you." });
    }

    const { before } = req.query; // ISO timestamp cursor for pagination

    const messages = await messageService.getMessages(user.user_id, partner.user_id, 50, before || null);

    // Map internal user IDs to public IDs for the client
    const myPublicId = user.public_user_id || user.user_id;
    const partnerPubId = partner.public_user_id || partner.user_id;
    const reactionsByMessage = await messageService.getReactionsForMessages(
      messages.map((m) => m.message_id),
      user.user_id
    );

    const mapped = messages.map((m) => ({
      messageId: m.message_id,
      senderId: m.sender_id === user.user_id ? myPublicId : partnerPubId,
      content: m.content,
      createdAt: toUtcIso(m.created_at),
      editedAt: m.edited_at ? toUtcIso(m.edited_at) : null,
      replyToMessageId: m.reply_to_message_id || null,
      expiresAt: m.expires_at ? toUtcIso(m.expires_at) : null,
      pinnedAt: m.pinned_at ? toUtcIso(m.pinned_at) : null,
      suppressedEmbeds: parseSuppressedEmbeds(m.suppressed_embeds),
      reactions: reactionsByMessage[m.message_id] || [],
    }));

    // Auto-delete summary (from global settings) so the client can show the banner.
    const autoDelete = dmAutoDeleteSummary(user.user_id, partner.user_id);

    // hasMore = true if we got a full page (meaning there may be older messages)
    return res.json({ messages: mapped, hasMore: messages.length === 50, autoDelete });
  } catch (err) {
    return next(err);
  }
}

// Seconds until a message from `senderId` to `recipientId` should auto-delete
// (0 = never), based on both users' global settings: the sender's own DM
// auto-delete, plus the recipient's "also delete the other person's messages"
// option. The shortest applicable timer wins.
function dmTtlSeconds(senderId, recipientId) {
  const sender = userRepository.getAutoDeleteSettings(senderId);
  const recipient = userRepository.getAutoDeleteSettings(recipientId);
  const candidates = [];
  // A user who has "cancelled auto-delete for this DM" drops out of the timer math
  // for that conversation: the sender's own auto-delete is skipped when they've
  // exempted this thread, and the recipient's "also delete theirs" is skipped when
  // they have. The other person's still-active auto-delete is left untouched.
  if (sender.dms && !messageRepository.getConversationAutoDeleteExempt(senderId, recipientId)) {
    candidates.push(sender.seconds);
  }
  if (recipient.dms && recipient.dmsBoth && !messageRepository.getConversationAutoDeleteExempt(recipientId, senderId)) {
    candidates.push(recipient.seconds);
  }
  return candidates.length ? Math.min(...candidates) : 0;
}

// Who has DM auto-delete switched ON (and at what interval), so the client can show a
// persistent top banner ("<name> uses auto-delete") instead of an inline notice. Keyed
// on each person's own setting (not the message-TTL math), so the banner names whoever
// actually enabled it. When someone turns it off, their side simply reads enabled:false
// and the banner drops - we never post a "disabled" announcement.
function dmAutoDeleteSummary(meId, partnerId) {
  const me = userRepository.getAutoDeleteSettings(meId);
  const partner = userRepository.getAutoDeleteSettings(partnerId);
  return {
    // `exempt` = I've cancelled auto-delete for THIS DM (only meaningful when my
    // global DM auto-delete is on). The client uses it to label the menu toggle
    // and to drop the "You use auto-delete" banner for this thread.
    self: {
      enabled: Boolean(me.dms),
      seconds: me.seconds,
      exempt: messageRepository.getConversationAutoDeleteExempt(meId, partnerId),
    },
    partner: { enabled: Boolean(partner.dms), seconds: partner.seconds },
    // Effective per-direction delete time (0 = never), so the banner can describe
    // exactly what disappears. These run the full timer math, so the "also delete
    // both people's messages" scope and per-DM exemptions are already folded in:
    // e.g. with my "both" on, theirMessagesSeconds becomes my interval too.
    yourMessagesSeconds: dmTtlSeconds(meId, partnerId),   // messages I send
    theirMessagesSeconds: dmTtlSeconds(partnerId, meId),  // messages they send
  };
}

/**
 * POST /api/messages/:userId/autodelete-exempt
 * Toggle whether THIS DM is exempt from the caller's global DM auto-delete.
 * Body: { exempt: boolean }. Returns the refreshed auto-delete summary.
 */
async function setDmAutoDeleteExempt(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partner = userRepository.findByAnyId(req.params.userId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    const exempt = Boolean(req.body?.exempt);
    messageRepository.setConversationAutoDeleteExempt(user.user_id, partner.user_id, exempt);

    // If the exemption removes all auto-delete coverage for a direction, keep the
    // messages that were already scheduled to vanish (mirrors disabling auto-delete);
    // the other person's still-active auto-delete keeps its own timers.
    if (dmTtlSeconds(user.user_id, partner.user_id) === 0) {
      await messageRepository.clearPendingExpiry(user.user_id, partner.user_id);
    }
    if (dmTtlSeconds(partner.user_id, user.user_id) === 0) {
      await messageRepository.clearPendingExpiry(partner.user_id, user.user_id);
    }

    return res.json({ exempt, autoDelete: dmAutoDeleteSummary(user.user_id, partner.user_id) });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST /api/messages/:userId
 * Send a message to the given user.
 */
async function sendMessage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partnerPublicId = req.params.userId;
    const partner = userRepository.findByAnyId(partnerPublicId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    const block = friendRepository.getBlockBetween(user.user_id, partner.user_id);
    if (block?.blocker_id === user.user_id) {
      return res.status(403).json({ message: "You cannot send a message to this user for you have blocked them." });
    }
    if (block?.blocker_id === partner.user_id) {
      return res.status(403).json({ message: "You cannot message this user for they have blocked you." });
    }

    // Friends or shared-server members can message each other
    if (!friendService.canDirectMessage(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only message friends or people who share a server with you." });
    }

    const { content, plaintextLength } = req.body;
    const validationError = validateMessageContent(content, plaintextLength);
    if (validationError) return res.status(400).json({ message: validationError });

    // Rate-limit STARTING new conversations (3/hour). A thread that already exists
    // in either direction means this is a reply, which is never limited. The flag
    // tells the client this isn't a transient limit to queue + retry, but a hard
    // stop to surface to the user.
    const isNewConversation = !messageRepository.conversationExists(user.user_id, partner.user_id);
    if (isNewConversation && hitNewConversationLimit(user.user_id)) {
      return res.status(429).json({
        newConversationLimit: true,
        message: "You're starting new conversations too quickly. You can start up to 3 new conversations per hour - try again later.",
      });
    }

    const myPublicId = user.public_user_id || user.user_id;

    // Auto-delete is surfaced as a persistent top banner on DM load (dmAutoDeleteSummary),
    // not an inline "X has auto-delete enabled" system message anymore.

    const replyToMessageId = typeof req.body?.replyToMessageId === "string" ? req.body.replyToMessageId : null;
    const saved = await messageService.saveMessage({
      senderId: user.user_id,
      receiverId: partner.user_id,
      content: content.trim(),
      replyToMessageId,
      ttlSeconds: dmTtlSeconds(user.user_id, partner.user_id),
    });

    // Notify active streams in real-time
    const notify = (targetId, eventData) => {
      const list = clients.get(targetId);
      if (list) {
        list.forEach((client) => {
          client.write(`data: ${JSON.stringify(eventData)}\n\n`);
        });
      }
    };

    const senderInternalId = user.user_id;
    const receiverInternalId = partner.user_id;

    // Send 'message' event to both participants
    notify(senderInternalId, { type: "message", partnerId: partnerPublicId });
    notify(receiverInternalId, { type: "message", partnerId: myPublicId });

    // Send 'conversation' event to refresh their sidebar
    notify(senderInternalId, { type: "conversation" });
    notify(receiverInternalId, { type: "conversation" });

    // WebSocket real-time broadcast fallback/sync
    const msgPayload = {
      type: "message",
      messageId: saved.message_id,
      senderId: myPublicId,
      receiverId: partnerPublicId,
      content: saved.content,
      createdAt: toUtcIso(saved.created_at),
      editedAt: saved.edited_at ? toUtcIso(saved.edited_at) : null,
      replyToMessageId: saved.reply_to_message_id || null,
      expiresAt: saved.expires_at ? toUtcIso(saved.expires_at) : null,
      reactions: [],
    };
    broadcastToUser(senderInternalId, msgPayload);
    broadcastToUser(receiverInternalId, msgPayload);

    getEnrichedConversations(senderInternalId)
      .then((convs) => broadcastToUser(senderInternalId, { type: "conversations", conversations: convs }))
      .catch((err) => console.error("WS sender sidebar push error:", err));

    getEnrichedConversations(receiverInternalId)
      .then((convs) => broadcastToUser(receiverInternalId, { type: "conversations", conversations: convs }))
      .catch((err) => console.error("WS receiver sidebar push error:", err));

    return res.status(201).json({
      message: {
        messageId: saved.message_id,
        senderId: myPublicId,
        content: saved.content,
        createdAt: toUtcIso(saved.created_at),
        editedAt: saved.edited_at ? toUtcIso(saved.edited_at) : null,
        replyToMessageId: saved.reply_to_message_id || null,
        expiresAt: saved.expires_at ? toUtcIso(saved.expires_at) : null,
        reactions: [],
      },
    });
  } catch (err) {
    return next(err);
  }
}

/**
 * PATCH /api/messages/:userId/:messageId
 * Edit one message sent by the current user.
 */
async function editMessage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partnerPublicId = req.params.userId;
    const partner = userRepository.findByAnyId(partnerPublicId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    if (!friendService.canDirectMessage(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only message friends or people who share a server with you." });
    }

    const existing = await messageService.getMessageById(req.params.messageId);
    if (!existing || existing.sender_id !== user.user_id || existing.receiver_id !== partner.user_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    const { content, plaintextLength } = req.body;
    const validationError = validateMessageContent(content, plaintextLength);
    if (validationError) return res.status(400).json({ message: validationError });

    const updated = await messageService.updateMessageContent({
      messageId: req.params.messageId,
      senderId: user.user_id,
      receiverId: partner.user_id,
      content: content.trim(),
    });
    if (!updated) return res.status(404).json({ message: "Message not found." });

    const myPublicId = user.public_user_id || user.user_id;
    const payload = {
      type: "message_update",
      messageId: updated.message_id,
      senderId: myPublicId,
      receiverId: partnerPublicId,
      content: updated.content,
      createdAt: toUtcIso(updated.created_at),
      editedAt: updated.edited_at ? toUtcIso(updated.edited_at) : null,
    };

    broadcastToUser(user.user_id, payload);
    broadcastToUser(partner.user_id, payload);

    return res.json({
      message: {
        messageId: updated.message_id,
        senderId: myPublicId,
        content: updated.content,
        createdAt: toUtcIso(updated.created_at),
        editedAt: updated.edited_at ? toUtcIso(updated.edited_at) : null,
      },
    });
  } catch (err) {
    return next(err);
  }
}

// Safely parse a message row's suppressed_embeds JSON into an array of indices.
function parseSuppressedEmbeds(raw) {
  if (!raw) return [];
  try { const arr = JSON.parse(raw); return Array.isArray(arr) ? arr : []; } catch { return []; }
}

/**
 * DELETE /api/messages/:userId/:messageId
 * Delete one message sent by the current user.
 */
async function deleteMessage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partnerPublicId = req.params.userId;
    const partner = userRepository.findByAnyId(partnerPublicId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only view conversations with friends or people who share a server with you." });
    }

    const existing = await messageService.getMessageById(req.params.messageId);
    if (!existing || existing.sender_id !== user.user_id || existing.receiver_id !== partner.user_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    const deleted = await messageService.deleteMessage({
      messageId: req.params.messageId,
      senderId: user.user_id,
      receiverId: partner.user_id,
    });
    if (!deleted) return res.status(404).json({ message: "Message not found." });

    const myPublicId = user.public_user_id || user.user_id;
    broadcastToUser(user.user_id, { type: "message_delete", messageId: req.params.messageId, partnerId: partnerPublicId });
    broadcastToUser(partner.user_id, { type: "message_delete", messageId: req.params.messageId, partnerId: myPublicId });

    getEnrichedConversations(user.user_id)
      .then((convs) => broadcastToUser(user.user_id, { type: "conversations", conversations: convs }))
      .catch((err) => console.error("WS delete sender sidebar push error:", err));

    getEnrichedConversations(partner.user_id)
      .then((convs) => broadcastToUser(partner.user_id, { type: "conversations", conversations: convs }))
      .catch((err) => console.error("WS delete receiver sidebar push error:", err));

    return res.json({ deleted });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST /api/messages/:userId/:messageId/suppress-embed
 * Hide one embed (by index) on a DM message. Author only - you control your own
 * message's embeds. Persisted server-side and broadcast so it hides for both sides.
 */
async function suppressEmbed(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partnerPublicId = req.params.userId;
    const partner = userRepository.findByAnyId(partnerPublicId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only view conversations with friends or people who share a server with you." });
    }

    const existing = await messageService.getMessageById(req.params.messageId);
    if (!existing || existing.sender_id !== user.user_id || existing.receiver_id !== partner.user_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    const index = Number(req.body?.index);
    if (!Number.isInteger(index) || index < 0 || index > 1) {
      return res.status(400).json({ message: "Invalid embed index." });
    }

    const suppressedEmbeds = messageRepository.addSuppressedEmbed(req.params.messageId, index);
    if (!suppressedEmbeds) return res.status(404).json({ message: "Message not found." });

    const myPublicId = user.public_user_id || user.user_id;
    broadcastToUser(user.user_id, { type: "message_embed_suppressed", messageId: req.params.messageId, partnerId: partnerPublicId, suppressedEmbeds });
    broadcastToUser(partner.user_id, { type: "message_embed_suppressed", messageId: req.params.messageId, partnerId: myPublicId, suppressedEmbeds });

    return res.json({ suppressedEmbeds });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST /api/messages/:userId/:messageId/reactions
 * Toggle one emoji reaction from the current user.
 */
async function toggleReaction(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partnerPublicId = req.params.userId;
    const partner = userRepository.findByAnyId(partnerPublicId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only view conversations with friends or people who share a server with you." });
    }

    const existing = await messageService.getMessageById(req.params.messageId);
    const isConversationMessage = existing && (
      (existing.sender_id === user.user_id && existing.receiver_id === partner.user_id) ||
      (existing.sender_id === partner.user_id && existing.receiver_id === user.user_id)
    );
    if (!isConversationMessage) {
      return res.status(404).json({ message: "Message not found." });
    }

    const emoji = typeof req.body.emoji === "string" ? req.body.emoji.trim() : "";
    const validationError = validateReactionEmoji(emoji);
    if (validationError) return res.status(400).json({ message: validationError });

    const result = await messageService.toggleReaction({
      messageId: req.params.messageId,
      userId: user.user_id,
      emoji,
    });
    if (result.blocked) {
      return res.status(409).json({ message: "This message already has 5 different reactions." });
    }

    const reactionsByMessage = await messageService.getReactionsForMessages([req.params.messageId], user.user_id);
    const reactionsForUser = reactionsByMessage[req.params.messageId] || [];
    const reactionsForPartner = (
      await messageService.getReactionsForMessages([req.params.messageId], partner.user_id)
    )[req.params.messageId] || [];

    const myPublicId = user.public_user_id || user.user_id;
    broadcastToUser(user.user_id, {
      type: "reaction_update",
      messageId: req.params.messageId,
      partnerId: partnerPublicId,
      reactions: reactionsForUser,
    });
    broadcastToUser(partner.user_id, {
      type: "reaction_update",
      messageId: req.params.messageId,
      partnerId: myPublicId,
      reactions: reactionsForPartner,
    });

    return res.json({ action: result.action, reactions: reactionsForUser });
  } catch (err) {
    return next(err);
  }
}

// Verify the message exists and belongs to the conversation between `user` and
// `partner`. Returns the row or null. Shared by pin/unpin.
async function conversationMessageOrNull(user, partner, messageId) {
  const existing = await messageService.getMessageById(messageId);
  const ok = existing && (
    (existing.sender_id === user.user_id && existing.receiver_id === partner.user_id) ||
    (existing.sender_id === partner.user_id && existing.receiver_id === user.user_id)
  );
  return ok ? existing : null;
}

/**
 * POST /api/messages/:userId/:messageId/pin  - pin a DM message.
 * Either participant may pin (DMs have no roles), Discord-style.
 */
async function pinDmMessage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partner = userRepository.findByAnyId(req.params.userId);
    if (!partner) return res.status(404).json({ message: "User not found." });
    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only pin messages in conversations with friends." });
    }
    const existing = await conversationMessageOrNull(user, partner, req.params.messageId);
    if (!existing) {
      return res.status(404).json({ message: "Message not found." });
    }
    const wasAlreadyPinned = Boolean(existing.pinned_at);

    const result = messageService.pinMessage({
      messageId: req.params.messageId,
      userA: user.user_id,
      userB: partner.user_id,
      pinnedBy: user.user_id,
    });
    if (!result.ok && result.reason === "limit") {
      return res.status(409).json({ message: "This conversation has reached the pin limit (50)." });
    }

    const myPublicId = user.public_user_id || user.user_id;
    const partnerPubId = partner.public_user_id || partner.user_id;
    broadcastToUser(user.user_id, { type: "message_pin", messageId: req.params.messageId, partnerId: req.params.userId });
    broadcastToUser(partner.user_id, { type: "message_pin", messageId: req.params.messageId, partnerId: myPublicId });

    // Persisted "X pinned a message" system notice - posted once, only when the
    // message wasn't already pinned (a no-op re-pin stays silent). Rendered as a
    // centered grey line, same as the auto-delete notices.
    if (result.ok && !wasAlreadyPinned) {
      const actor = user.profile_alias || user.username || "Someone";
      const noticeRow = await messageService.saveMessage({
        senderId: user.user_id,
        receiverId: partner.user_id,
        // `target` = the pinned message, so clicking the notice can jump to it.
        content: JSON.stringify({ system: true, kind: "pin", actor, target: req.params.messageId }),
        ttlSeconds: 0, // the notice itself never auto-deletes
      });
      const notice = {
        type: "message",
        messageId: noticeRow.message_id,
        senderId: myPublicId,
        receiverId: partnerPubId,
        content: noticeRow.content,
        createdAt: toUtcIso(noticeRow.created_at),
        editedAt: null,
        replyToMessageId: null,
        expiresAt: null,
        reactions: [],
      };
      broadcastToUser(user.user_id, notice);
      broadcastToUser(partner.user_id, notice);
    }
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/**
 * DELETE /api/messages/:userId/:messageId/pin  - unpin a DM message.
 */
async function unpinDmMessage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partner = userRepository.findByAnyId(req.params.userId);
    if (!partner) return res.status(404).json({ message: "User not found." });
    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only unpin messages in conversations with friends." });
    }
    if (!(await conversationMessageOrNull(user, partner, req.params.messageId))) {
      return res.status(404).json({ message: "Message not found." });
    }

    messageService.unpinMessage({
      messageId: req.params.messageId,
      userA: user.user_id,
      userB: partner.user_id,
    });

    const myPublicId = user.public_user_id || user.user_id;
    broadcastToUser(user.user_id, { type: "message_unpin", messageId: req.params.messageId, partnerId: req.params.userId });
    broadcastToUser(partner.user_id, { type: "message_unpin", messageId: req.params.messageId, partnerId: myPublicId });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/messages/:userId/pins  - pinned messages for this DM, newest first.
 * Content is still E2E ciphertext; the client decrypts it like the message list.
 */
async function getDmPins(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partner = userRepository.findByAnyId(req.params.userId);
    if (!partner) return res.status(404).json({ message: "User not found." });
    if (!friendService.canViewConversation(user.user_id, partner.user_id)) {
      return res.status(403).json({ message: "You can only view conversations with friends or people who share a server with you." });
    }

    const rows = messageService.getPinnedMessages(user.user_id, partner.user_id);
    const myPublicId = user.public_user_id || user.user_id;
    const partnerPubId = partner.public_user_id || partner.user_id;
    const messages = rows.map((m) => ({
      messageId: m.message_id,
      senderId: m.sender_id === user.user_id ? myPublicId : partnerPubId,
      content: m.content,
      createdAt: toUtcIso(m.created_at),
      editedAt: m.edited_at ? toUtcIso(m.edited_at) : null,
      replyToMessageId: m.reply_to_message_id || null,
      pinnedAt: m.pinned_at ? toUtcIso(m.pinned_at) : null,
      // Who pinned it - in a DM that's always one of the two participants, so map
      // the internal id straight to its public id (client resolves name + avatar).
      pinnedBy: m.pinned_by ? (m.pinned_by === user.user_id ? myPublicId : partnerPubId) : null,
    }));
    return res.json({ messages });
  } catch (err) {
    return next(err);
  }
}

/**
 * DELETE /api/messages/:userId
 * Delete every message in the DM conversation.
 */
async function purgeMessages(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const partnerPublicId = req.params.userId;
    const partner = userRepository.findByAnyId(partnerPublicId);
    if (!partner) return res.status(404).json({ message: "User not found." });

    await messageService.purgeConversation(user.user_id, partner.user_id);
    const myPublicId = user.public_user_id || user.user_id;

    broadcastToUser(user.user_id, { type: "purge", partnerId: partnerPublicId });
    broadcastToUser(partner.user_id, { type: "purge", partnerId: myPublicId });

    getEnrichedConversations(user.user_id)
      .then((convs) => broadcastToUser(user.user_id, { type: "conversations", conversations: convs }))
      .catch((err) => console.error("WS sidebar refresh error:", err));

    getEnrichedConversations(partner.user_id)
      .then((convs) => broadcastToUser(partner.user_id, { type: "conversations", conversations: convs }))
      .catch((err) => console.error("WS sidebar refresh error:", err));

    // Intentionally return no count - the purge leaves no record of how many
    // (or that any) messages were deleted.
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/**
 * POST /api/messages/purge-all
 * Delete every DM the user is part of and close all of their threads. The
 * messages are shared rows, so the partners' copies go too - refresh them.
 */
async function purgeAllDms(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    // Snapshot partners BEFORE the wipe so we know whom to notify.
    const partnerIds = messageService.getConversationPartnerIds(user.user_id);
    await messageService.purgeAllDms(user.user_id);
    const myPublicId = user.public_user_id || user.user_id;

    // "Purge my DMs" also drops the user out of every group chat: their authored
    // group messages are deleted (the rest of each group's history stays) and all
    // of their uploaded files are erased everywhere. Tell their client to remove
    // each group from the sidebar immediately.
    const { leftGroupIds, survivingGroupIds } = await groupService.purgeUserFromAllGroups(user.user_id);
    await assetService.purgeOwnerAssets(myPublicId);
    for (const groupId of leftGroupIds) {
      broadcastToUser(user.user_id, { type: "group_removed", groupId });
    }
    // Surviving groups lost a member (and maybe gained a new random owner) - tell
    // the remaining members so their member list + owner crown update live.
    for (const groupId of survivingGroupIds) {
      const group = groupRepository.getGroup(groupId);
      if (group) broadcastToGroupMembers(group.group_id, { type: "group_update", group: publicGroup(group, { withMembers: true }) });
    }

    // Notify with cheap websocket events only - each client refreshes its OWN
    // sidebar (the "purge"/"purge_all" handlers call refreshDmSidebar). We do NOT
    // run getEnrichedConversations per partner here: that would be unbounded DB
    // work for a user with many conversations. broadcastToUser is a no-op for
    // anyone offline, so the fan-out stays cheap regardless of partner count.
    broadcastToUser(user.user_id, { type: "purge_all" });
    for (const partnerId of partnerIds) {
      if (partnerId === user.user_id) continue;
      broadcastToUser(partnerId, { type: "purge", partnerId: myPublicId });
    }

    // Intentionally return no count - leaves no record of how many were deleted.
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /api/messages/stream
 * Persistent EventSource connection for real-time notifications.
 */
async function getMessageStream(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no", // Bypass proxy buffering
    });
    res.write("\n");

    const userId = user.user_id;
    if (!clients.has(userId)) {
      clients.set(userId, []);
    }
    clients.get(userId).push(res);

    req.on("close", () => {
      const list = clients.get(userId) || [];
      const index = list.indexOf(res);
      if (index !== -1) {
        list.splice(index, 1);
      }
      if (list.length === 0) {
        clients.delete(userId);
      }
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  validateReactionEmoji,
  getConversations,
  getDmConversationPins,
  setDmConversationPin,
  markRead,
  getMessageProfile,
  getMessages,
  sendMessage,
  editMessage,
  deleteMessage,
  suppressEmbed,
  toggleReaction,
  pinDmMessage,
  unpinDmMessage,
  getDmPins,
  purgeMessages,
  purgeAllDms,
  setDmAutoDeleteExempt,
  getMessageStream,
};
