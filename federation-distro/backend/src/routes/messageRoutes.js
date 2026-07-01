const express = require("express");
const { messageLimiter, messageSendLimiter, purgeLimiter, pinLimiter } = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const {
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
} = require("../controllers/messageController");
const { getUserLinkPreview, getUserLinkPreviewImage } = require("../controllers/serverController");

const router = express.Router();

// Live EventSource message stream (bypass rate limiting for persistent connections)
router.get("/stream", getMessageStream);

// All message routes below are rate-limited
router.use(messageLimiter);

// Read-only - no CSRF needed
router.get("/conversations", getConversations);
router.get("/conversation-pins", getDmConversationPins);
// Link-preview (embed) unfurling for DMs - must precede the "/:userId" catch-all.
router.get("/link-preview", getUserLinkPreview);
router.get("/link-preview/image", getUserLinkPreviewImage);
router.get("/profiles/:userId", getMessageProfile);
// Pinned messages - specific path before the "/:userId" message-list catch-all.
router.get("/:userId/pins", getDmPins);
router.get("/:userId", getMessages);

// Write - CSRF required
// Bulk "purge all DMs" - literal path declared before the "/:userId" routes.
// Tight purgeLimiter on top of the global one: this is a heavy, rare operation.
router.post("/purge-all", purgeLimiter, requireCsrf, purgeAllDms);
// Per-DM "cancel auto-delete" toggle. Literal second segment, so it's declared
// before the "/:userId/:messageId" routes to avoid being shadowed.
router.post("/:userId/conversation-pin", pinLimiter, requireCsrf, setDmConversationPin);
router.delete("/:userId/conversation-pin", pinLimiter, requireCsrf, setDmConversationPin);
router.post("/:userId/autodelete-exempt", requireCsrf, setDmAutoDeleteExempt);
router.post("/:userId/read", requireCsrf, markRead);
router.post("/:userId", messageSendLimiter, requireCsrf, sendMessage);
router.patch("/:userId/:messageId", messageSendLimiter, requireCsrf, editMessage);
router.post("/:userId/:messageId/reactions", messageSendLimiter, requireCsrf, toggleReaction);
router.post("/:userId/:messageId/suppress-embed", messageSendLimiter, requireCsrf, suppressEmbed);
router.post("/:userId/:messageId/pin", pinLimiter, requireCsrf, pinDmMessage);
router.delete("/:userId/:messageId/pin", pinLimiter, requireCsrf, unpinDmMessage);
router.delete("/:userId/:messageId", requireCsrf, deleteMessage);
router.delete("/:userId", requireCsrf, purgeMessages);

module.exports = router;
