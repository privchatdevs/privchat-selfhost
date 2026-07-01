const express = require("express");
const { messageLimiter, messageSendLimiter, groupIconLimiter, pinLimiter } = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const {
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
} = require("../controllers/groupController");

const router = express.Router();

router.use(messageLimiter);

// Read-only
router.get("/", listGroups);
router.get("/:id", getGroup);
router.get("/:id/icon", getGroupIcon);
router.get("/:id/messages", getMessages);
router.get("/:id/pins", getGroupPins);

// Write - CSRF required
router.post("/", requireCsrf, createGroup);
// Group picture - raw image body (≤3 MB). express.raw only matches image types,
// so the group JSON parser (mounted in server.js) skips it.
router.post(
  "/:id/icon",
  groupIconLimiter,
  express.raw({ type: ["image/png", "image/jpeg", "image/webp"], limit: "3mb" }),
  requireCsrf,
  uploadGroupIcon
);
router.delete("/:id/icon", requireCsrf, removeGroupIcon);
router.post("/:id/messages", messageSendLimiter, requireCsrf, sendMessage);
router.patch("/:id/messages/:messageId", messageSendLimiter, requireCsrf, editMessage);
router.delete("/:id/messages/:messageId", requireCsrf, deleteMessage);
router.post("/:id/messages/:messageId/suppress-embed", messageSendLimiter, requireCsrf, suppressEmbed);
router.post("/:id/messages/:messageId/pin", pinLimiter, requireCsrf, pinGroupMessage);
router.delete("/:id/messages/:messageId/pin", pinLimiter, requireCsrf, unpinGroupMessage);
router.post("/:id/members", requireCsrf, addMembers);
// "/me" must be declared before the "/:userId" param route so leaving works.
router.delete("/:id/members/me", requireCsrf, leaveGroup);
router.delete("/:id/members/:userId", requireCsrf, removeMember);
// Owner-only: delete the whole group. Distinct path from the /members/* deletes.
router.delete("/:id", requireCsrf, deleteGroup);
// Owner-only: transfer ownership to another member.
router.post("/:id/owner/:userId", requireCsrf, transferOwnership);
// Owner-only: wipe all messages but keep the group + members.
router.post("/:id/purge", requireCsrf, purgeGroupMessages);
router.patch("/:id", requireCsrf, renameGroup);
router.post("/:id/read", requireCsrf, markRead);

module.exports = router;
