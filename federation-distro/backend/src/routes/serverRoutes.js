const express = require("express");
const { serverAvatarLimiter, serverLimiter, serverCreateLimiter, serverMessageSendLimiter, roleMutationLimiter, pinLimiter } = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const {
  banMember,
  cloneChannel,
  createCategory,
  createChannel,
  createInvite,
  createRole,
  createServer,
  deleteCategory,
  deleteChannel,
  purgeChannel,
  deleteChannelMessage,
  suppressChannelMessageEmbed,
  editChannelMessage,
  deleteRole,
  deleteServer,
  getChannelMessages,
  getChannelPins,
  getServerSendKey,
  pinChannelMessage,
  unpinChannelMessage,
  getLinkPreview,
  getLinkPreviewImage,
  getMembers,
  getInviteIconImage,
  getInviteBannerImage,
  getPublicInvite,
  getServerDetails,
  getServerIconImage,
  getServerBannerImage,
  uploadServerBanner,
  joinByInvite,
  kickMember,
  leaveServer,
  listBannedMembers,
  listInvites,
  listInviteInvitees,
  clearInvites,
  listDiscoveryServers,
  listMyServers,
  reorderServers,
  renameCategory,
  renameChannel,
  reorderChannelLayout,
  reorderRoles,
  getChannelPermissions,
  setChannelPermission,
  revokeInvite,
  sendChannelMessage,
  getAutomod,
  updateAutomod,
  getServerPrivacy,
  setServerPrivacy,
  getMyPingBlockedServers,
  toggleChannelReaction,
  setMemberRoles,
  timeoutMember,
  setMemberNickname,
  unbanMember,
  updateRole,
  updateServer,
  transferOwnership,
  uploadServerIcon,
  listWebhooks,
  createWebhook,
  renameWebhook,
  deleteWebhook,
  uploadWebhookAvatar,
  applyForDiscovery,
  getMyDiscoveryApplication,
} = require("../controllers/serverController");

const router = express.Router();

router.use(serverLimiter);

// Invite join must be matched before the /:serverId routes.
router.get("/invites/:code", getPublicInvite);
router.get("/invites/:code/icon", getInviteIconImage);
router.get("/invites/:code/banner", getInviteBannerImage);
router.post("/invites/:code/join", requireCsrf, joinByInvite);

// Per-session AES key for the encrypted server-message send path - literal path,
// declared before the "/:serverId" catch-all so it isn't treated as a server id.
router.get("/send-key", getServerSendKey);

// Servers where the signed-in user has the ping block on (for client-side ping
// suppression). Literal path - declared before the "/:serverId" routes.
router.get("/privacy/mine", getMyPingBlockedServers);

// Servers
router.get("/discovery", listDiscoveryServers);
router.get("/", listMyServers);
router.post("/", serverCreateLimiter, requireCsrf, createServer);
// Literal path - must be declared before the "/:serverId" routes so "reorder"
// isn't parsed as a server id.
router.post("/reorder", requireCsrf, reorderServers);
router.get("/:serverId", getServerDetails);
router.patch("/:serverId", requireCsrf, updateServer);
router.post("/:serverId/transfer", requireCsrf, transferOwnership);
router.delete("/:serverId", requireCsrf, deleteServer);
router.get("/:serverId/discovery-application", getMyDiscoveryApplication);
router.post("/:serverId/discovery-application", requireCsrf, applyForDiscovery);

// Icon
router.get("/:serverId/icon", getServerIconImage);
router.post(
  "/:serverId/icon",
  serverAvatarLimiter,
  express.raw({ type: ["image/png", "image/jpeg", "image/webp"], limit: "3mb" }),
  requireCsrf,
  uploadServerIcon
);

// Banner (per-server 2/hour limit is enforced inside uploadServerBanner)
router.get("/:serverId/banner", getServerBannerImage);
router.post(
  "/:serverId/banner",
  serverAvatarLimiter,
  express.raw({ type: ["image/png", "image/jpeg", "image/webp", "image/gif"], limit: "10mb" }),
  requireCsrf,
  uploadServerBanner
);

// Invites
router.post("/:serverId/invites", requireCsrf, createInvite);
router.get("/:serverId/invites", listInvites);
router.get("/:serverId/invites/:code/invitees", listInviteInvitees);
router.delete("/:serverId/invites", requireCsrf, clearInvites);
router.delete("/:serverId/invites/:code", requireCsrf, revokeInvite);

// Members
router.get("/:serverId/members", getMembers);
router.delete("/:serverId/members/me", requireCsrf, leaveServer);
router.delete("/:serverId/members/:userId", requireCsrf, kickMember);
router.put("/:serverId/members/:userId/roles", requireCsrf, setMemberRoles);
router.post("/:serverId/members/:userId/timeout", requireCsrf, timeoutMember);
router.post("/:serverId/members/:userId/nickname", requireCsrf, setMemberNickname);

// Bans
router.get("/:serverId/bans", listBannedMembers);
router.post("/:serverId/bans/:userId", requireCsrf, banMember);
router.delete("/:serverId/bans/:userId", requireCsrf, unbanMember);

// AutoMod (owner / Manage Server)
router.get("/:serverId/automod", getAutomod);
router.put("/:serverId/automod", requireCsrf, updateAutomod);

// Per-server privacy ("Manage Privacy") - any member sets their own.
router.get("/:serverId/privacy", getServerPrivacy);
router.put("/:serverId/privacy", requireCsrf, setServerPrivacy);

// Roles
router.post("/:serverId/roles", roleMutationLimiter, requireCsrf, createRole);
router.put("/:serverId/roles/reorder", requireCsrf, reorderRoles);
router.patch("/:serverId/roles/:roleId", requireCsrf, updateRole);
router.delete("/:serverId/roles/:roleId", roleMutationLimiter, requireCsrf, deleteRole);

// Categories
router.post("/:serverId/categories", requireCsrf, createCategory);
router.patch("/:serverId/categories/:categoryId", requireCsrf, renameCategory);
router.delete("/:serverId/categories/:categoryId", requireCsrf, deleteCategory);

// Channels
router.post("/:serverId/channels", requireCsrf, createChannel);
router.put("/:serverId/channels/layout", requireCsrf, reorderChannelLayout);
router.patch("/:serverId/channels/:channelId", requireCsrf, renameChannel);
router.delete("/:serverId/channels/:channelId", requireCsrf, deleteChannel);
router.post("/:serverId/channels/:channelId/purge", requireCsrf, purgeChannel);
router.post("/:serverId/channels/:channelId/clone", requireCsrf, cloneChannel);
router.get("/:serverId/channels/:channelId/permissions", getChannelPermissions);
router.put("/:serverId/channels/:channelId/permissions", requireCsrf, setChannelPermission);

// Channel webhooks (management - gated by Manage Channels inside the controller)
router.get("/:serverId/channels/:channelId/webhooks", listWebhooks);
router.post("/:serverId/channels/:channelId/webhooks", requireCsrf, createWebhook);
router.patch("/:serverId/channels/:channelId/webhooks/:webhookId", requireCsrf, renameWebhook);
router.delete("/:serverId/channels/:channelId/webhooks/:webhookId", requireCsrf, deleteWebhook);
router.post(
  "/:serverId/channels/:channelId/webhooks/:webhookId/avatar",
  express.raw({ type: ["image/png", "image/jpeg", "image/webp"], limit: "3mb" }),
  requireCsrf,
  uploadWebhookAvatar
);

// Channel messages
router.get("/:serverId/link-preview", getLinkPreview);
router.get("/:serverId/link-preview/image", getLinkPreviewImage);
router.get("/:serverId/channels/:channelId/messages", getChannelMessages);
router.get("/:serverId/channels/:channelId/pins", getChannelPins);
router.post("/:serverId/channels/:channelId/messages", serverMessageSendLimiter, requireCsrf, sendChannelMessage);
router.patch("/:serverId/channels/:channelId/messages/:messageId", serverMessageSendLimiter, requireCsrf, editChannelMessage);
router.delete("/:serverId/channels/:channelId/messages/:messageId", requireCsrf, deleteChannelMessage);
router.post("/:serverId/channels/:channelId/messages/:messageId/suppress-embed", serverMessageSendLimiter, requireCsrf, suppressChannelMessageEmbed);
router.post("/:serverId/channels/:channelId/messages/:messageId/pin", pinLimiter, requireCsrf, pinChannelMessage);
router.delete("/:serverId/channels/:channelId/messages/:messageId/pin", pinLimiter, requireCsrf, unpinChannelMessage);
router.post("/:serverId/channels/:channelId/messages/:messageId/reactions", serverMessageSendLimiter, requireCsrf, toggleChannelReaction);

module.exports = router;
