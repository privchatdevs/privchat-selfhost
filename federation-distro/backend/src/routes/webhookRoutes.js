const express = require("express");
const { getWebhookAvatarImage, executeWebhook, getWebhookInfo } = require("../controllers/serverController");
const { webhookLimiter } = require("../middleware/security");

// Public webhook endpoints - token-authenticated, NO session/CSRF. External
// clients (scripts, CI, etc.) POST here to drop a message into a channel.
const router = express.Router();

// Dedicated per-IP budget. The global limiter skips /api/webhooks, so hammering
// a webhook only exhausts this bucket - it can never 429 the user's app traffic.
router.use(webhookLimiter);

// Avatar is public so webhook-authored messages render for every channel viewer.
router.get("/:webhookId/avatar", getWebhookAvatarImage);

// Info: GET { id, name, channelName, serverName } so a client can tag its posts
// with the destination channel. Same token auth as execute. Defined AFTER /avatar
// so that literal path still wins over the :token placeholder.
router.get("/:webhookId/:token", getWebhookInfo);

// Execute: POST { content, username? } as application/json. Size-capped + the
// server-wide rate limit are enforced in the controller.
router.post("/:webhookId/:token", executeWebhook);

module.exports = router;
