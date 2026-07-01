const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { config } = require("../config/env");

const APP_PERMISSIONS_POLICY = [
  "camera=(self)",
  "microphone=(self)",
  "display-capture=(self)",
  "autoplay=*",
  "fullscreen=*",
  "encrypted-media=*",
  "geolocation=()",
  "payment=()",
  "usb=()",
  "magnetometer=()",
  "gyroscope=()",
  "accelerometer=()",
  "midi=()",
  "browsing-topics=()",
  "interest-cohort=()",
].join(", ");

/**
 * Global baseline: 2000 requests per 15 minutes.
 * Generous enough for normal browsing and user actions across multiple tabs.
 * Direct-message conversation updates are pushed over a websocket.
 */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 2000,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please slow down and try again later." },
  // Public webhook traffic (external scripts/CI) gets its own dedicated budget
  // via webhookLimiter. Skip it here so a webhook posting in a loop can't drain
  // the per-IP global budget and 429 unrelated endpoints (heartbeat, etc.) for
  // the same client.
  skip: (req) => req.path.startsWith("/api/webhooks"),
});

/**
 * Public webhook endpoints: 30 requests per 60 seconds per IP. Its own bucket,
 * entirely separate from the global limiter, so spamming a webhook only ever
 * exhausts this budget - never the user's app traffic (heartbeat, messages, etc.).
 * This is the per-source guard; the controller also enforces a per-webhook cap
 * (keyed by webhook id, 15/min) that IP rotation / proxies cannot bypass.
 */
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many webhook requests. Please slow down and try again." },
});

/**
 * Auth endpoints (login / register): 60 requests per 15 minutes per IP.
 * Generous enough for normal use; the per-account wrong-password check in
 * authService is the primary login brute-force defence.
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Try again later." },
});

/**
 * Profile picture uploads: 5 changes per 60 seconds per IP.
 * Prevents both spam uploads and server-side image-processing abuse.
 */
const profilePictureLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many profile picture changes. Please wait a minute and try again." },
});

/**
 * Server avatar uploads: 5 changes per 60 seconds per IP.
 * Keeps server icon changes from being spammed or used for upload abuse.
 */
const serverAvatarLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many server avatar changes. Please wait a minute and try again." },
});

// Group-chat icon uploads (heavy: each writes to B2). 5 per minute, like the
// profile-picture / server-avatar limiters.
const groupIconLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many group icon changes. Please wait a minute and try again." },
});

/**
 * Profile / alias / bio updates: 10 changes per 60 seconds per IP.
 * Generous for legitimate use, blocks rapid automated patching.
 */
const profileUpdateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many profile update requests. Please wait a minute and try again." },
});

// Dedicated limiter for badge show/hide toggles (its own budget, separate from
// other profile updates). 12 toggles per 30s is plenty for legit use while
// stopping rapid spam of the endpoint.
const badgeUpdateLimiter = rateLimit({
  windowMs: 30 * 1000,
  limit: 12,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You're changing badges too fast. Please wait a few seconds and try again." },
});

/**
 * Username changes: 3 per 15 minutes per IP.
 * Username changes are already gated by a 7-day per-account cooldown and an
 * argon2 password check; this adds a network-layer guard against rapid retries.
 */
const usernameLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 3,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many username change requests. Please try again later." },
});

/**
 * CSRF token endpoint: 200 fetches per 15 minutes per IP.
 * The CSRF token is re-fetched before every authenticated action.
 */
const csrfLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Try again later." },
});

/**
 * Heartbeat endpoint: 60 pings per 15 minutes per IP (one every ~15 s max).
 * The client pings every 5 minutes in practice, so this is very generous.
 */
const heartbeatLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Try again later." },
});

/**
 * Friends API: 120 requests per 60 seconds per IP.
 * Covers reads (GET friends/pending) every 30s plus user interactions.
 */
const friendsLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please slow down and try again." },
});

/**
 * Messages API: 120 requests per 60 seconds per IP.
 * Conversation-list refreshes are handled by websocket, so this mainly covers
 * initial loads, pagination, and message mutations.
 */
const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many message requests. Please slow down." },
});

/**
 * Sending messages: 10 sends per 10 seconds per IP.
 * The client keeps up to 10 over-limit sends pending and retries after reset.
 */
const messageSendLimiter = rateLimit({
  windowMs: 10 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You are being rate limited." },
});

/**
 * Email verification code entry: 5 attempts per 60 seconds per IP.
 * A 6-digit code has 1,000,000 possibilities and expires in 15 minutes, so this
 * makes brute-forcing it infeasible.
 */
const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many verification attempts. Please wait a minute and try again." },
});

/**
 * Security settings (2FA + auto-delete config): 20 per minute per IP. Generous
 * enough for flipping several toggles at once, tight enough to block abuse.
 */
const securityLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many settings changes. Please wait a minute and try again." },
});

/**
 * Bulk data purges (purge all DMs / purge all friends): 5 per 15 minutes per IP,
 * shared across both endpoints. Each purge is a heavy, one-off cleanup (batched
 * table-wide deletes + a fan-out to every affected user), so it's deliberately
 * tight - a legitimate user runs it at most a handful of times, never in a loop.
 */
const purgeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You're purging too often. Please wait a few minutes and try again." },
});

/**
 * Servers API: 180 requests per 60 seconds per IP.
 * Covers rail/list refreshes, member lists, and settings interactions.
 */
const serverLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 180,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please slow down and try again." },
});

/**
 * Creating servers: 2 per 5 minutes per IP. Server creation is heavy (channels,
 * roles, default setup), so this stops someone spamming new servers.
 */
const serverCreateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 2,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You're creating servers too quickly. Please wait a few minutes and try again." },
});

/**
 * Sending server channel messages: 10 sends per 10 seconds per IP,
 * mirroring the DM send limit.
 */
const serverMessageSendLimiter = rateLimit({
  windowMs: 10 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You are being rate limited." },
});

/**
 * Creating/deleting roles: 10 mutations per minute per IP. Shared across both the
 * create and delete routes so a burst of either counts toward the same budget.
 */
const roleMutationLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You are creating or deleting roles too quickly. Please slow down." },
});

/**
 * DM attachment uploads: 20 files per 60 seconds per IP. Generous for normal
 * sharing while bounding B2 upload abuse; the 50 MB per-user rolling budget is
 * the real storage cap.
 */
const assetUploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You are uploading too fast. Please wait a moment and try again." },
});

/**
 * Pinning / unpinning: 15 actions per 60 seconds per IP, shared across DM
 * sidebar pins plus DM, group, and server message pin + unpin routes. Each
 * pin/unpin can broadcast and refresh UI, so this blocks rapid toggling while
 * staying generous for normal use.
 */
const pinLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 15,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "You're pinning too fast. Please wait a moment and try again." },
});

/**
 * Federation endpoints (/api/federation/*): 30 requests per 60 seconds per IP.
 * These are hit by other servers, not browsers - a peer only needs an
 * occasional key fetch (keys are cacheable for 24h) and a discovery probe, so
 * a tight budget blunts key-fetch floods and malformed-request probing.
 */
const federationLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many federation requests. Please slow down." },
});

function applySecurity(app) {
  app.use((_req, res, next) => {
    res.setHeader("Permissions-Policy", APP_PERMISSIONS_POLICY);
    next();
  });

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        frameSrc: [
          "'self'",
          "https://www.youtube-nocookie.com",
          "https://www.youtube.com",
          "https://www.instagram.com",
          "https://open.spotify.com",
          "https://www.tiktok.com",
        ],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        // blob: lets the noise-suppression AudioWorklet load from a generated
        // Blob URL (worklet modules are governed by script-src / worker-src).
        scriptSrc: ["'self'", "blob:"],
        workerSrc: ["'self'", "blob:"],
        styleSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }));

  app.use(cors({
    origin: config.appOrigins,
    credentials: true,
  }));

  app.use(globalLimiter);
}

module.exports = {
  applySecurity,
  assetUploadLimiter,
  authLimiter,
  csrfLimiter,
  federationLimiter,
  friendsLimiter,
  heartbeatLimiter,
  messageLimiter,
  messageSendLimiter,
  profilePictureLimiter,
  profileUpdateLimiter,
  badgeUpdateLimiter,
  purgeLimiter,
  serverAvatarLimiter,
  groupIconLimiter,
  serverLimiter,
  serverCreateLimiter,
  serverMessageSendLimiter,
  roleMutationLimiter,
  pinLimiter,
  securityLimiter,
  usernameLimiter,
  verifyLimiter,
  webhookLimiter,
};
