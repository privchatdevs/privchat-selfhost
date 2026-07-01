require("dotenv").config();

const net = require("net");
const express = require("express");
const cookieParser = require("cookie-parser");
const authRoutes = require("./routes/authRoutes");
const serverRoutes = require("./routes/serverRoutes");
const reportRoutes = require("./routes/reportRoutes");
const feedbackRoutes = require("./routes/feedbackRoutes");
const webhookRoutes = require("./routes/webhookRoutes");
const assetRoutes = require("./routes/assetRoutes");
const searchRoutes = require("./routes/searchRoutes");
const federationRoutes = require("./routes/federationRoutes");
const { serveAsset, headAsset, assetMeta } = require("./controllers/assetController");
const { config } = require("./config/env");
const { applySecurity } = require("./middleware/security");
const { errorHandler, notFoundHandler } = require("./middleware/errorHandler");
const { devLogger } = require("./middleware/devLogger");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

// There is deliberately NO admin panel on a self-hosted server: it is a single
// community, and its owner moderates it with the normal in-app tools
// (right-click a member -> kick/ban, roles, permissions) like any other server.
// Platform-operator tooling lives on the home server, not here.

// Per-user HTTP bandwidth accounting (also feeds the WebSocket layer's
// accounting). It only snapshots socket byte counters here and records on
// response finish; user attribution reads the cookie then. Loaded defensively
// so a tracker failure can never take the API down.
let bandwidthTracker = null;
try { bandwidthTracker = require("./services/bandwidthTracker"); } catch (err) {
  console.error("Bandwidth tracker not loaded:", err.message);
}
if (bandwidthTracker) app.use(bandwidthTracker.httpMiddleware);

applySecurity(app);
// AutoMod configs carry the full keyword list (the service caps it at 10k chars),
// which can JSON-encode just past the default 16kb cap. Parse it with a roomier
// limit first. Anything genuinely oversized (e.g. a tampered 1M-char payload) is
// still rejected with 413 before the controller runs, and the service re-clamps
// every field server-side regardless of what the client sent.
app.use("/api/servers/:serverId/automod", express.json({ limit: "64kb" }));
app.use(express.json({ limit: "16kb" }));
app.use(cookieParser(config.cookieSecret));

if (process.env.DEV_MODE === "true") {
  console.log("\x1b[33m[DEV_MODE]\x1b[0m Verbose request/response logging is \x1b[32mON\x1b[0m");
  app.use(devLogger);
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// A self-hosted server hosts ONE thing: its community (channels, members,
// media). DMs, friend lists, and group chats are personal social graph - they
// are processed and stored by each user's HOME server, never by a community
// host, so those APIs are deliberately not mounted here.
app.use("/api/auth", authRoutes);
app.use("/api/servers", serverRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/feedback", feedbackRoutes);
app.use("/api/webhooks", webhookRoutes);
app.use("/api/assets", assetRoutes);
app.use("/api/search", searchRoutes);
app.use("/api/federation", federationRoutes);

// Public, shareable DM attachment links: /asset/<ownerPublicId>/<slug>. Served
// straight off the backend (proxied by nginx) so the link works for anyone, not
// just signed-in users. Hardened in the controller (nosniff + sandbox CSP). The
// HEAD route is registered first so the cheap DB-only probe handles HEAD rather
// than Express falling through to the GET handler (which would hit B2).
app.get("/asset/:owner/:slug/meta", assetMeta);
app.head("/asset/:owner/:slug", headAsset);
app.get("/asset/:owner/:slug", serveAsset);

app.use(notFoundHandler);
app.use(errorHandler);

const { initWebSocketServer } = require("./services/websocketServer");
const sessionRepository = require("./repositories/sessionRepository");

// Purge revoked/expired sessions on boot and every hour so the table doesn't
// accumulate dead rows over time.
function purgeSessions() {
  try {
    const removed = sessionRepository.purgeExpiredSessions();
    if (removed > 0) {
      console.log(`Purged ${removed} expired/revoked session(s).`);
    }
  } catch (err) {
    console.error("Session purge failed:", err);
  }
}
purgeSessions();
setInterval(purgeSessions, 60 * 60 * 1000).unref();

// Reap auto-delete-expired messages in the background (batched, every minute).
const { startAutoDeleteSweeper } = require("./services/autoDeleteSweeper");
startAutoDeleteSweeper();

function findFreePort(startPort) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        resolve(findFreePort(startPort + 1));
      } else {
        reject(err);
      }
    });
    server.listen(startPort, () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

findFreePort(config.port).then((port) => {
  if (port !== config.port) {
    console.warn(`Port ${config.port} is in use - using port ${port} instead.`);
  }
  const server = app.listen(port, () => {
    console.log(`Auth API listening on http://localhost:${port}`);
    // Loud, actionable reminder at boot if server-channel messages are being stored
    // in the clear. DMs and group chats are client-side E2E regardless; this flag
    // only governs at-rest encryption of SERVER channel content.
    try {
      const { encryptionEnabled } = require("./security/serverMessageCipher");
      if (encryptionEnabled()) {
        console.log("\x1b[32m[AT-REST]\x1b[0m Server-channel message encryption is ON.");
      } else if (config.isProduction) {
        console.warn("\x1b[31m[AT-REST]\x1b[0m SERVER_MSG_KEY_BASE64 is NOT set - server channel messages are stored as PLAINTEXT. Generate one (openssl rand -base64 32), set it in the environment, restart, then run scripts/encrypt-server-messages.js to convert existing rows.");
      } else {
        console.warn("\x1b[33m[AT-REST]\x1b[0m SERVER_MSG_KEY_BASE64 not set - server channel messages stored as plaintext (fine for dev; set it in production).");
      }
    } catch { /* cipher module is optional - never block boot over a log line */ }
    // Prove this server actually owns PUBLIC_URL: fetch our own federation key
    // from that address the same way other servers will. Warning-only (see the
    // federation service for why), but it catches an unowned/misrouted domain
    // at setup time instead of after days of confusing federation failures.
    if (config.federation.enabled) {
      try {
        require("./services/federation").startIdentitySelfCheck(config.publicUrl);
      } catch { /* never block boot over a diagnostic */ }
    }
  });
  initWebSocketServer(server);
});
