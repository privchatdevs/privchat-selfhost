const path = require("path");

const required = ["COOKIE_SECRET", "AES_256_KEY_BASE64"];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
}

const aesKey = Buffer.from(process.env.AES_256_KEY_BASE64, "base64");

if (aesKey.length !== 32) {
  throw new Error("AES_256_KEY_BASE64 must decode to exactly 32 bytes.");
}

// At-rest key for server channel messages (ChaCha20-Poly1305). OPTIONAL: when
// unset, server-message encryption is simply off (content stored as today). When
// set it must decode to exactly 32 bytes. Generate with: openssl rand -base64 32
let serverMsgKey = null;
if (process.env.SERVER_MSG_KEY_BASE64) {
  serverMsgKey = Buffer.from(process.env.SERVER_MSG_KEY_BASE64, "base64");
  if (serverMsgKey.length !== 32) {
    throw new Error("SERVER_MSG_KEY_BASE64 must decode to exactly 32 bytes.");
  }
}

// The full public address of this server, e.g. https://chat.yourdomain.net.
// Used for invite links, webhook URLs, and the federation identity suffix.
const publicUrl = (process.env.PUBLIC_URL || "http://localhost:4000").trim().replace(/\/+$/, "");
let publicHost;
try {
  publicHost = new URL(publicUrl).hostname.toLowerCase();
} catch {
  throw new Error(`PUBLIC_URL is not a valid URL: ${publicUrl}`);
}

// Browser origins allowed by CORS. Defaults to the public URL itself; add more
// (comma-separated) if the web app is served from a different origin.
const appOrigins = (process.env.APP_ORIGIN || publicUrl)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean)
  .map((origin) => new URL(origin).origin);

// Where the databases, uploads, and the federation signing key live. Back this
// folder up - it IS the server.
const dataDir = process.env.DATA_DIR || path.join(__dirname, "../../data");

const config = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT || 4000),
  publicUrl,
  publicHost,
  serverDisplayName: (process.env.SERVER_NAME || "PrivChat Server").trim().slice(0, 80),
  appOrigins,
  cookieSecret: process.env.COOKIE_SECRET,
  aesKey,
  serverMsgKey,
  // hCaptcha on login/registration. OPTIONAL for self-hosted servers: leave both
  // blank to run without a captcha (fine for small/private instances).
  hcaptcha: {
    siteKey: process.env.HCAPTCHA_SITE_KEY || "",
    secretKey: process.env.HCAPTCHA_SECRET_KEY || "",
  },
  isProduction: process.env.NODE_ENV === "production",
  dataDir,
  dbPath: process.env.DB_PATH || path.join(dataDir, "auth.db"),
  messagesDbPath: process.env.MESSAGES_DB_PATH || path.join(dataDir, "data.db"),
  adminDbPath: process.env.ADMIN_DB_PATH || path.join(dataDir, "admin.db"),
  smtp: {
    host: process.env.SMTP_HOST || "",
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    user: process.env.SMTP_USER || "",
    pass: process.env.SMTP_PASS || "",
    from: process.env.MAIL_FROM || `PrivChat <no-reply@${publicHost}>`,
  },
  // S3-compatible object storage (Backblaze B2, MinIO, AWS S3, ...) - stores all
  // user media (avatars, banners, server icons, attachments). OPTIONAL: leave
  // blank and media uploads are simply disabled; chat still works. The B2_*
  // names are accepted as aliases for compatibility.
  b2: {
    keyId: process.env.S3_KEY_ID || process.env.B2_KEY_ID || "",
    appKey: process.env.S3_KEY || process.env.B2_APP_KEY || "",
    bucket: process.env.S3_BUCKET || process.env.B2_BUCKET || "",
    endpoint: process.env.S3_ENDPOINT || process.env.B2_ENDPOINT || "",
    region: process.env.S3_REGION || process.env.B2_REGION || "us-east-005",
  },
};

config.b2.enabled = Boolean(config.b2.keyId && config.b2.appKey && config.b2.bucket && config.b2.endpoint);

// Federation (global identity across PrivChat servers). ON by default for a
// self-hosted server - accounts from other servers can join this one. Set
// FEDERATION=off to run a fully private, standalone server. serverName is the
// identity suffix other servers see (user@<serverName>); it defaults to this
// server's public hostname. The Ed25519 signing key comes from
// FEDERATION_SIGNING_KEY_BASE64 (a PKCS8 DER private key, base64) or is
// generated on first boot into the data folder.
config.federation = {
  enabled: (process.env.FEDERATION || "on").trim().toLowerCase() !== "off",
  serverName: (process.env.FEDERATION_SERVER_NAME || publicHost).trim().toLowerCase(),
  signingKeyBase64: process.env.FEDERATION_SIGNING_KEY_BASE64 || "",
  keyPath: process.env.FEDERATION_KEY_PATH || path.join(dataDir, "federation-key.json"),
};

config.cookieNames = {
  csrf: config.isProduction ? "__Host-csrf" : "csrf",
  session: config.isProduction ? "__Host-session" : "session",
};

module.exports = { config };
