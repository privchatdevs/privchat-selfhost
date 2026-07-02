const crypto = require("crypto");
const argon2 = require("argon2");
const { config } = require("../config/env");
const userRepository = require("../repositories/userRepository");
const sessionRepository = require("../repositories/sessionRepository");
const serverRepository = require("../repositories/serverRepository");
const messageRepository = require("../repositories/messageRepository");
const groupService = require("./groupService");
const assetService = require("./assetService");
const { verifyHCaptcha } = require("../security/hcaptcha");
const { getUserBadges, getAllUserBadges } = require("./badges");
const { createSessionToken, hashSessionToken } = require("../security/sessionToken");
// No email on a self-hosted community server: registration is instant (no
// verification codes), and every email-dependent flow (login 2FA, password
// reset, email change) is deliberately disabled below.
const b2Storage = require("./b2Storage");
const { generateInitialProfilePicture } = require("./profilePicture");
const { normalizeOwnStatus } = require("./presence");

const VERIFY_CODE_TTL_MS = 15 * 60 * 1000;
const VERIFY_RESEND_COOLDOWN_MS = 60 * 1000;
// Max wrong guesses against a single emailed 6-digit code before the challenge is
// burned and a fresh code must be requested. This bounds brute force per-challenge
// (a 6-digit code is 1,000,000 values) independently of the per-IP rate limiter,
// which an attacker cycling IPs/proxies could otherwise sidestep. On the last two
// resets a new code is generated, so `attempts` resets there too.
const MAX_CODE_ATTEMPTS = 5;

// ── Profile cosmetics (banner color + profile style) ─────────────────────────
// Solid-color banner choices the user can pick instead of uploading an image.
// A fixed allowlist because the value is rendered straight into CSS on the client.
const BANNER_COLORS = [
  "#5865f2", "#3ba55d", "#faa61a", "#ed4245", "#eb459e",
  "#9b59b6", "#1abc9c", "#e67e22", "#2c2f33", "#23272a",
  "#000000", "#ffffff", "#7289da", "#2ecc71", "#e91e63", "#00b8d4",
];

// The full catalog of named profile styles, shown to everyone in Customization.
// "default" is the standard gray backdrop; the rest recolor the no-banner
// backdrop and are selectable by any signed-in account.
const PROFILE_STYLE_CATALOG = ["default", "black", "white"];

// Whether an account can use a given profile style.
function ownsProfileStyle(_user, style) {
  return PROFILE_STYLE_CATALOG.includes(style);
}

// Which profile styles a given user row is allowed to select (the ones they own).
function eligibleProfileStyles(user) {
  return PROFILE_STYLE_CATALOG.filter((style) => ownsProfileStyle(user, style));
}

// ── App themes (whole-client recolor) ────────────────────────────────────────
// Only the user themselves ever sees their own theme. "custom" is backed by an
// uploaded image + palette.
const APP_THEME_CATALOG = ["default", "black", "custom"];

function themesEnabled(_user) {
  return true;
}

const HEX_COLOR_RE = /^#[0-9a-f]{6}$/i;

// Keys the client may set on a custom theme's palette. Anything else is dropped.
const THEME_PALETTE_KEYS = [
  "appBg", "panel", "surface", "surfaceDark", "input", "active", "hover", "accent", "text",
];

function clampNumber(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

// Coerce an untrusted custom-theme config into a safe, bounded shape. Every palette
// value must be a #rrggbb hex (it's injected into CSS), blur/darken are clamped.
function sanitizeThemeConfig(raw) {
  const input = raw && typeof raw === "object" ? raw : {};
  const palette = {};
  const rawPalette = input.palette && typeof input.palette === "object" ? input.palette : {};
  for (const key of THEME_PALETTE_KEYS) {
    const val = rawPalette[key];
    if (typeof val === "string" && HEX_COLOR_RE.test(val.trim())) {
      palette[key] = val.trim().toLowerCase();
    }
  }
  return {
    blur: Math.round(clampNumber(input.blur, 0, 30, 6)),
    darken: Number(clampNumber(input.darken, 0, 0.9, 0.5).toFixed(2)),
    palette,
    // Whether the wallpaper is an animated GIF (the client renders it un-blurred so
    // it keeps moving). Persisted so it survives reloads / config-only saves.
    gif: Boolean(input.gif),
  };
}

// Registrations are held here (NOT in the users table) until the email code is
// confirmed. Keyed by normalized email. In-memory: a server restart drops any
// in-flight registrations, which simply means the user registers again.
const pendingRegistrations = new Map();

// In-flight 2FA login challenges (password was correct, awaiting emailed code).
// Keyed by an opaque challengeId. In-memory: a restart just means re-login.
const pendingLogins = new Map();

function cleanupExpiredPendingLogins() {
  const now = Date.now();
  for (const [key, pending] of pendingLogins) {
    if (pending.expiresAt <= now) pendingLogins.delete(key);
  }
}

// In-flight email changes: the user asked to move to `newEmail` and we emailed a
// code to their CURRENT address to prove it's really them. Keyed by an opaque
// challengeId. In-memory: a restart just means they start the change over.
const pendingEmailChanges = new Map();

function cleanupExpiredEmailChanges() {
  const now = Date.now();
  for (const [key, pending] of pendingEmailChanges) {
    if (pending.expiresAt <= now) pendingEmailChanges.delete(key);
  }
}

// A new email already claimed by another in-flight change (different account).
function emailChangePendingElsewhere(emailNorm, exceptChallengeId) {
  const now = Date.now();
  for (const [key, pending] of pendingEmailChanges) {
    if (key !== exceptChallengeId && pending.expiresAt > now && pending.newEmailNorm === emailNorm) {
      return true;
    }
  }
  return false;
}

// Pragmatic email shape check (the full RFC is not worth chasing). Mirrors what
// the zod register schema accepts: something@something.tld, no spaces.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function isValidEmail(value) {
  return typeof value === "string" && value.length <= 320 && EMAIL_PATTERN.test(value);
}

// In-flight "forgot password" resets, keyed by an opaque challengeId emailed
// flows hand back to the client. In-memory: a restart just means starting over.
const pendingPasswordResets = new Map();

function cleanupExpiredPasswordResets() {
  const now = Date.now();
  for (const [key, pending] of pendingPasswordResets) {
    if (pending.expiresAt <= now) pendingPasswordResets.delete(key);
  }
}

// "ab***@gmail.com" - enough to recognise your own address without exposing it.
function maskEmail(email) {
  const [local, domain] = String(email).split("@");
  if (!domain) return email;
  const head = local.slice(0, 2);
  return `${head}${"*".repeat(Math.max(1, local.length - 2))}@${domain}`;
}

function generateVerificationCode() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

function cleanupExpiredPending() {
  const now = Date.now();
  for (const [key, pending] of pendingRegistrations) {
    if (pending.expiresAt <= now) pendingRegistrations.delete(key);
  }
}

// node:sqlite throws on a UNIQUE-index violation. The unique index on
// username_normalized (and email_normalized) is the REAL guarantee that two
// accounts can never share a name - this just lets the rare check-then-insert
// race in verifyEmail surface as a clean "taken" message instead of a 500.
function isUniqueViolation(err) {
  const msg = String(err?.message || "");
  return /UNIQUE constraint failed/i.test(msg) || err?.code === "SQLITE_CONSTRAINT_UNIQUE";
}

const LOCK_ATTEMPTS = 5;
const LOCK_MINUTES = 15;
const SESSION_HOURS = 8;
// "Remember me" sessions (the default on sign-in and after email verification)
// keep you logged in for 30 days before a fresh sign-in is required.
const PERSISTENT_SESSION_DAYS = 30;

// Wrong-password sliding-window for EMAIL sign-ins: 5 failed attempts within 60
// seconds triggers a 429. Email sign-ins also count toward the per-account lock.
const WRONG_PASSWORD_WINDOW_SECONDS = 60;
const WRONG_PASSWORD_MAX_ATTEMPTS = 5;

// Username sign-ins never lock the account - a username is public, so locking on
// bad username attempts would let anyone lock a victim out (DoS). They're only
// throttled per-IP instead: 3 attempts per minute per IP, try as often as you like.
const USERNAME_WINDOW_SECONDS = 60;
const USERNAME_MAX_ATTEMPTS_PER_IP = 3;

function publicUser(user) {
  const profilePictureVersion = user.updated_at || user.created_at || Date.now();
  const profileBannerVersion = user.updated_at || user.created_at || Date.now();
  // `badges` is the public (visible) list shown to others. `ownedBadges` is every
  // badge the user has earned and `hiddenBadges` the subset they've chosen to hide -
  // both used only by the owner's own "manage badges" settings (publicUser is built
  // for the signed-in user themselves, never for viewing someone else).
  const ownedBadges = getAllUserBadges(user);
  const visibleBadges = getUserBadges(user);
  const visibleSet = new Set(visibleBadges);
  // Sanitize the stored style against the current catalog.
  const styleOptions = eligibleProfileStyles(user);
  const profileStyle = styleOptions.includes(user.profile_style) ? user.profile_style : "default";
  const canTheme = themesEnabled(user);
  const appTheme = canTheme && APP_THEME_CATALOG.includes(user.app_theme) ? user.app_theme : "default";
  let appThemeConfig = null;
  if (user.app_theme_config) {
    try { appThemeConfig = JSON.parse(user.app_theme_config); } catch { appThemeConfig = null; }
  }
  const appThemeVersion = user.updated_at || user.created_at || Date.now();
  return {
    id: user.public_user_id || user.user_id,
    userNumber: user.user_number,
    badges: visibleBadges,
    ownedBadges,
    hiddenBadges: ownedBadges.filter((id) => !visibleSet.has(id)),
    username: user.username,
    alias: user.profile_alias || "",
    bio: user.bio || "",
    email: user.email,
    profilePictureUrl: `/api/auth/profile-picture?v=${encodeURIComponent(profilePictureVersion)}`,
    profileBannerUrl: user.profile_banner_mime
      ? `/api/auth/profile-banner?v=${encodeURIComponent(profileBannerVersion)}`
      : "",
    profileBannerColor: user.profile_banner_color || "",
    profileStyle,
    profileStyleOptions: styleOptions,
    profileStyleCatalog: PROFILE_STYLE_CATALOG,
    bannerColorOptions: BANNER_COLORS,
    themesEnabled: canTheme,
    appTheme,
    appThemeConfig,
    appThemeImageUrl: user.app_theme_image_mime
      ? `/api/auth/app-theme-image?v=${encodeURIComponent(appThemeVersion)}`
      : "",
    lastLoginAt: user.last_login_at,
    createdAt: user.created_at,
    usernameLastChangedAt: user.username_last_changed_at || null,
    publicKey: user.public_key || null,
    encryptedPrivateKey: user.encrypted_private_key || null,
    keySalt: user.key_salt || null,
  };
}

function authError() {
  const error = new Error("Invalid email or password.");
  error.statusCode = 401;
  return error;
}

function sessionCookieOptions(expiresAt) {
  return {
    httpOnly: true,
    sameSite: "strict",
    // Follows the PUBLIC_URL scheme (see config.cookieSecure) - a Secure cookie
    // over plain http is silently dropped by browsers, which would break login
    // on an http self-host.
    secure: config.cookieSecure,
    path: "/",
    expires: expiresAt,
  };
}

async function createSessionForUser({ user, rememberMe, ipAddress, userAgent }) {
  // Admin "capture IP": if this account was flagged, grab the IP on this sign-on.
  if (ipAddress) {
    try { userRepository.recordIpIfCapturing(user.user_id, ipAddress); } catch { /* never block sign-in */ }
  }

  const token = createSessionToken();
  const tokenHash = hashSessionToken(token);
  const hours = rememberMe ? PERSISTENT_SESSION_DAYS * 24 : SESSION_HOURS;
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);

  await sessionRepository.createSession({
    userId: user.user_id,
    tokenHash,
    expiresAt,
    ipAddress,
    userAgent,
  });

  return {
    token,
    expiresAt,
    user: publicUser(user),
  };
}

async function register({ username, email, password, publicKey, encryptedPrivateKey, keySalt, "h-captcha-response": hCaptchaResponse, ipAddress, userAgent }) {
  await verifyHCaptcha({ token: hCaptchaResponse, ipAddress });
  cleanupExpiredPending();

  const emailNorm = email.toLowerCase();

  // Emails an admin has banned can never register again.
  if (userRepository.isEmailBanned(email)) {
    const error = new Error("This email address is not permitted to register.");
    error.statusCode = 403;
    throw error;
  }

  // Only a real (created) account or a reserved name blocks a username here. A
  // username that's merely PENDING (someone's unverified, in-flight signup - maybe
  // even this same person retrying with a new email) does NOT reserve the name:
  // several people may be mid-signup with it, and whoever confirms their email
  // first creates the account and wins it (first come, first served). The UNIQUE
  // index on username_normalized + the guarded insert in verifyEmail make it
  // impossible for two accounts to share a name no matter the timing.
  if (await userRepository.findByUsername(username)
    || userRepository.isUsernameReserved(username)) {
    const error = new Error("Username is taken.");
    error.statusCode = 409;
    throw error;
  }
  // No email on a self-hosted server, so no enumeration-safe indirection is
  // possible - a taken email simply errors. Fine for a single community.
  if (await userRepository.findByEmail(email)) {
    const error = new Error("That email already has an account on this server.");
    error.statusCode = 409;
    throw error;
  }

  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });

  // Self-hosted servers don't send email: the account is created and signed in
  // IMMEDIATELY - no verification code. (Once the federation join flow ships,
  // most members won't register here at all; local accounts are mainly the
  // owner and invited friends.) The UNIQUE indexes are still the hard guarantee
  // against a name/email race.
  let user;
  try {
    user = await userRepository.createUser({
      username,
      email,
      passwordHash,
      publicKey,
      encryptedPrivateKey,
      keySalt,
    });
  } catch (err) {
    if (isUniqueViolation(err)) {
      const error = new Error("That username or email was just taken. Please register again.");
      error.statusCode = 409;
      throw error;
    }
    throw err;
  }
  userRepository.markEmailVerified(user.user_id);
  await userRepository.writeAuditLog({ userId: user.user_id, email: user.email, success: true, ipAddress, userAgent });
  return createSessionForUser({ user, rememberMe: true, ipAddress, userAgent });
}

// Self-hosted servers create accounts instantly in register() - there is no
// email, so there is nothing to verify. Kept as endpoints for API shape
// compatibility with the main app's client.
function emailNotUsedError() {
  const error = new Error("This server doesn't use email verification - accounts are active as soon as they register.");
  error.statusCode = 400;
  return error;
}

async function verifyEmail() {
  throw emailNotUsedError();
}

async function resendVerification() {
  throw emailNotUsedError();
}

async function login({ email: identifier, password, rememberMe, ipAddress, userAgent }) {
  // Whether they signed in with an email or a username decides which brute-force
  // protection applies. A username is public, so we never lock the account on bad
  // username attempts (that would let anyone DoS-lock a victim) - those are only
  // throttled per-IP. Email (private) keeps the sliding window + per-account lock.
  const isEmailLogin = isValidEmail(identifier);

  // --- Rate limit (before expensive argon2 work) ---
  if (isEmailLogin) {
    // Email: 5 failed attempts in the last 60s by this email OR this IP → 429.
    const recentFailures = userRepository.countFailedLoginsInWindow({
      identifier,
      ipAddress,
      windowSeconds: WRONG_PASSWORD_WINDOW_SECONDS,
    });
    if (recentFailures >= WRONG_PASSWORD_MAX_ATTEMPTS) {
      const error = new Error("Too many sign-in attempts. Please wait a minute and try again.");
      error.statusCode = 429;
      throw error;
    }
  } else {
    // Username: 3 failed attempts per minute per IP (no account lock).
    const recentByIp = userRepository.countFailedLoginsByIpInWindow({
      ipAddress,
      windowSeconds: USERNAME_WINDOW_SECONDS,
    });
    if (recentByIp >= USERNAME_MAX_ATTEMPTS_PER_IP) {
      const error = new Error("Too many sign-in attempts. Please wait a minute and try again.");
      error.statusCode = 429;
      throw error;
    }
  }

  let user = await userRepository.findByEmail(identifier);
  if (!user) {
    user = await userRepository.findByUsername(identifier);
  }

  if (!user) {
    // No live account - but if this email was banned and the password still
    // matches what that account had, say it's disabled (a wrong password gets the
    // generic error, so we don't leak ban status to a guesser).
    const banned = userRepository.getBannedEmail(identifier);
    if (banned?.password_hash) {
      let bannedMatch = false;
      try { bannedMatch = await argon2.verify(banned.password_hash, password); } catch { bannedMatch = false; }
      if (bannedMatch) {
        await userRepository.writeAuditLog({ email: identifier, success: false, ipAddress, userAgent });
        const error = new Error("Your account has been disabled.");
        error.statusCode = 403;
        throw error;
      }
    }
    await userRepository.writeAuditLog({ email: identifier, success: false, ipAddress, userAgent });
    throw authError();
  }

  // --- Per-account DB-level lockout (15-minute lock after 5 bad attempts) ---
  // Only enforced for EMAIL sign-ins; a locked account can still be reached by
  // username (subject to the per-IP throttle above), so the lock can't be abused
  // to deny a victim access to their own account.
  if (isEmailLogin && user.locked_until && new Date(user.locked_until) > new Date()) {
    const error = new Error("Account temporarily locked due to too many failed attempts. Try again later.");
    error.statusCode = 423;
    throw error;
  }

  const isValid = await argon2.verify(user.password_hash, password);

  if (!isValid) {
    // Only email sign-ins count toward (and can trigger) the per-account lock.
    if (isEmailLogin) {
      await userRepository.recordFailedLogin({
        userId: user.user_id,
        lockAttempts: LOCK_ATTEMPTS,
        lockMinutes: LOCK_MINUTES,
      });
    }
    // Always audit the failure - it drives both the per-IP throttle and the log.
    await userRepository.writeAuditLog({ userId: user.user_id, email: user.email, success: false, ipAddress, userAgent });
    throw authError();
  }

  // Password is correct. Email 2FA is not available on a self-hosted server
  // (there is no email channel to deliver the code), so a correct password
  // always signs in directly - even if two_factor_enabled was somehow set.

  await userRepository.recordSuccessfulLogin(user.user_id);

  const session = await createSessionForUser({
    user: { ...user, last_login_at: new Date().toISOString() },
    rememberMe,
    ipAddress,
    userAgent,
  });
  await userRepository.writeAuditLog({ userId: user.user_id, email: user.email, success: true, ipAddress, userAgent });

  return session;
}

// Email 2FA doesn't exist on a self-hosted server - login() never withholds a
// session, so there is never a challenge to finish.
function twoFactorNotAvailableError() {
  const error = new Error("Email 2FA isn't available on a self-hosted server - sign in with your password.");
  error.statusCode = 400;
  return error;
}

async function verifyLogin() {
  throw twoFactorNotAvailableError();
}

async function resendLoginCode() {
  throw twoFactorNotAvailableError();
}

// Auto-delete durations the client may pick (seconds): 1h, 8h, 24h, 7d, 1 month.
const AUTO_DELETE_SECONDS = new Set([3600, 28800, 86400, 604800, 2592000]);

// Allowed "delete my account after N months inactive" values (0 = never).
const INACTIVE_DELETE_MONTHS = new Set([0, 1, 3, 6, 12]);

const PRIVACY_LEVELS = new Set(["anyone", "mutual_servers", "friends_of_friends"]);

function getSecuritySettings(account) {
  return {
    twoFactorEnabled: Boolean(account.two_factor_enabled),
    autodeleteSeconds: account.autodelete_seconds || 86400,
    autodeleteDms: Boolean(account.autodelete_dms),
    autodeleteDmsBoth: Boolean(account.autodelete_dms_both),
    autodeleteServers: Boolean(account.server_autodelete),
    // Default 6 months when the column is somehow null (it's NOT NULL DEFAULT 6).
    inactiveDeleteMonths: account.inactive_delete_months ?? 6,
    dmPrivacy: account.dm_privacy ?? "mutual_servers",
    friendRequestPrivacy: account.friend_request_privacy ?? "anyone",
  };
}

function updateSecuritySettings({ userId, twoFactorEnabled, autodeleteSeconds, autodeleteDms, autodeleteDmsBoth, autodeleteServers, inactiveDeleteMonths, dmPrivacy, friendRequestPrivacy }) {
  // Email 2FA can't work without email - refuse to enable it rather than
  // letting someone flip a switch that would lock them out at next login.
  if (twoFactorEnabled) {
    const error = new Error("Email 2FA isn't available on a self-hosted server - it has no email.");
    error.statusCode = 400;
    throw error;
  }
  const patch = { userId, twoFactorEnabled: false, serverAutodelete: autodeleteServers, autodeleteDms, autodeleteDmsBoth };
  // Only accept a whitelisted inactivity window (0 = never).
  if (typeof inactiveDeleteMonths === "number" && INACTIVE_DELETE_MONTHS.has(inactiveDeleteMonths)) {
    patch.inactiveDeleteMonths = inactiveDeleteMonths;
  }
  // Only accept a whitelisted duration.
  if (typeof autodeleteSeconds === "number" && AUTO_DELETE_SECONDS.has(autodeleteSeconds)) {
    patch.autodeleteSeconds = autodeleteSeconds;
  }
  userRepository.updateSecuritySettings(patch);

  // Privacy is a combinable set, stored as a comma-separated list of whitelisted
  // levels (e.g. "mutual_servers,friends_of_friends"). An empty string means
  // nobody new (friends and existing chats are always allowed regardless).
  const privacyPatch = { userId };
  if (typeof dmPrivacy === "string") privacyPatch.dmPrivacy = sanitizePrivacyCsv(dmPrivacy);
  if (typeof friendRequestPrivacy === "string") privacyPatch.friendRequestPrivacy = sanitizePrivacyCsv(friendRequestPrivacy);
  if (typeof privacyPatch.dmPrivacy === "string" || typeof privacyPatch.friendRequestPrivacy === "string") {
    userRepository.updatePrivacySettings(privacyPatch);
  }
}

function sanitizePrivacyCsv(value) {
  return [...new Set(
    String(value).split(",").map((token) => token.trim()).filter((token) => PRIVACY_LEVELS.has(token))
  )].join(",");
}

async function logout(token) {
  if (!token) {
    return;
  }

  await sessionRepository.revokeSession(hashSessionToken(token));
}

async function getSessionUser(token) {
  if (!token) {
    return null;
  }

  const user = await sessionRepository.findUserBySession(hashSessionToken(token));
  return user ? publicUser(user) : null;
}

async function getSessionAccount(token) {
  if (!token) {
    return null;
  }

  return sessionRepository.findUserBySession(hashSessionToken(token));
}

async function getProfilePicture(userId) {
  const ref = userRepository.getProfilePictureRef(userId);
  if (ref?.profile_picture_key) {
    try {
      const media = await b2Storage.getMedia(ref.profile_picture_key);
      return { data: media.body, mimeType: media.contentType || ref.profile_picture_mime || "application/octet-stream" };
    } catch {
      // Object missing/unreachable - fall back to the generated default below.
    }
  }
  return generateInitialProfilePicture(ref?.username);
}

async function getProfileBanner(userId) {
  const ref = userRepository.getProfileBannerRef(userId);
  if (!ref?.profile_banner_key) return null;
  try {
    const media = await b2Storage.getMedia(ref.profile_banner_key);
    return { profile_banner: media.body, profile_banner_mime: media.contentType || ref.profile_banner_mime };
  } catch {
    return null;
  }
}

async function getUserByAnyId(id) {
  return userRepository.findByAnyId(id);
}

async function updateProfilePicture({ userId, publicUserId, data, mimeType }) {
  const key = await b2Storage.uploadMedia({ ownerId: publicUserId, buffer: data, contentType: mimeType });
  userRepository.updateProfilePicture({ userId, key, mimeType });
}

async function updateProfileBanner({ userId, publicUserId, data, mimeType }) {
  const key = await b2Storage.uploadMedia({ ownerId: publicUserId, buffer: data, contentType: mimeType });
  userRepository.updateProfileBanner({ userId, key, mimeType });
}

async function updateProfile({ userId, alias, bio }) {
  userRepository.updateProfile({ userId, alias, bio });
}

// Pick (or clear, with an empty value) a solid-color banner. The color must be one
// of the fixed allowlist; choosing one clears any uploaded image banner. Returns
// the refreshed self-user so the client can re-render immediately.
async function updateBannerColor({ userId, color }) {
  const normalized = color ? String(color).trim().toLowerCase() : "";
  if (normalized && !BANNER_COLORS.includes(normalized)) {
    const error = new Error("That banner color isn't available.");
    error.statusCode = 400;
    throw error;
  }
  userRepository.updateProfileBannerColor({ userId, color: normalized || null });
  return publicUser(userRepository.findById(userId));
}

// Switch the profile style. Gated styles (e.g. "black") are only accepted for the
// accounts they're assigned to; everyone else is limited to "default".
async function updateProfileStyle({ userId, style }) {
  const user = userRepository.findById(userId);
  if (!user) {
    const error = new Error("Account not found.");
    error.statusCode = 404;
    throw error;
  }
  const requested = String(style || "default").trim().toLowerCase();
  if (!eligibleProfileStyles(user).includes(requested)) {
    const error = new Error("That profile style isn't available on your account.");
    error.statusCode = 403;
    throw error;
  }
  userRepository.updateProfileStyle({ userId, style: requested });
  return publicUser(userRepository.findById(userId));
}

// Fetch the bytes of a user's custom-theme image from B2 (only the owner ever
// requests their own). Null when none is set or the object is unreachable.
async function getAppThemeImage(userId) {
  const ref = userRepository.getAppThemeRef(userId);
  if (!ref?.app_theme_image_key) return null;
  try {
    const media = await b2Storage.getMedia(ref.app_theme_image_key);
    return { data: media.body, mimeType: media.contentType || ref.app_theme_image_mime };
  } catch {
    return null;
  }
}

// Upload a new custom-theme image. Mirrors the profile-banner flow.
async function updateAppThemeImage({ userId, publicUserId, data, mimeType }) {
  const user = userRepository.findById(userId);
  if (!user) {
    const error = new Error("Account not found.");
    error.statusCode = 404;
    throw error;
  }
  const key = await b2Storage.uploadMedia({ ownerId: publicUserId, buffer: data, contentType: mimeType });
  userRepository.updateAppThemeImage({ userId, key, mimeType });
  return publicUser(userRepository.findById(userId));
}

// Switch the app theme + save its config. The theme name must be in the catalog
// and the config is sanitized (bounded blur/darken, hex-only palette).
async function updateAppTheme({ userId, theme, config }) {
  const user = userRepository.findById(userId);
  if (!user) {
    const error = new Error("Account not found.");
    error.statusCode = 404;
    throw error;
  }
  const requested = String(theme || "default").trim().toLowerCase();
  if (!APP_THEME_CATALOG.includes(requested)) {
    const error = new Error("That theme isn't available.");
    error.statusCode = 400;
    throw error;
  }
  // Only the custom theme carries a config; the others store none.
  const configJson = requested === "custom" ? JSON.stringify(sanitizeThemeConfig(config)) : null;
  userRepository.updateAppTheme({ userId, theme: requested, config: configJson });
  return publicUser(userRepository.findById(userId));
}

// Set which of the user's earned badges are hidden. Only badges the user actually
// has are stored (unknown/unearned ids are ignored), then the refreshed self-user
// is returned so the client can re-render its profile immediately.
async function updateVisibleBadges({ userId, hidden }) {
  const user = userRepository.findById(userId);
  if (!user) {
    const error = new Error("Account not found.");
    error.statusCode = 404;
    throw error;
  }
  const owned = new Set(getAllUserBadges(user));
  const sanitized = Array.isArray(hidden)
    ? [...new Set(hidden.map((id) => String(id).trim()).filter((id) => owned.has(id)))]
    : [];
  userRepository.setHiddenBadges(userId, sanitized);
  return publicUser(userRepository.findById(userId));
}

async function updateUsername({ userId, newUsername, password }) {
  const user = await userRepository.findById(userId);
  if (!user) {
    const error = new Error("User not found.");
    error.statusCode = 404;
    throw error;
  }

  // 1. Verify password confirmation
  const isValid = await argon2.verify(user.password_hash, password);
  if (!isValid) {
    const error = new Error("Invalid password confirmation.");
    error.statusCode = 401;
    throw error;
  }

  // 2. Check if username is the same
  if (user.username.toLowerCase() === newUsername.toLowerCase()) {
    const error = new Error("New username must be different from current username.");
    error.statusCode = 400;
    throw error;
  }

  // 3. Check 7-day cooldown (7 * 24 * 60 * 60 * 1000 = 604800000 ms)
  if (user.username_last_changed_at) {
    const lastChanged = new Date(user.username_last_changed_at);
    const diffMs = Date.now() - lastChanged.getTime();
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
    if (diffMs < sevenDaysMs) {
      const remainingMs = sevenDaysMs - diffMs;
      const remainingDays = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));
      const error = new Error(`You can only change your username once every 7 days. Try again in ${remainingDays} day(s).`);
      error.statusCode = 400;
      throw error;
    }
  }

  // 4. Check if new username is already taken (or held by a recent ban/deletion)
  const usernameTaken = (await userRepository.findByUsername(newUsername))
    || userRepository.isUsernameReserved(newUsername);
  if (usernameTaken) {
    const error = new Error("Username is taken.");
    error.statusCode = 409;
    throw error;
  }

  // 5. Update username
  await userRepository.updateUsername({
    userId,
    username: newUsername,
  });
}

// Matches the registration rule ("at least 8 characters").
const MIN_PASSWORD_LENGTH = 8;
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

// Change the account password after re-verifying the CURRENT password. The
// client re-encrypts the E2E private key under the new password and passes the
// new blob + salt so login on other devices can still recover the key; if it
// couldn't (no local key), those are omitted and only the hash changes.
async function changePassword({ userId, currentPassword, newPassword, encryptedPrivateKey = null, keySalt = null, currentToken = null }) {
  const user = await userRepository.findById(userId);
  if (!user) {
    const error = new Error("Account not found.");
    error.statusCode = 404;
    throw error;
  }

  const currentValid = await argon2.verify(user.password_hash, currentPassword || "");
  if (!currentValid) {
    const error = new Error("Your current password is incorrect.");
    error.statusCode = 401;
    throw error;
  }

  if (typeof newPassword !== "string" || newPassword.length < MIN_PASSWORD_LENGTH) {
    const error = new Error("New password needs to be at least 8 characters.");
    error.statusCode = 400;
    throw error;
  }

  // Re-using the same password isn't a change - reject it so the user knows.
  if (await argon2.verify(user.password_hash, newPassword)) {
    const error = new Error("New password must be different from your current one.");
    error.statusCode = 400;
    throw error;
  }

  const passwordHash = await argon2.hash(newPassword, ARGON2_OPTIONS);
  userRepository.updatePassword({ userId, passwordHash, encryptedPrivateKey, keySalt });

  // Sign out every OTHER session (other devices, or a stolen session) while
  // keeping the device that made the change logged in.
  if (currentToken) {
    sessionRepository.revokeOtherSessions(userId, hashSessionToken(currentToken));
  }
}

// A self-hosted server has no email channel, so every emailed-code flow below
// is disabled with an honest message. Password changes still work while signed
// in (change-password re-verifies the current password) - what does NOT exist
// is recovery for a FORGOTTEN password: hosts should keep their password in a
// password manager.
function noEmailFlowError(what) {
  const error = new Error(`${what} isn't available on a self-hosted server - it has no email. If you forgot your password, ask the server owner (or re-register).`);
  error.statusCode = 400;
  return error;
}

async function forgotPassword() {
  throw noEmailFlowError("Password reset by email");
}

async function resetPassword() {
  throw noEmailFlowError("Password reset by email");
}

async function resendPasswordResetCode() {
  throw noEmailFlowError("Password reset by email");
}

async function startEmailChange() {
  throw noEmailFlowError("Changing your email");
}

async function verifyEmailChange() {
  throw noEmailFlowError("Changing your email");
}

async function resendEmailChangeCode() {
  throw noEmailFlowError("Changing your email");
}

async function recordHeartbeat(userId, ip, status = null) {
  userRepository.updateLastSeen(userId, status ? normalizeOwnStatus(status) : null);
  // If an admin has armed "capture IP" on this user, their heartbeat (every ~20s
  // while online) records the IP immediately - no need to wait for a fresh login.
  // This is a no-op for everyone who isn't armed, so only the one enabled user is
  // ever recorded.
  if (ip) {
    try { userRepository.recordIpIfCapturing(userId, ip); } catch { /* never block heartbeat */ }
  }
}

async function updateKeys({ userId, publicKey, encryptedPrivateKey, keySalt }) {
  await userRepository.updateKeys({ userId, publicKey, encryptedPrivateKey, keySalt });
}

// Permanently and irreversibly delete an account after re-verifying the
// password. Wipes the user everywhere: every DM (including the copies sitting in
// other people's conversations), all reactions, the social graph, server
// membership + authored server messages, any servers they own (full cascade),
// and their avatar/banner/owned-server-icon objects in B2.
// The actual purge - shared by the user-facing (password-checked) delete and the
// admin-initiated ban. Wipes the account, owned servers, all data, and B2 media.
async function purgeAccount(userId) {
  // Collect every B2 object key to remove once the DB rows are gone.
  const mediaKeys = [];
  const pictureRef = userRepository.getProfilePictureRef(userId);
  if (pictureRef?.profile_picture_key) mediaKeys.push(pictureRef.profile_picture_key);
  const bannerRef = userRepository.getProfileBannerRef(userId);
  if (bannerRef?.profile_banner_key) mediaKeys.push(bannerRef.profile_banner_key);
  const themeRef = userRepository.getAppThemeRef(userId);
  if (themeRef?.app_theme_image_key) mediaKeys.push(themeRef.app_theme_image_key);

  // Owned servers are wiped entirely (batched internally so huge servers don't
  // freeze the process).
  for (const server of serverRepository.listOwnedServers(userId)) {
    await serverRepository.deleteServerCascade(server.server_id);
    if (server.icon_key) mediaKeys.push(server.icon_key);
    if (server.banner_key) mediaKeys.push(server.banner_key);
  }

  // Leave every group chat: delete the user's authored group messages (the rest of
  // each group's history stays), transferring ownership or fully purging a group
  // that empties out. Then hard-delete every file the user ever uploaded (DM and
  // group attachments alike) so nothing of theirs lingers in B2.
  await groupService.purgeUserFromAllGroups(userId);
  const publicId = (await userRepository.findById(userId))?.public_user_id || userId;
  await assetService.purgeOwnerAssets(publicId);

  // Everything else of the user's across the shared data.db (also batched), then
  // the account row + sessions + audit trail in the auth DB.
  await serverRepository.deleteAllUserData(userId);
  userRepository.deleteUserAccount(userId);

  // Best-effort media cleanup (never throws - orphan objects are non-critical).
  await Promise.all(mediaKeys.map((key) => b2Storage.deleteMedia(key)));
}

async function deleteAccount({ userId, password }) {
  const user = await userRepository.findById(userId);
  if (!user) {
    const error = new Error("Account not found.");
    error.statusCode = 404;
    throw error;
  }

  const isValid = await argon2.verify(user.password_hash, password);
  if (!isValid) {
    const error = new Error("Incorrect password.");
    error.statusCode = 401;
    throw error;
  }

  await purgeAccount(userId);
}

// Admin ban: same full purge, no password (the admin panel is IP-whitelisted and
// session-gated). The caller emails the user first, before this erases them.
async function deleteAccountAsAdmin(userId) {
  const user = await userRepository.findById(userId);
  if (!user) {
    const error = new Error("Account not found.");
    error.statusCode = 404;
    throw error;
  }
  // Block this email from ever registering again (keeping the password hash so a
  // sign-in with the same credentials gets a "disabled" message), then erase it.
  userRepository.banEmail(user.email, user.password_hash);
  await purgeAccount(userId);
}

// Telegram-style inactive-account self-destruct. Fully purges accounts that have
// passed their own configured inactivity window (inactive_delete_months). Same
// erase as a user-initiated delete, but the email is NOT banned - a returning user
// can just sign up again. Silent by design (no per-account logging or notice).
// Capped per run; a backlog clears over subsequent sweeps. Returns the count.
async function sweepInactiveAccounts(limit = 50) {
  const ids = userRepository.getAccountsInactiveBeyondThreshold(limit);
  for (const userId of ids) {
    try { await purgeAccount(userId); } catch { /* best-effort; retried next sweep */ }
  }
  return ids.length;
}

module.exports = {
  deleteAccount,
  deleteAccountAsAdmin,
  sweepInactiveAccounts,
  getProfilePicture,
  getProfileBanner,
  getAppThemeImage,
  getUserByAnyId,
  getSessionAccount,
  getSessionUser,
  login,
  verifyLogin,
  resendLoginCode,
  changePassword,
  forgotPassword,
  resetPassword,
  resendPasswordResetCode,
  startEmailChange,
  verifyEmailChange,
  resendEmailChangeCode,
  getSecuritySettings,
  updateSecuritySettings,
  logout,
  recordHeartbeat,
  register,
  resendVerification,
  verifyEmail,
  sessionCookieOptions,
  updateProfile,
  updateProfileBanner,
  updateBannerColor,
  updateProfileStyle,
  updateAppTheme,
  updateAppThemeImage,
  updateProfilePicture,
  updateUsername,
  updateVisibleBadges,
  updateKeys,
};
