const { createCsrfToken } = require("../middleware/csrf");
const { config } = require("../config/env");
const { loginSchema, profileSchema, registerSchema, usernameUpdateSchema } = require("../security/validation");
const authService = require("../services/authService");
const messageRepository = require("../repositories/messageRepository");
const serverRepository = require("../repositories/serverRepository");
const userRepository = require("../repositories/userRepository");
const { broadcastToUser, getEnrichedConversations } = require("../services/websocketServer");
const { toUtcIso } = require("../utils/time");
const { getUserBadges } = require("../services/badges");
const { isPublicOnline, publicPresenceStatus } = require("../services/presence");

const MAX_PROFILE_PICTURE_BYTES = 5 * 1024 * 1024;
const MAX_PROFILE_BANNER_BYTES = 5 * 1024 * 1024;
// Animated GIF profile pictures / banners get a larger budget than static images.
const MAX_PROFILE_MEDIA_GIF_BYTES = 10 * 1024 * 1024;
const MAX_APP_THEME_IMAGE_BYTES = 8 * 1024 * 1024;
const PROFILE_PICTURE_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
const PROFILE_BANNER_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
const APP_THEME_IMAGE_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || "";
}

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}

async function getCurrentUser(req) {
  return authService.getSessionUser(getSessionToken(req));
}

async function getCurrentAccount(req) {
  return authService.getSessionAccount(getSessionToken(req));
}

function isPng(buffer) {
  return buffer.length >= 8
    && buffer[0] === 0x89
    && buffer[1] === 0x50
    && buffer[2] === 0x4e
    && buffer[3] === 0x47
    && buffer[4] === 0x0d
    && buffer[5] === 0x0a
    && buffer[6] === 0x1a
    && buffer[7] === 0x0a;
}

function isJpeg(buffer) {
  return buffer.length >= 3
    && buffer[0] === 0xff
    && buffer[1] === 0xd8
    && buffer[2] === 0xff;
}

function isWebp(buffer) {
  return buffer.length >= 12
    && buffer[0] === 0x52 // R
    && buffer[1] === 0x49 // I
    && buffer[2] === 0x46 // F
    && buffer[3] === 0x46 // F
    && buffer[8] === 0x57 // W
    && buffer[9] === 0x45 // E
    && buffer[10] === 0x42 // B
    && buffer[11] === 0x50; // P
}

function isGif(buffer) {
  return buffer.length >= 6
    && buffer[0] === 0x47 // G
    && buffer[1] === 0x49 // I
    && buffer[2] === 0x46 // F
    && buffer[3] === 0x38 // 8
    && (buffer[4] === 0x37 || buffer[4] === 0x39)
    && buffer[5] === 0x61; // a
}

function detectMimeType(buffer, { allowGif = false } = {}) {
  if (isPng(buffer)) return "image/png";
  if (isJpeg(buffer)) return "image/jpeg";
  if (isWebp(buffer)) return "image/webp";
  if (allowGif && isGif(buffer)) return "image/gif";
  return null;
}

function validateProfilePicture(buffer, mimeType) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    const error = new Error("Choose a profile picture to upload.");
    error.statusCode = 400;
    throw error;
  }

  const detectedMimeType = detectMimeType(buffer, { allowGif: true });
  console.info("[MEDIA_UPLOAD_DEBUG] profile-picture validation", {
    declaredMimeType: mimeType,
    detectedMimeType,
    bytes: buffer.length,
  });
  if (!detectedMimeType || !PROFILE_PICTURE_TYPES.has(detectedMimeType)) {
    const error = new Error("Profile picture must be a valid PNG, JPG, WebP, or GIF file.");
    error.statusCode = 400;
    throw error;
  }

  // Animated GIFs get the larger budget; static images keep the 5 MB cap.
  const limit = detectedMimeType === "image/gif" ? MAX_PROFILE_MEDIA_GIF_BYTES : MAX_PROFILE_PICTURE_BYTES;
  if (buffer.length > limit) {
    const error = new Error(`Profile picture cannot be over ${detectedMimeType === "image/gif" ? 10 : 5} MB.`);
    error.statusCode = 413;
    throw error;
  }

  return detectedMimeType;
}

function validateProfileBanner(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    const error = new Error("Choose a profile banner to upload.");
    error.statusCode = 400;
    throw error;
  }

  const detectedMimeType = detectMimeType(buffer, { allowGif: true });
  console.info("[MEDIA_UPLOAD_DEBUG] profile-banner validation", {
    detectedMimeType,
    bytes: buffer.length,
  });
  if (!detectedMimeType || !PROFILE_BANNER_TYPES.has(detectedMimeType)) {
    const error = new Error("Profile banner must be a valid PNG, JPG, WebP, or GIF file.");
    error.statusCode = 400;
    throw error;
  }

  const limit = detectedMimeType === "image/gif" ? MAX_PROFILE_MEDIA_GIF_BYTES : MAX_PROFILE_BANNER_BYTES;
  if (buffer.length > limit) {
    const error = new Error(`Profile banner cannot be over ${detectedMimeType === "image/gif" ? 10 : 5} MB.`);
    error.statusCode = 413;
    throw error;
  }

  return detectedMimeType;
}

function validateAppThemeImage(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    const error = new Error("Choose an image for your theme.");
    error.statusCode = 400;
    throw error;
  }

  if (buffer.length > MAX_APP_THEME_IMAGE_BYTES) {
    const error = new Error("Theme image cannot be over 8 MB.");
    error.statusCode = 413;
    throw error;
  }

  const detectedMimeType = detectMimeType(buffer, { allowGif: true });
  if (!detectedMimeType || !APP_THEME_IMAGE_TYPES.has(detectedMimeType)) {
    const error = new Error("Theme image must be a valid PNG, JPG, WebP, or GIF file.");
    error.statusCode = 400;
    throw error;
  }

  return detectedMimeType;
}

function getCsrf(req, res) {
  const csrfToken = createCsrfToken(req, res);
  res.json({ csrfToken });
}

async function login(req, res, next) {
  try {
    const payload = loginSchema.parse(req.body);
    const result = await authService.login({
      ...payload,
      ipAddress: getClientIp(req),
      userAgent: req.get("User-Agent") || "",
    });

    // 2FA on login: password was right, but a session is withheld until the
    // emailed code is confirmed via /verify-login.
    if (result.twoFactorRequired) {
      return res.json({
        twoFactorRequired: true,
        challengeId: result.challengeId,
        email: result.email,
      });
    }

    res.cookie(config.cookieNames.session, result.token, authService.sessionCookieOptions(result.expiresAt));
    res.json({ user: result.user });
  } catch (error) {
    if (error.verificationRequired) {
      return res.status(403).json({ message: error.message, verificationRequired: true, email: error.email });
    }
    return next(error);
  }
}

async function verifyLogin(req, res, next) {
  try {
    const challengeId = typeof req.body?.challengeId === "string" ? req.body.challengeId : "";
    const code = typeof req.body?.code === "string" ? req.body.code.trim() : "";
    if (!challengeId || !code) {
      return res.status(400).json({ message: "A verification code is required." });
    }
    const session = await authService.verifyLogin({
      challengeId,
      code,
      ipAddress: getClientIp(req),
      userAgent: req.get("User-Agent") || "",
    });
    res.cookie(config.cookieNames.session, session.token, authService.sessionCookieOptions(session.expiresAt));
    return res.json({ user: session.user });
  } catch (error) {
    return next(error);
  }
}

async function resendLoginCode(req, res, next) {
  try {
    const challengeId = typeof req.body?.challengeId === "string" ? req.body.challengeId : "";
    if (!challengeId) {
      return res.status(400).json({ message: "Missing sign-in challenge." });
    }
    await authService.resendLoginCode({ challengeId });
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
}

async function getSecuritySettings(req, res, next) {
  try {
    const account = await getCurrentAccount(req);
    if (!account) return res.status(401).json({ message: "Not signed in." });
    return res.json({ settings: authService.getSecuritySettings(account) });
  } catch (error) {
    return next(error);
  }
}

// Post (or replace) an auto-delete system notice in ONE conversation: drops this
// user's prior notice there, saves the new one (never expires), broadcasts both
// the removal and the new notice to each side. `fields` is the notice payload
// (action + optional scope/seconds).
async function postAutoDeleteNoticeTo(account, receiverId, fields) {
  const receiver = userRepository.findById(receiverId);
  if (!receiver) return;
  messageRepository.deleteAutoDeleteNotices(account.user_id, receiverId).forEach((id) => {
    broadcastToUser(account.user_id, { type: "message_delete", messageId: id });
    broadcastToUser(receiverId, { type: "message_delete", messageId: id });
  });
  const actor = account.profile_alias || account.username || "Someone";
  const row = await messageRepository.saveMessage({
    senderId: account.user_id,
    receiverId,
    content: JSON.stringify({ system: true, kind: "autodelete", actor, ...fields }),
    ttlSeconds: 0,
  });
  const payload = {
    type: "message",
    messageId: row.message_id,
    senderId: account.public_user_id || account.user_id,
    receiverId: receiver.public_user_id || receiverId,
    content: row.content,
    createdAt: toUtcIso(row.created_at),
    editedAt: null,
    replyToMessageId: null,
    expiresAt: null,
    reactions: [],
  };
  broadcastToUser(account.user_id, payload);
  broadcastToUser(receiverId, payload);
}

// Re-post the notice to every conversation where auto-delete was announced during
// the active period (since `sinceIso`) - used to announce a turn-OFF, or to
// refresh the notice when the scope/duration changed while it stays on.
async function reannounceAutoDeleteNotices(account, sinceIso, fields) {
  const receivers = messageRepository.listAutoDeleteNoticeReceivers(account.user_id, sinceIso);
  for (const receiverId of receivers) {
    await postAutoDeleteNoticeTo(account, receiverId, fields);
  }
}

// Effective auto-delete TTL (seconds, 0 = none) for messages from sender→recipient,
// from both users' current settings (sender's own + recipient's "also delete theirs").
function dmTtlBetween(senderId, recipientId) {
  const sender = userRepository.getAutoDeleteSettings(senderId);
  const recipient = userRepository.getAutoDeleteSettings(recipientId);
  const candidates = [];
  // Respect each side's per-DM "cancel auto-delete" opt-out (see dmTtlSeconds in
  // messageController), so reconcile clears expiry on threads a user has exempted.
  if (sender.dms && !messageRepository.getConversationAutoDeleteExempt(senderId, recipientId)) {
    candidates.push(sender.seconds);
  }
  if (recipient.dms && recipient.dmsBoth && !messageRepository.getConversationAutoDeleteExempt(recipientId, senderId)) {
    candidates.push(recipient.seconds);
  }
  return candidates.length ? Math.min(...candidates) : 0;
}

// After a user's DM auto-delete coverage shrinks, clear the pending expiry on any
// messages that should no longer auto-delete (e.g. they turned it off, so a
// message that was going to vanish in 7h is kept). Checks both directions per
// conversation using current settings, so the other person's still-active
// auto-delete is respected.
async function reconcileDmExpiries(userId) {
  const partners = messageRepository.getConversationPartnerIds(userId);
  for (const partnerId of partners) {
    if (dmTtlBetween(userId, partnerId) === 0) await messageRepository.clearPendingExpiry(userId, partnerId);
    if (dmTtlBetween(partnerId, userId) === 0) await messageRepository.clearPendingExpiry(partnerId, userId);
  }
}

async function updateSecuritySettings(req, res, next) {
  try {
    const account = await getCurrentAccount(req);
    if (!account) return res.status(401).json({ message: "Not signed in." });

    const body = req.body || {};
    const patch = { userId: account.user_id };
    if (typeof body.twoFactorEnabled === "boolean") patch.twoFactorEnabled = body.twoFactorEnabled;
    if (typeof body.autodeleteServers === "boolean") patch.autodeleteServers = body.autodeleteServers;
    if (typeof body.autodeleteDms === "boolean") patch.autodeleteDms = body.autodeleteDms;
    if (typeof body.autodeleteDmsBoth === "boolean") patch.autodeleteDmsBoth = body.autodeleteDmsBoth;
    if (typeof body.autodeleteSeconds === "number") patch.autodeleteSeconds = body.autodeleteSeconds;
    if (typeof body.inactiveDeleteMonths === "number") patch.inactiveDeleteMonths = body.inactiveDeleteMonths;
    if (typeof body.dmPrivacy === "string") patch.dmPrivacy = body.dmPrivacy;
    if (typeof body.friendRequestPrivacy === "string") patch.friendRequestPrivacy = body.friendRequestPrivacy;

    // Capture DM auto-delete state before the change to detect a turn-OFF.
    const beforeAd = userRepository.getAutoDeleteSettings(account.user_id);
    authService.updateSecuritySettings(patch);

    // Keep the in-chat notices in sync (fire-and-forget). Turning auto-delete OFF
    // no longer blasts a "disabled" notice to every past DM - it's posted lazily
    // when you next OPEN that conversation (getMessages), so stale DMs you haven't
    // touched in weeks aren't spammed.
    const dmsTurnedOff = beforeAd.dms && body.autodeleteDms === false;
    if (!dmsTurnedOff && beforeAd.dms && body.autodeleteDms !== false) {
      // Still on - if scope or duration changed, refresh the notice to match.
      const ad = userRepository.getAutoDeleteSettings(account.user_id);
      if (ad.dmsBoth !== beforeAd.dmsBoth || ad.seconds !== beforeAd.seconds) {
        reannounceAutoDeleteNotices(account, ad.dmsSince, {
          action: "enabled",
          seconds: ad.seconds,
          scope: ad.dmsBoth ? "both" : "mine",
        }).catch((err) => console.error("auto-delete re-announce failed:", err));
      }
    }

    // If DM auto-delete coverage shrank (turned off DMs or "also delete theirs"),
    // cancel pending deletions that no longer apply. Fire-and-forget + batched.
    const dmsReduced = beforeAd.dms && body.autodeleteDms === false;
    const bothReduced = beforeAd.dmsBoth && body.autodeleteDmsBoth === false;
    if (dmsReduced || bothReduced) {
      reconcileDmExpiries(account.user_id)
        .catch((err) => console.error("auto-delete expiry reconcile failed:", err));
    }

    const updated = await getCurrentAccount(req);
    return res.json({ settings: authService.getSecuritySettings(updated) });
  } catch (error) {
    return next(error);
  }
}

// Change the account password (requires the current password). The client may
// include a private-key blob re-encrypted under the new password so E2E key
// recovery keeps working on other devices.
async function changePassword(req, res, next) {
  try {
    const account = await getCurrentAccount(req);
    if (!account) return res.status(401).json({ message: "Not signed in." });

    const body = req.body || {};
    const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
    if (!currentPassword) {
      return res.status(400).json({ message: "Enter your current password." });
    }

    await authService.changePassword({
      userId: account.user_id,
      currentPassword,
      newPassword: typeof body.newPassword === "string" ? body.newPassword : "",
      encryptedPrivateKey: typeof body.encryptedPrivateKey === "string" ? body.encryptedPrivateKey : null,
      keySalt: typeof body.keySalt === "string" ? body.keySalt : null,
      currentToken: getSessionToken(req),
    });
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
}

// Forgot-password (public, from the login screen). Always responds the same way
// so it can't be used to discover which emails have accounts.
async function forgotPassword(req, res, next) {
  try {
    const result = await authService.forgotPassword({ email: req.body?.email });
    return res.json(result);
  } catch (error) {
    return next(error);
  }
}

// Finish a forgot-password reset with the emailed code + a new password.
async function resetPassword(req, res, next) {
  try {
    const { affectedPartnerIds = [] } = await authService.resetPassword({
      challengeId: req.body?.challengeId,
      code: req.body?.code,
      newPassword: req.body?.newPassword,
    });

    // The reset wiped this user's DMs (shared rows), so refresh each partner's
    // conversation list live. Best-effort, never blocks the response.
    affectedPartnerIds.forEach((partnerId) => {
      getEnrichedConversations(partnerId)
        .then((conversations) => broadcastToUser(partnerId, { type: "conversations", conversations }))
        .catch(() => {});
    });

    // Don't leak internal ids / partner list back to the (unauthenticated) client.
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
}

async function resendPasswordResetCode(req, res, next) {
  try {
    const result = await authService.resendPasswordResetCode({ challengeId: req.body?.challengeId });
    return res.json(result);
  } catch (error) {
    return next(error);
  }
}

// Step 1 of changing email: emails a confirmation code to the CURRENT address.
async function startEmailChange(req, res, next) {
  try {
    const account = await getCurrentAccount(req);
    if (!account) return res.status(401).json({ message: "Not signed in." });
    const result = await authService.startEmailChange({ account, newEmail: req.body?.newEmail });
    return res.json(result);
  } catch (error) {
    return next(error);
  }
}

// Step 2: confirm the code and move the account to the new email.
async function verifyEmailChange(req, res, next) {
  try {
    const account = await getCurrentAccount(req);
    if (!account) return res.status(401).json({ message: "Not signed in." });
    const result = await authService.verifyEmailChange({
      userId: account.user_id,
      challengeId: req.body?.challengeId,
      code: req.body?.code,
    });
    return res.json({ ok: true, ...result });
  } catch (error) {
    return next(error);
  }
}

async function resendEmailChangeCode(req, res, next) {
  try {
    const account = await getCurrentAccount(req);
    if (!account) return res.status(401).json({ message: "Not signed in." });
    const result = await authService.resendEmailChangeCode({
      userId: account.user_id,
      challengeId: req.body?.challengeId,
    });
    return res.json(result);
  } catch (error) {
    return next(error);
  }
}

async function register(req, res, next) {
  try {
    const payload = registerSchema.parse(req.body);
    const session = await authService.register({
      ...payload,
      ipAddress: getClientIp(req),
      userAgent: req.get("User-Agent") || "",
    });

    // Self-hosted servers don't send email: the account is live immediately,
    // so registration signs you straight in - no verification step.
    res.cookie(config.cookieNames.session, session.token, authService.sessionCookieOptions(session.expiresAt));
    res.status(201).json({ user: session.user });
  } catch (error) {
    next(error);
  }
}

async function verifyEmail(req, res, next) {
  try {
    const email = typeof req.body?.email === "string" ? req.body.email.trim() : "";
    const code = typeof req.body?.code === "string" ? req.body.code.trim() : "";
    if (!email || !code) {
      return res.status(400).json({ message: "Email and code are required." });
    }

    const session = await authService.verifyEmail({
      email,
      code,
      ipAddress: getClientIp(req),
      userAgent: req.get("User-Agent") || "",
    });

    res.cookie(config.cookieNames.session, session.token, authService.sessionCookieOptions(session.expiresAt));
    return res.status(201).json({ user: session.user });
  } catch (error) {
    return next(error);
  }
}

async function resendVerification(req, res, next) {
  try {
    const email = typeof req.body?.email === "string" ? req.body.email.trim() : "";
    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }
    await authService.resendVerification({ email });
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
}

async function logout(req, res, next) {
  try {
    const token = getSessionToken(req);
    await authService.logout(token);
    res.clearCookie(config.cookieNames.session, authService.sessionCookieOptions(new Date()));
    res.status(204).send();
  } catch (error) {
    next(error);
  }
}

async function deleteAccount(req, res, next) {
  try {
    const account = await getCurrentAccount(req);
    if (!account) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!password) {
      return res.status(400).json({ message: "Password is required to delete your account." });
    }

    // Capture everyone who shares a DM or server with us BEFORE we wipe the data,
    // so we can push them a live refresh once the account is gone.
    const affected = new Set([
      ...messageRepository.getConversationPartnerIds(account.user_id),
      ...serverRepository.getSharedMemberIdsForUser(account.user_id),
    ]);
    affected.delete(account.user_id);

    await authService.deleteAccount({ userId: account.user_id, password });

    // The session row is already gone (cascade); clear the cookie too.
    res.clearCookie(config.cookieNames.session, authService.sessionCookieOptions(new Date()));

    // Best-effort live update so former DM partners' conversation lists refresh
    // without a reload. Never blocks the response.
    affected.forEach((recipientId) => {
      getEnrichedConversations(recipientId)
        .then((conversations) => broadcastToUser(recipientId, { type: "conversations", conversations }))
        .catch(() => {});
    });

    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
}

async function me(req, res, next) {
  try {
    const user = await getCurrentUser(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    return res.json({ user });
  } catch (error) {
    return next(error);
  }
}

async function heartbeat(req, res, next) {
  try {
    const user = await getCurrentAccount(req);
    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }
    await authService.recordHeartbeat(user.user_id, getClientIp(req), req.body?.status);
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
}

async function getProfilePicture(req, res, next) {
  try {
    const user = await getCurrentAccount(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const { uid } = req.query;
    let targetUserId = user.user_id;

    if (uid) {
      const targetUser = await authService.getUserByAnyId(uid);
      if (targetUser) {
        targetUserId = targetUser.user_id;
      }
    }

    const profilePicture = await authService.getProfilePicture(targetUserId);
    res.type(profilePicture.mimeType);
    res.set("Cache-Control", "private, max-age=60");
    return res.send(Buffer.from(profilePicture.data));
  } catch (error) {
    return next(error);
  }
}

async function getProfileBanner(req, res, next) {
  try {
    const user = await getCurrentAccount(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const { uid } = req.query;
    let targetUserId = user.user_id;

    if (uid) {
      const targetUser = await authService.getUserByAnyId(uid);
      if (targetUser) {
        targetUserId = targetUser.user_id;
      }
    }

    const profileBanner = await authService.getProfileBanner(targetUserId);
    if (!profileBanner?.profile_banner || !profileBanner?.profile_banner_mime) {
      return res.status(204).send();
    }

    res.type(profileBanner.profile_banner_mime);
    res.set("Cache-Control", "private, max-age=60");
    return res.send(Buffer.from(profileBanner.profile_banner));
  } catch (error) {
    return next(error);
  }
}

async function updateProfilePicture(req, res, next) {
  try {
    const user = await getCurrentAccount(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const mimeType = (req.get("Content-Type") || "").split(";")[0].toLowerCase();
    const detectedMimeType = validateProfilePicture(req.body, mimeType);

    await authService.updateProfilePicture({
      userId: user.user_id,
      publicUserId: user.public_user_id || user.user_id,
      data: req.body,
      mimeType: detectedMimeType,
    });

    const updatedUser = await getCurrentUser(req);
    const publicUserId = user.public_user_id || user.user_id;
    const profilePictureUrl = `/api/auth/profile-picture?uid=${encodeURIComponent(publicUserId)}&v=${encodeURIComponent(Date.now())}`;
    const recipients = new Set([
      user.user_id,
      ...messageRepository.getConversationPartnerIds(user.user_id),
      ...serverRepository.getSharedMemberIdsForUser(user.user_id),
    ]);
    recipients.forEach((recipientId) => {
      broadcastToUser(recipientId, {
        type: "profile_update",
        userId: publicUserId,
        username: updatedUser.username,
        alias: updatedUser.alias || "",
        profilePictureUrl,
      });
    });
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

async function updateProfileBanner(req, res, next) {
  try {
    const user = await getCurrentAccount(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const detectedMimeType = validateProfileBanner(req.body);

    await authService.updateProfileBanner({
      userId: user.user_id,
      publicUserId: user.public_user_id || user.user_id,
      data: req.body,
      mimeType: detectedMimeType,
    });

    const updatedUser = await getCurrentUser(req);
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

async function updateProfile(req, res, next) {
  try {
    const user = await getCurrentAccount(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const payload = profileSchema.parse(req.body);
    await authService.updateProfile({
      userId: user.user_id,
      alias: payload.alias,
      bio: payload.bio,
    });

    const updatedUser = await getCurrentUser(req);
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

// Save which of the user's earned badges are hidden from their profile.
async function updateBadges(req, res, next) {
  try {
    const user = await getCurrentAccount(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const hidden = Array.isArray(req.body?.hidden) ? req.body.hidden : [];
    const updatedUser = await authService.updateVisibleBadges({
      userId: user.user_id,
      hidden,
    });
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

// Pick a solid-color banner (or clear it with an empty color to fall back to the
// profile style's default backdrop).
async function updateBannerColor(req, res, next) {
  try {
    const user = await getCurrentAccount(req);
    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const color = typeof req.body?.color === "string" ? req.body.color : "";
    const updatedUser = await authService.updateBannerColor({
      userId: user.user_id,
      color,
    });
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

// Switch the profile style (gated styles are enforced server-side).
async function updateProfileStyle(req, res, next) {
  try {
    const user = await getCurrentAccount(req);
    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const style = typeof req.body?.style === "string" ? req.body.style : "default";
    const updatedUser = await authService.updateProfileStyle({
      userId: user.user_id,
      style,
    });
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

// Serve a user's custom-theme image (the wallpaper behind the messages area).
async function getAppThemeImage(req, res, next) {
  try {
    const user = await getCurrentAccount(req);
    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const themeImage = await authService.getAppThemeImage(user.user_id);
    if (!themeImage?.data || !themeImage?.mimeType) {
      return res.status(204).send();
    }

    res.type(themeImage.mimeType);
    res.set("Cache-Control", "private, max-age=60");
    return res.send(Buffer.from(themeImage.data));
  } catch (error) {
    return next(error);
  }
}

// Switch the app theme (default / black / custom) + save the custom config.
async function updateAppTheme(req, res, next) {
  try {
    const user = await getCurrentAccount(req);
    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const theme = typeof req.body?.theme === "string" ? req.body.theme : "default";
    const updatedUser = await authService.updateAppTheme({
      userId: user.user_id,
      theme,
      config: req.body?.config,
    });
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

// Upload the image that backs a custom theme.
async function updateAppThemeImage(req, res, next) {
  try {
    const user = await getCurrentAccount(req);
    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const detectedMimeType = validateAppThemeImage(req.body);
    const updatedUser = await authService.updateAppThemeImage({
      userId: user.user_id,
      publicUserId: user.public_user_id || user.user_id,
      data: req.body,
      mimeType: detectedMimeType,
    });
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

async function updateUsername(req, res, next) {
  try {
    const user = await getCurrentAccount(req);

    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const payload = usernameUpdateSchema.parse(req.body);
    await authService.updateUsername({
      userId: user.user_id,
      newUsername: payload.username,
      password: payload.password,
    });

    const updatedUser = await getCurrentUser(req);
    return res.json({ user: updatedUser });
  } catch (error) {
    return next(error);
  }
}

async function saveKeys(req, res, next) {
  try {
    const user = await getCurrentAccount(req);
    if (!user) {
      return res.status(401).json({ message: "Not signed in." });
    }

    const { publicKey, encryptedPrivateKey, keySalt } = req.body;
    if (!publicKey || !encryptedPrivateKey || !keySalt) {
      return res.status(400).json({ message: "Public key, encrypted private key, and salt are required." });
    }

    await authService.updateKeys({
      userId: user.user_id,
      publicKey,
      encryptedPrivateKey,
      keySalt,
    });

    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
}

// Public profile card ("View Full Profile" modal): public fields + join date.
// Auth-required; returns only public info, looked up by public OR internal id.
async function getPublicProfile(req, res, next) {
  try {
    const viewer = await getCurrentUser(req);
    if (!viewer) return res.status(401).json({ error: "Not authenticated." });
    const uid = typeof req.query.uid === "string" ? req.query.uid.trim() : "";
    if (!uid) return res.status(400).json({ error: "Missing user id." });
    const user = userRepository.findByAnyId(uid);
    if (!user) return res.status(404).json({ error: "User not found." });
    const publicId = user.public_user_id || user.user_id;
    const v = encodeURIComponent(user.updated_at || user.created_at || "");
    const presenceStatus = publicPresenceStatus(user);
    return res.json({
      userId: publicId,
      username: user.username,
      alias: user.profile_alias || "",
      bio: user.bio || "",
      badges: getUserBadges(user),
      userNumber: user.user_number, // join order, surfaced on the "first 10,000" badge tooltip
      createdAt: toUtcIso(user.created_at),
      isOnline: isPublicOnline(user),
      presenceStatus,
      profilePictureUrl: `/api/auth/profile-picture?uid=${encodeURIComponent(publicId)}&v=${v}`,
      profileBannerUrl: user.profile_banner_mime
        ? `/api/auth/profile-banner?uid=${encodeURIComponent(publicId)}&v=${v}`
        : "",
      profileBannerColor: user.profile_banner_color || "",
      profileStyle: user.profile_style || "default",
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  deleteAccount,
  getPublicProfile,
  getCsrf,
  getProfileBanner,
  getProfilePicture,
  heartbeat,
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
  me,
  register,
  resendVerification,
  verifyEmail,
  updateProfile,
  updateBadges,
  updateBannerColor,
  updateProfileStyle,
  getAppThemeImage,
  updateAppTheme,
  updateAppThemeImage,
  updateProfileBanner,
  updateProfilePicture,
  updateUsername,
  saveKeys,
};
