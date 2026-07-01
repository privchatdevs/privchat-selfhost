const express = require("express");
const {
  authLimiter,
  csrfLimiter,
  heartbeatLimiter,
  profilePictureLimiter,
  profileUpdateLimiter,
  badgeUpdateLimiter,
  securityLimiter,
  usernameLimiter,
  verifyLimiter,
} = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const {
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
} = require("../controllers/authController");

const router = express.Router();

// ── Public / low-sensitivity ──────────────────────────────────────────────────
router.get("/csrf", csrfLimiter, getCsrf);
router.get("/me", me);
router.get("/profile-banner", getProfileBanner);
router.get("/profile-picture", getProfilePicture);
router.get("/app-theme-image", getAppThemeImage);
router.get("/public-profile", getPublicProfile);

// ── Authentication ─────────────────────────────────────────────────────────────
router.post("/login", authLimiter, requireCsrf, login);
router.post("/verify-login", verifyLimiter, requireCsrf, verifyLogin);
router.post("/resend-login-code", authLimiter, requireCsrf, resendLoginCode);
router.post("/register", authLimiter, requireCsrf, register);
router.post("/verify-email", verifyLimiter, requireCsrf, verifyEmail);
router.post("/resend-verification", authLimiter, requireCsrf, resendVerification);
router.post("/logout", requireCsrf, logout);

// Forgot-password (public). Enumeration-safe + rate-limited + CSRF-protected.
router.post("/forgot-password", authLimiter, requireCsrf, forgotPassword);
router.post("/reset-password", verifyLimiter, requireCsrf, resetPassword);
router.post("/reset-password/resend", authLimiter, requireCsrf, resendPasswordResetCode);

// ── Security settings (2FA toggle, auto-delete config) ───────────────────────
router.get("/security", getSecuritySettings);
router.patch("/security", securityLimiter, requireCsrf, updateSecuritySettings);

// Account credentials: password change re-verifies the current password; email
// change emails a code to the CURRENT address. Rate-limited + CSRF-protected.
router.post("/change-password", securityLimiter, requireCsrf, changePassword);
router.post("/change-email/start", securityLimiter, requireCsrf, startEmailChange);
router.post("/change-email/verify", verifyLimiter, requireCsrf, verifyEmailChange);
router.post("/change-email/resend", authLimiter, requireCsrf, resendEmailChangeCode);

// Password-gated, rate-limited, CSRF-protected - and irreversible.
router.post("/delete-account", authLimiter, requireCsrf, deleteAccount);
router.post("/keys", requireCsrf, saveKeys);

// ── Heartbeat ──────────────────────────────────────────────────────────────────
router.post("/heartbeat", heartbeatLimiter, heartbeat);

// ── Profile management ─────────────────────────────────────────────────────────
router.patch("/profile", profileUpdateLimiter, requireCsrf, updateProfile);
router.patch("/badges", badgeUpdateLimiter, requireCsrf, updateBadges);
router.patch("/banner-color", profileUpdateLimiter, requireCsrf, updateBannerColor);
router.patch("/profile-style", profileUpdateLimiter, requireCsrf, updateProfileStyle);
router.patch("/app-theme", profileUpdateLimiter, requireCsrf, updateAppTheme);
router.post(
  "/app-theme-image",
  profilePictureLimiter,
  express.raw({ type: ["image/png", "image/jpeg", "image/webp", "image/gif"], limit: "8mb" }),
  requireCsrf,
  updateAppThemeImage
);
router.patch("/username", usernameLimiter, requireCsrf, updateUsername);
router.post(
  "/profile-picture",
  profilePictureLimiter,
  express.raw({ type: ["image/png", "image/jpeg", "image/webp", "image/gif"], limit: "10mb" }),
  requireCsrf,
  updateProfilePicture
);
router.post(
  "/profile-banner",
  profilePictureLimiter,
  express.raw({ type: ["image/png", "image/jpeg", "image/webp", "image/gif"], limit: "10mb" }),
  requireCsrf,
  updateProfileBanner
);

module.exports = router;
