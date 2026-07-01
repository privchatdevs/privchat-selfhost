const express = require("express");
const { assetUploadLimiter, purgeLimiter } = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const {
  uploadAsset,
  getStorageUsage,
  purgeStorage,
  getLibrary,
  getStarred,
  starMedia,
  unstarMedia,
} = require("../controllers/assetController");

const router = express.Router();

// The signed-in user's storage usage (read-only, no CSRF).
router.get("/usage", getStorageUsage);

// Media-library tabs (read-only, no CSRF): the user's own uploads + their stars.
router.get("/library", getLibrary);
router.get("/starred", getStarred);

// Star / unstar a media item (own or someone else's). JSON body, CSRF-protected.
router.post("/star", requireCsrf, starMedia);
router.delete("/star", requireCsrf, unstarMedia);

// Permanently delete ALL of the user's uploaded media. Rate-limited (heavy) + CSRF.
router.post("/purge", purgeLimiter, requireCsrf, purgeStorage);

// Raw body upload (any content type, up to 11 MB at the parser; the service
// enforces the real 10 MB cap). CSRF token travels in the X-CSRF-Token header
// since the body is the file bytes, not JSON.
router.post(
  "/",
  assetUploadLimiter,
  express.raw({ type: () => true, limit: "11mb" }),
  requireCsrf,
  uploadAsset
);

module.exports = router;
