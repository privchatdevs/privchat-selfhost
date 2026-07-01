const express = require("express");
const { friendsLimiter, purgeLimiter } = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const {
  acceptRequest,
  blockUser,
  cancelRequest,
  declineRequest,
  getBlocked,
  getBlockState,
  getFriends,
  getPending,
  purgeFriends,
  removeFriend,
  sendRequest,
  unblockUser,
} = require("../controllers/friendController");

const router = express.Router();

// All friend routes are rate-limited
router.use(friendsLimiter);

// Read-only
router.get("/", getFriends);
router.get("/pending", getPending);
router.get("/blocked", getBlocked);
router.get("/blocks/:userId", getBlockState);

// Write operations require CSRF protection
// Bulk "remove all friends" - declared before "/:id" routes so the literal path wins.
// Tight purgeLimiter (shared with the DM purge) since this is a heavy, rare action.
router.post("/purge-all", purgeLimiter, requireCsrf, purgeFriends);
router.post("/request", requireCsrf, sendRequest);
router.post("/blocks/:userId", requireCsrf, blockUser);
router.delete("/blocks/:userId", requireCsrf, unblockUser);
router.post("/:id/accept", requireCsrf, acceptRequest);
router.post("/:id/decline", requireCsrf, declineRequest);
router.delete("/:id/request", requireCsrf, cancelRequest);
router.delete("/:id", requireCsrf, removeFriend);

module.exports = router;
