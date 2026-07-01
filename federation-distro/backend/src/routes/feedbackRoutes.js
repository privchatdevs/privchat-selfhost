const express = require("express");
const { messageLimiter } = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const { submitFeedback } = require("../controllers/feedbackController");

const router = express.Router();

router.use(messageLimiter);
router.post("/", requireCsrf, submitFeedback);

module.exports = router;
