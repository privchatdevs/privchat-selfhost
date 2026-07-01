const express = require("express");
const { messageLimiter } = require("../middleware/security");
const { requireCsrf } = require("../middleware/csrf");
const { submitReport } = require("../controllers/reportController");

const router = express.Router();

router.use(messageLimiter);
router.post("/", requireCsrf, submitReport);

module.exports = router;
