const express = require("express");
const { messageLimiter } = require("../middleware/security");
const { searchPeople, searchGlobal } = require("../controllers/searchController");

const router = express.Router();

router.use(messageLimiter);

// Read-only (GET) - no CSRF/body parsing needed.
router.get("/people", searchPeople);
router.get("/", searchGlobal);

module.exports = router;
