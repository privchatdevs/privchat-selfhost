const express = require("express");
const { federationLimiter } = require("../middleware/security");
const { federationGate, getKeys, getInfo } = require("../controllers/federationController");

const router = express.Router();

// Public server-to-server surface: strangers' servers hit these, so they get
// their own rate budget and the flag/blacklist gate before any handler runs.
router.use(federationLimiter);
router.use(federationGate);
router.get("/keys", getKeys);
router.get("/info", getInfo);

module.exports = router;
