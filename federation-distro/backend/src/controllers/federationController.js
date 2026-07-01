const { config } = require("../config/env");
const { loadOrCreateKeypair } = require("../services/federation");
const federationRepository = require("../repositories/federationRepository");

const SERVER_VERSION = "1.0";

// Public federation surface. Two rules apply to every route here:
//   1. Feature-flagged: with FEDERATION unset/off these endpoints answer 404,
//      indistinguishable from the feature not existing.
//   2. Blacklist-gated: a request from a blocked IP/CIDR also gets a plain 404
//      (never a 403 - a blocked server learns nothing about why).
function federationGate(req, res, next) {
  if (!config.federation.enabled) {
    res.status(404).json({ error: "Not found." });
    return;
  }
  if (federationRepository.isIpBlocked(req.ip)) {
    res.status(404).json({ error: "Not found." });
    return;
  }
  next();
}

// GET /api/federation/keys - this server's published verification keys. Other
// servers fetch this to verify tokens we signed. validUntil tells cachers when
// to re-fetch (24h), mirroring Matrix's valid_until_ts.
function getKeys(_req, res) {
  const { keyId, publicKeyBase64 } = loadOrCreateKeypair();
  res.json({
    serverName: config.federation.serverName,
    keys: { [keyId]: publicKeyBase64 },
    validUntil: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
  });
}

// GET /api/federation/info - discovery card shown before a user joins this
// server from elsewhere: who we are, what we run, where our keys live.
function getInfo(_req, res) {
  const { keyId } = loadOrCreateKeypair();
  res.json({
    name: config.serverDisplayName,
    serverName: config.federation.serverName,
    version: SERVER_VERSION,
    federation: true,
    keysUrl: "/api/federation/keys",
    keyId,
  });
}

module.exports = { federationGate, getKeys, getInfo };
