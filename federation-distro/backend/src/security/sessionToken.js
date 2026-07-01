const crypto = require("crypto");

function createSessionToken() {
  return crypto.randomBytes(32).toString("base64url");
}

function hashSessionToken(token) {
  return crypto.createHash("sha256").update(token, "utf8").digest();
}

module.exports = { createSessionToken, hashSessionToken };
