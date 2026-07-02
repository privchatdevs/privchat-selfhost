const crypto = require("crypto");
const { config } = require("../config/env");

function createCsrfToken(req, res) {
  const token = crypto.randomBytes(32).toString("base64url");

  res.cookie(config.cookieNames.csrf, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: config.cookieSecure,
    signed: true,
    path: "/",
  });

  return token;
}

function requireCsrf(req, res, next) {
  const cookieToken = req.signedCookies?.[config.cookieNames.csrf];
  const headerToken = req.get("X-CSRF-Token") || req.body?.csrfToken;

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ message: "Security check failed. Refresh and try again." });
  }

  return next();
}

module.exports = { createCsrfToken, requireCsrf };
