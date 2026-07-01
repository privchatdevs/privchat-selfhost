const { config } = require("../config/env");

async function verifyHCaptcha({ token, ipAddress }) {
  // Captcha is OPTIONAL on a self-hosted server: with no secret configured,
  // login/registration simply run without one. Set HCAPTCHA_SITE_KEY +
  // HCAPTCHA_SECRET_KEY to turn it on (recommended for open registration).
  if (!config.hcaptcha.secretKey) {
    return;
  }

  const data = new URLSearchParams({
    secret: config.hcaptcha.secretKey,
    response: token,
    remoteip: ipAddress,
    sitekey: config.hcaptcha.siteKey,
  });

  let response;
  try {
    response = await fetch("https://api.hcaptcha.com/siteverify", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: data,
    });
  } catch {
    const error = new Error("Could not verify captcha. Check the server internet connection.");
    error.statusCode = 502;
    throw error;
  }

  const result = await response.json().catch(() => ({}));

  if (!response.ok || !result.success) {
    const codes = result["error-codes"] || [];
    const error = new Error(codes.includes("invalid-input-secret")
      ? "Captcha secret key is invalid."
      : "Please complete the captcha again.");
    error.statusCode = 400;
    throw error;
  }
}

module.exports = { verifyHCaptcha };
