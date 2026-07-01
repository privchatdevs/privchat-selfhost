const { config } = require("../config/env");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const feedbackRepository = require("../repositories/feedbackRepository");

const MAX_MESSAGE = 4000;
const MIN_MESSAGE = 3;
const DAILY_LIMIT = 2; // per-user cap on feedback submissions (2 per day)

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}
async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

// Receive a "Help Us" message (suggestion / bug / other) and file it for the
// admin "Other" inbox. Auth-required so each note is tied to a real account (the
// admin may reward a praised contributor later).
async function submitFeedback(req, res) {
  try {
    const user = await requireAuth(req);
    if (!user) {
      res.status(401).json({ error: "Not authenticated." });
      return;
    }

    const { kind, message } = req.body || {};
    const cleanKind = feedbackRepository.VALID_KINDS.has(kind) ? kind : "other";
    const cleanMessage = typeof message === "string" ? message.trim().slice(0, MAX_MESSAGE) : "";
    if (cleanMessage.length < MIN_MESSAGE) {
      res.status(400).json({ error: "Please add a little more detail before sending." });
      return;
    }

    if (feedbackRepository.countByUserLastDay(user.user_id) >= DAILY_LIMIT) {
      res.status(429).json({ error: "You can send up to 2 suggestions per day - please try again tomorrow. Thank you!" });
      return;
    }

    feedbackRepository.createFeedback({
      userId: user.user_id,
      publicId: user.public_user_id,
      username: user.username,
      kind: cleanKind,
      message: cleanMessage,
    });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Could not send your feedback." });
  }
}

module.exports = { submitFeedback };
