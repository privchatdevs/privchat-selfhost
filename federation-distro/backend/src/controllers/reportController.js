const { config } = require("../config/env");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const reportRepository = require("../repositories/reportRepository");
const userRepository = require("../repositories/userRepository");
const serverRepository = require("../repositories/serverRepository");

const MAX_EXCERPT = 500;
const MAX_DETAILS = 2000; // free-text the reporter writes for an "Other" report
const HOURLY_LIMIT = 2; // hidden: extra reports past this are silently dropped

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}
async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

// Scopes describe WHAT is being reported:
//   dm / server        - a message (the existing message reports)
//   profile            - a user's profile picture / banner / bio
//   server_profile     - a server's icon / banner / name (the "reported user" we
//                        store is the server OWNER, so the admin sees who's
//                        responsible).
const VALID_SCOPES = new Set(["dm", "group", "server", "profile", "server_profile"]);

// Submit a report. Reasons: 'automated' | 'csam' | 'profile'. Always responds
// { ok: true } on a valid request, even when the hidden per-user hourly cap is
// hit, so a spammer can't detect the limit.
async function submitReport(req, res) {
  try {
    const user = await requireAuth(req);
    if (!user) {
      res.status(401).json({ error: "Not authenticated." });
      return;
    }

    const { reportedUserId, reason, scope, messageId, serverId, channelId, messageExcerpt, clientRecentMessages, details } = req.body || {};

    if (!reportRepository.VALID_REASONS.has(reason)) {
      res.status(400).json({ error: "Invalid report reason." });
      return;
    }

    // "Other" reports carry the reporter's free-text explanation (≤2000 chars) and
    // require it. Any report may include details, but only "other" demands them.
    const cleanedDetails = typeof details === "string" ? details.trim().slice(0, MAX_DETAILS) : "";
    if (reason === "other" && !cleanedDetails) {
      res.status(400).json({ error: "Please describe what you're reporting." });
      return;
    }

    const normalizedScope = VALID_SCOPES.has(scope) ? scope : null;

    // For a server report there's no specific reported user - the responsible
    // party is the server's owner, so resolve and store that as the target.
    let targetUserId = reportedUserId && typeof reportedUserId === "string" ? reportedUserId : null;
    let resolvedServerId = serverId ? String(serverId).slice(0, 100) : null;
    if (normalizedScope === "server_profile") {
      if (!resolvedServerId) {
        res.status(400).json({ error: "Missing server." });
        return;
      }
      const server = serverRepository.getServer(resolvedServerId);
      if (!server) {
        res.status(400).json({ error: "Server not found." });
        return;
      }
      targetUserId = server.owner_id;
    }

    if (!targetUserId || typeof targetUserId !== "string") {
      res.status(400).json({ error: "Missing reported user." });
      return;
    }
    if (targetUserId === user.user_id || targetUserId === user.public_user_id) {
      res.status(400).json({ error: "You can't report your own content." });
      return;
    }
    // Reassign so the rest of the handler uses the resolved id.
    const reportedTargetId = targetUserId;

    // Hidden limit: accept the request but drop the report once over the cap.
    if (reportRepository.countByReporterLastHour(user.user_id) >= HOURLY_LIMIT) {
      res.json({ ok: true });
      return;
    }

    // Snapshot the reported user's recent messages (with timestamps) so the admin
    // can review context later. "Automated activity" reports cast a wider net -
    // the last 30 across the ENTIRE server (botting/spam usually spans channels),
    // each tagged with its channel name; everything else takes the last 10 in just
    // the reported channel. Server messages are plaintext server-side; DMs are
    // E2E-encrypted and never readable here.
    let recentMessages = null;
    try {
      const reportedUser = userRepository.findByAnyId(String(reportedTargetId));
      if (reportedUser) {
        if (reason === "automated" && resolvedServerId) {
          recentMessages = serverRepository
            .getRecentUserServerMessages(resolvedServerId, reportedUser.user_id, 30)
            .map((m) => ({
              content: String(m.content || "").slice(0, MAX_EXCERPT),
              createdAt: m.created_at,
              channelName: m.channel_name || null,
            }));
        } else if (channelId) {
          recentMessages = serverRepository
            .getRecentUserChannelMessages(String(channelId), reportedUser.user_id, 10)
            .map((m) => ({ content: String(m.content || "").slice(0, MAX_EXCERPT), createdAt: m.created_at }));
        }
      }
    } catch { /* snapshot is best-effort */ }

    // DM spam/botting: the server can't read E2E DM history, so the reporter's
    // client sends a snapshot of the sender's recent messages. Trust it only for
    // this case, capped and sanitized; the admin panel marks it as reporter-supplied
    // (the report's scope=dm already signals it can't be server-verified).
    if (!recentMessages && (normalizedScope === "dm" || normalizedScope === "group") && reason === "automated" && Array.isArray(clientRecentMessages)) {
      const cleaned = clientRecentMessages
        .filter((m) => m && typeof m.content === "string" && m.content.trim())
        .slice(0, 30)
        .map((m) => ({
          content: m.content.slice(0, MAX_EXCERPT),
          createdAt: typeof m.createdAt === "string" ? m.createdAt.slice(0, 40) : null,
        }));
      if (cleaned.length) recentMessages = cleaned;
    }

    reportRepository.createReport({
      reporterId: user.user_id,
      reportedUserId: String(reportedTargetId).slice(0, 100),
      reason,
      scope: normalizedScope,
      messageId: messageId ? String(messageId).slice(0, 100) : null,
      serverId: resolvedServerId,
      channelId: channelId ? String(channelId).slice(0, 100) : null,
      messageExcerpt: typeof messageExcerpt === "string" ? messageExcerpt.slice(0, MAX_EXCERPT) : null,
      recentMessages,
      details: cleanedDetails || null,
    });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Could not submit report." });
  }
}

module.exports = { submitReport };
