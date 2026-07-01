const messageRepository = require("../repositories/messageRepository");
const serverRepository = require("../repositories/serverRepository");
const groupRepository = require("../repositories/groupRepository");
const groupService = require("./groupService");
const assetService = require("./assetService");

// How often to reap expired messages. Correctness doesn't depend on this being
// fast - reads already hide expired messages and clients hide them live, so this
// is purely storage reclamation. Once a minute is plenty and stays cheap.
const SWEEP_INTERVAL_MS = 60 * 1000;
const INITIAL_DELAY_MS = 10 * 1000;
// Inactive-account deletion is heavy and inactivity is measured in months, so it
// runs far less often than the per-minute message sweep - once an hour is plenty.
const ACCOUNT_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

let running = false;
let lastAccountSweepAt = 0;

// Delete the B2 media behind auto-deleted attachment messages. `attachments` is
// [{ senderId, content }] gathered by the sweeps above. We only delete an asset
// when the EXPIRING message's sender actually owns it (marker.owner matches the
// sender's public or internal id) - never trusting a marker that points at another
// user's slug, so one user can't wipe another's media by referencing it.
async function purgeExpiredAttachments(attachments) {
  if (!attachments.length) return;
  try {
    const authDb = require("../config/db");
    const pubCache = new Map(); // internal id -> public id (cached per sweep)
    const publicIdOf = (internalId) => {
      if (pubCache.has(internalId)) return pubCache.get(internalId);
      let publicId = null;
      try { publicId = authDb.prepare("SELECT public_user_id FROM users WHERE user_id = ?").get(internalId)?.public_user_id || null; }
      catch { /* auth.db unavailable - fall back to internal-id match only */ }
      pubCache.set(internalId, publicId);
      return publicId;
    };

    const seen = new Set();
    const refs = [];
    for (const { senderId, content } of attachments) {
      for (const ref of assetService.parseAttachmentRefs(content)) {
        if (ref.owner !== senderId && ref.owner !== publicIdOf(senderId)) continue; // ownership gate
        const key = `${ref.owner} ${ref.slug}`;
        if (!seen.has(key)) { seen.add(key); refs.push(ref); }
      }
    }

    const removed = await assetService.purgeAttachments(refs);
    if (removed > 0) console.log(`[AUTO-DELETE] freed ${removed} attachment${removed === 1 ? "" : "s"} from storage`);
  } catch (error) {
    console.error("[AUTO-DELETE] media cleanup failed:", error.message);
  }
}

async function sweepOnce() {
  if (running) return; // never overlap sweeps
  running = true;
  try {
    // Collect { senderId, content } for every DM / server message reaped this pass,
    // so we can then delete the underlying B2 media (not just the row that linked to
    // it). DM + server channel markers are plaintext, so their owner/slug is readable
    // here; group attachments are E2E and instead get purged wholesale when the group
    // itself is deleted.
    const attachments = [];
    const collect = (arr) => { if (Array.isArray(arr) && arr.length) attachments.push(...arr); };
    collect(await messageRepository.sweepExpiredMessages());
    collect(await serverRepository.sweepExpiredServerMessages());
    collect(await serverRepository.sweepChannelAutoDelete());
    await groupRepository.sweepExpiredGroupMessages();
    await groupService.sweepInactiveGroups();
    await purgeExpiredAttachments(attachments);
    // Telegram-style inactive-account self-destruct (throttled to hourly).
    const now = Date.now();
    if (now - lastAccountSweepAt >= ACCOUNT_SWEEP_INTERVAL_MS) {
      lastAccountSweepAt = now;
      await require("./authService").sweepInactiveAccounts();
    }
  } catch (error) {
    console.error("[AUTO-DELETE] sweep failed:", error.message);
  } finally {
    running = false;
  }
}

function startAutoDeleteSweeper() {
  setTimeout(sweepOnce, INITIAL_DELAY_MS);
  const timer = setInterval(sweepOnce, SWEEP_INTERVAL_MS);
  timer.unref?.(); // don't keep the process alive just for the sweeper
  console.log(`\x1b[32m[AUTO-DELETE]\x1b[0m Sweeper running every ${SWEEP_INTERVAL_MS / 1000}s`);
  return timer;
}

module.exports = { startAutoDeleteSweeper, sweepOnce };
