const messageDb = require("../config/messageDb");

// Per-member, per-server privacy. A member can opt out of pings, DMs, and/or
// friend requests that reach them BECAUSE of a specific server. DM + friend
// request blocks are enforced server-side here; the ping block is applied
// client-side (the message still arrives, it just doesn't ping you).
//
// Columns map to the three toggles:
//   block_pings        - suppress @mention pings from this server (client-applied)
//   block_dms          - members of this server can't DM you (unless already friends)
//   block_friend_reqs  - members of this server can't friend-request you

function getForUserServer(userId, serverId) {
  const row = messageDb
    .prepare("SELECT block_pings, block_dms, block_friend_reqs FROM server_privacy WHERE user_id = ? AND server_id = ?")
    .get(userId, serverId);
  return {
    blockPings: Boolean(row?.block_pings),
    blockDms: Boolean(row?.block_dms),
    blockFriendRequests: Boolean(row?.block_friend_reqs),
  };
}

function setForUserServer(userId, serverId, { blockPings, blockDms, blockFriendRequests }) {
  messageDb
    .prepare(`
      INSERT INTO server_privacy (user_id, server_id, block_pings, block_dms, block_friend_reqs, updated_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(user_id, server_id) DO UPDATE SET
        block_pings = excluded.block_pings,
        block_dms = excluded.block_dms,
        block_friend_reqs = excluded.block_friend_reqs,
        updated_at = excluded.updated_at
    `)
    .run(userId, serverId, blockPings ? 1 : 0, blockDms ? 1 : 0, blockFriendRequests ? 1 : 0);
}

// True when `recipientId` has the given block ON for some server that `senderId`
// is a member of - i.e. the sender is reaching them THROUGH a blocked server.
// `column` is whitelisted so it can never be attacker-controlled SQL.
function isSenderBlockedByServer(recipientId, senderId, column) {
  const allowed = new Set(["block_dms", "block_friend_reqs", "block_pings"]);
  if (!allowed.has(column)) return false;
  return Boolean(
    messageDb
      .prepare(`
        SELECT 1
        FROM server_privacy sp
        JOIN server_members sm ON sm.server_id = sp.server_id
        WHERE sp.user_id = ? AND sp.${column} = 1 AND sm.user_id = ?
        LIMIT 1
      `)
      .get(recipientId, senderId)
  );
}

// Server ids where this user has the ping block on, so the client can silence
// those mentions as they arrive (the ping block is client-applied).
function getPingBlockedServerIds(userId) {
  return messageDb
    .prepare("SELECT server_id FROM server_privacy WHERE user_id = ? AND block_pings = 1")
    .all(userId)
    .map((row) => row.server_id);
}

// Note: cleanup on server deletion / account purge is handled inline in
// serverRepository (alongside the other per-server / per-user table deletes).

module.exports = {
  getForUserServer,
  setForUserServer,
  isSenderBlockedByServer,
  getPingBlockedServerIds,
};
