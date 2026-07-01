const crypto = require("crypto");
const messageDb = require("../config/messageDb");
const { encryptContent, decryptContent, isAttachmentMarker } = require("../security/serverMessageCipher");

// Server message content is encrypted at rest (when SERVER_MSG_KEY_BASE64 is set).
// Every row returned to the rest of the app must have its `content` decrypted back
// to plaintext, so callers see exactly what they saw before. Pass-through for
// legacy/plaintext rows, so a mixed table during rollout reads correctly.
function decryptRow(row) {
  if (row && row.content != null) row.content = decryptContent(row.content);
  return row;
}

// Permission bitmask. The server owner bypasses every check; ADMINISTRATOR
// grants everything except deleting the server (owner only).
const PERMISSIONS = {
  ADMINISTRATOR: 1,
  MANAGE_SERVER: 2,
  MANAGE_ROLES: 4,
  MANAGE_CHANNELS: 8,
  KICK_MEMBERS: 16,
  BAN_MEMBERS: 32,
  CREATE_INVITES: 64,
  DELETE_MESSAGES: 128,
  DRAG_USERS: 256,
  MENTION_EVERYONE: 512,
  // Channel-level bits - only meaningful as per-channel overwrites, not assigned
  // in the server role editor. Everyone gets them by default per channel.
  VIEW_CHANNEL: 1024,
  SEND_MESSAGES: 2048,
  // Send Embeds: whether a member's links get a preview embed AND whether they
  // can upload/share file attachments. Assignable in the role editor AND per
  // channel. On by default for @everyone.
  SEND_EMBEDS: 4096,
  // Lets a member set their OWN per-server nickname. Changing OTHER people's
  // nicknames needs Manage Server / admin.
  CHANGE_NICKNAME: 8192,
  // Legacy bit for the old separate "Share Files" permission. New writes fold it
  // into SEND_EMBEDS so embeds/files stay one permission.
  SHARE_FILES: 16384,
  // Voice-channel bits - only meaningful as per-channel overwrites on VOICE
  // channels. On by default for everyone (added in channelPermissionsFor for
  // voice channels), like View + Send are for text. CONNECT = join the channel,
  // SPEAK = transmit microphone audio, VIDEO = share screen / camera.
  CONNECT: 32768,
  SPEAK: 65536,
  VIDEO: 131072,
  // React to messages with emoji. On by default for @everyone and assignable in
  // the role editor AND per channel. Independent of Send Messages, so members can
  // react in read-only channels (e.g. #announcements) unless it's removed.
  ADD_REACTIONS: 262144,
};

const ALL_PERMISSIONS = Object.values(PERMISSIONS).reduce((mask, bit) => mask | bit, 0);
const WITHOUT_SHARE_FILES = ~PERMISSIONS.SHARE_FILES;

function normalizeMergedPermissions(mask) {
  let normalized = Number(mask) || 0;
  if (normalized & PERMISSIONS.SHARE_FILES) {
    normalized |= PERMISSIONS.SEND_EMBEDS;
    normalized &= ~PERMISSIONS.SHARE_FILES;
  }
  return normalized;
}

function normalizeMergedOverwrite(allow, deny) {
  let normalizedAllow = Number(allow) || 0;
  let normalizedDeny = Number(deny) || 0;
  if (normalizedAllow & PERMISSIONS.SHARE_FILES) normalizedAllow |= PERMISSIONS.SEND_EMBEDS;
  if (normalizedDeny & PERMISSIONS.SHARE_FILES) normalizedDeny |= PERMISSIONS.SEND_EMBEDS;
  normalizedAllow &= ~PERMISSIONS.SHARE_FILES;
  normalizedDeny &= ~PERMISSIONS.SHARE_FILES;
  normalizedDeny &= ~normalizedAllow;
  return { allow: normalizedAllow, deny: normalizedDeny };
}

// The permissions that can be set per-channel (allow/inherit/deny). Channel
// management stays a server-wide role permission only - it's not a per-channel
// overwrite, so Manage Channel / Manage Permissions are intentionally excluded.
const CHANNEL_OVERWRITE_PERMISSIONS =
  PERMISSIONS.VIEW_CHANNEL | PERMISSIONS.SEND_MESSAGES | PERMISSIONS.SEND_EMBEDS
  | PERMISSIONS.ADD_REACTIONS
  | PERMISSIONS.CONNECT | PERMISSIONS.SPEAK | PERMISSIONS.VIDEO;

const EVERYONE_ROLE_ID = "@everyone";
const EVERYONE_ROLE_NAME = "@everyone";
// What @everyone gets on a brand-new server: create invites, send embeds/files,
// and add reactions. (Everything else is off by default.)
const DEFAULT_EVERYONE_PERMISSIONS =
  PERMISSIONS.CREATE_INVITES | PERMISSIONS.SEND_EMBEDS | PERMISSIONS.ADD_REACTIONS;

const MAX_SERVERS_PER_USER = 50;
const MAX_SERVER_NAME_LENGTH = 64;
const MAX_CHANNEL_NAME_LENGTH = 32;
const MAX_ROLE_NAME_LENGTH = 32;
const MAX_NICKNAME_LENGTH = 32;
const MAX_TEXT_CHANNELS_PER_SERVER = 50;
const MAX_VOICE_CHANNELS_PER_SERVER = 10;
const MAX_CATEGORIES_PER_SERVER = 25;
const MAX_ROLES_PER_SERVER = 30;
const MAX_CATEGORY_NAME_LENGTH = 32;
const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
// How many *active* (non-expired) invites one user may have per server. Expired
// codes don't count, so slots free up as old ones lapse.
const MAX_INVITES_PER_USER_PER_SERVER = 20;

// One-time backfill: servers created before CHANGE_NICKNAME existed don't have it
// in their @everyone perms, so members couldn't set their own nickname there. OR
// the bit in for every server. Idempotent - the WHERE makes it a no-op once every
// row already has the bit, so it's safe to run on each boot.
try {
  messageDb.prepare(
    "UPDATE servers SET everyone_permissions = everyone_permissions | ? WHERE (everyone_permissions & ?) = 0"
  ).run(PERMISSIONS.CHANGE_NICKNAME, PERMISSIONS.CHANGE_NICKNAME);
  // Servers created before ADD_REACTIONS existed must keep working: grant it to
  // every @everyone that lacks it, so reactions don't suddenly break on upgrade.
  messageDb.prepare(
    "UPDATE servers SET everyone_permissions = everyone_permissions | ? WHERE (everyone_permissions & ?) = 0"
  ).run(PERMISSIONS.ADD_REACTIONS, PERMISSIONS.ADD_REACTIONS);
  // Merge the old Share Files bit into Send Embeds everywhere permissions are
  // stored. This preserves existing file grants while making embeds/files one
  // setting going forward.
  messageDb.prepare(
    "UPDATE servers SET everyone_permissions = (everyone_permissions | ?) & ?, updated_at = datetime('now') WHERE (everyone_permissions & ?) != 0"
  ).run(PERMISSIONS.SEND_EMBEDS, WITHOUT_SHARE_FILES, PERMISSIONS.SHARE_FILES);
  messageDb.prepare(
    "UPDATE server_roles SET permissions = (permissions | ?) & ? WHERE (permissions & ?) != 0"
  ).run(PERMISSIONS.SEND_EMBEDS, WITHOUT_SHARE_FILES, PERMISSIONS.SHARE_FILES);
  messageDb.prepare(
    "UPDATE channel_overwrites SET allow = (allow | ?) & ? WHERE (allow & ?) != 0"
  ).run(PERMISSIONS.SEND_EMBEDS, WITHOUT_SHARE_FILES, PERMISSIONS.SHARE_FILES);
  messageDb.prepare(
    "UPDATE channel_overwrites SET deny = (deny | ?) & ? WHERE (deny & ?) != 0"
  ).run(PERMISSIONS.SEND_EMBEDS, WITHOUT_SHARE_FILES, PERMISSIONS.SHARE_FILES);
  messageDb.prepare("UPDATE channel_overwrites SET deny = deny & (~allow)").run();
  messageDb.prepare("DELETE FROM channel_overwrites WHERE allow = 0 AND deny = 0").run();
} catch {
  // servers table may not exist on a brand-new DB yet - nothing to backfill.
}

// node:sqlite is synchronous, so deleting millions of rows in one statement would
// freeze the whole server and hold a long write lock. Bulk deletes go through
// deleteInBatches(): each chunk removes at most DELETE_BATCH_SIZE rows, then we
// pause so the event loop and the DB are free between chunks (a soft cap on
// how much we delete per second).
const DELETE_BATCH_SIZE = 1000;
const DELETE_BATCH_PAUSE_MS = 25;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// `sql` MUST delete at most DELETE_BATCH_SIZE rows per run (use a
// `WHERE rowid IN (SELECT rowid ... LIMIT ${DELETE_BATCH_SIZE})` form). Loops
// until a run deletes nothing.
async function deleteInBatches(sql, params) {
  const stmt = messageDb.prepare(sql);
  for (;;) {
    const info = stmt.run(...params);
    if (!info.changes) break;
    await sleep(DELETE_BATCH_PAUSE_MS);
  }
}

function newId() {
  return crypto.randomUUID();
}

function newInviteCode(length = 10) {
  // URL-safe chars, no confusing 0/O/1/l characters.
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (let index = 0; index < length; index += 1) {
    code += alphabet[crypto.randomInt(alphabet.length)];
  }
  return code;
}

// Longer-lived invites get longer, harder-to-guess codes. ttlMs === null means a
// permanent invite. <=7 days: 10, >7 days: 11, >=1 month: 15, permanent: 20.
const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const PERMANENT_EXPIRES_AT = "9999-12-31T23:59:59.999Z";
function inviteCodeLengthForTtl(ttlMs) {
  if (ttlMs === null) return 20;
  const days = ttlMs / ONE_DAY_MS;
  if (days >= 30) return 15;
  if (days > 7) return 11;
  return 10;
}

// ── Servers ──────────────────────────────────────────────────────────────────

function createServer({ ownerId, name }) {
  const serverId = newId();
  messageDb.prepare(`
    INSERT INTO servers (server_id, owner_id, name, everyone_permissions)
    VALUES (?, ?, ?, ?)
  `).run(serverId, ownerId, name, normalizeMergedPermissions(DEFAULT_EVERYONE_PERMISSIONS));
  return getServer(serverId);
}

function getServer(serverId) {
  return messageDb.prepare(`
    SELECT server_id, owner_id, name, icon_mime, banner_mime, everyone_permissions, uncategorized_position, created_at, updated_at
    FROM servers
    WHERE server_id = ?
  `).get(serverId);
}

function setUncategorizedPosition(serverId, position) {
  messageDb.prepare(
    "UPDATE servers SET uncategorized_position = ? WHERE server_id = ?"
  ).run(position, serverId);
}

function getServerIcon(serverId) {
  return messageDb.prepare(`
    SELECT icon_key, icon_mime, name
    FROM servers
    WHERE server_id = ?
  `).get(serverId);
}

function updateServerName(serverId, name) {
  messageDb.prepare(
    "UPDATE servers SET name = ?, updated_at = datetime('now') WHERE server_id = ?"
  ).run(name, serverId);
}

// Hand the server to a new owner. The previous owner stays a member (their
// membership row is untouched) but loses owner status.
function updateServerOwner(serverId, newOwnerId) {
  messageDb.prepare(
    "UPDATE servers SET owner_id = ?, updated_at = datetime('now') WHERE server_id = ?"
  ).run(newOwnerId, serverId);
}

function updateServerIcon(serverId, iconKey, mime) {
  messageDb.prepare(
    "UPDATE servers SET icon_key = ?, icon_mime = ?, updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE server_id = ?"
  ).run(iconKey, mime, serverId);
}

function getServerBanner(serverId) {
  return messageDb.prepare(`
    SELECT banner_key, banner_mime, name
    FROM servers
    WHERE server_id = ?
  `).get(serverId);
}

function updateServerBanner(serverId, bannerKey, mime) {
  messageDb.prepare(
    "UPDATE servers SET banner_key = ?, banner_mime = ?, updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE server_id = ?"
  ).run(bannerKey, mime, serverId);
}

function getEveryonePermissions(serverId) {
  const row = messageDb.prepare(
    "SELECT everyone_permissions FROM servers WHERE server_id = ?"
  ).get(serverId);
  return normalizeMergedPermissions(row?.everyone_permissions ?? DEFAULT_EVERYONE_PERMISSIONS);
}

function updateEveryonePermissions(serverId, permissions) {
  messageDb.prepare(
    "UPDATE servers SET everyone_permissions = ?, updated_at = datetime('now') WHERE server_id = ?"
  ).run(normalizeMergedPermissions(permissions), serverId);
}

async function deleteServerCascade(serverId) {
  // Potentially-huge tables (messages + their reactions) go in batches first.
  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN server_messages sm ON sm.message_id = mr.message_id
      JOIN server_channels sc ON sc.channel_id = sm.channel_id
      WHERE sc.server_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [serverId]);
  await deleteInBatches(`
    DELETE FROM server_messages WHERE rowid IN (
      SELECT sm.rowid FROM server_messages sm
      JOIN server_channels sc ON sc.channel_id = sm.channel_id
      WHERE sc.server_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [serverId]);
  // Everything else is bounded (≤ tens of rows) - one quick transaction.
  messageDb.exec("BEGIN");
  try {
    messageDb.prepare(
      "DELETE FROM channel_overwrites WHERE channel_id IN (SELECT channel_id FROM server_channels WHERE server_id = ?)"
    ).run(serverId);
    messageDb.prepare("DELETE FROM server_channels WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_categories WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_member_roles WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_roles WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_discovery WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_discovery_applications WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_discovery_blocks WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_invites WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_bans WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_members WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM server_privacy WHERE server_id = ?").run(serverId);
    messageDb.prepare("DELETE FROM servers WHERE server_id = ?").run(serverId);
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

function listServersForUser(userId) {
  // Custom drag order first (rail_position, lower = higher on the rail). Members
  // who've never reordered all share position 0, so they fall back to newest-
  // joined-first - keeping the most recent server on top until the user drags.
  return messageDb.prepare(`
    SELECT s.server_id, s.owner_id, s.name, s.icon_mime, s.banner_mime, s.created_at, s.updated_at, m.joined_at
    FROM server_members m
    JOIN servers s ON s.server_id = m.server_id
    WHERE m.user_id = ?
    ORDER BY m.rail_position ASC, m.joined_at DESC, s.server_id DESC
  `).all(userId);
}

// Persist a user's custom rail order. Positions are assigned 0..n-1 in the given
// order; ids the user isn't a member of are simply ignored by the UPDATE.
function setServerRailOrder(userId, serverIds) {
  const update = messageDb.prepare(
    "UPDATE server_members SET rail_position = ? WHERE user_id = ? AND server_id = ?"
  );
  messageDb.exec("BEGIN");
  try {
    serverIds.forEach((serverId, index) => update.run(index, userId, serverId));
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

function countServersForUser(userId) {
  return messageDb.prepare(
    "SELECT COUNT(*) AS total FROM server_members WHERE user_id = ?"
  ).get(userId).total;
}

// Total community servers hosted on THIS instance (across all operators). Used to
// enforce the one-community-per-box cap on a self-hosted server.
function countAllServers() {
  return messageDb.prepare("SELECT COUNT(*) AS total FROM servers").get().total;
}

// ── Members ──────────────────────────────────────────────────────────────────

function addMember(serverId, userId) {
  // Place new servers at the top of the rail (smallest rail_position so far,
  // minus one) so a freshly created/joined server appears first - matching the
  // newest-on-top behaviour, while still respecting any custom order below it.
  const minPos = messageDb.prepare(
    "SELECT COALESCE(MIN(rail_position), 0) AS m FROM server_members WHERE user_id = ?"
  ).get(userId).m;
  messageDb.prepare(`
    INSERT OR IGNORE INTO server_members (server_id, user_id, rail_position)
    VALUES (?, ?, ?)
  `).run(serverId, userId, minPos - 1);
}

// Drop a member's own per-member channel overwrites for one server. Called when
// they leave / are kicked / are banned so a non-member doesn't linger in a
// channel's permission list (and a since-deleted account doesn't show up there as
// "unknown member"). Scoped to this server's channels only - per-server, as asked.
function deleteMemberChannelOverwrites(serverId, userId) {
  messageDb.prepare(`
    DELETE FROM channel_overwrites
    WHERE target_type = 'member' AND target_id = ?
      AND channel_id IN (SELECT channel_id FROM server_channels WHERE server_id = ?)
  `).run(userId, serverId);
}

function removeMember(serverId, userId) {
  messageDb.exec("BEGIN");
  try {
    messageDb.prepare("DELETE FROM server_member_roles WHERE server_id = ? AND user_id = ?").run(serverId, userId);
    messageDb.prepare("DELETE FROM server_members WHERE server_id = ? AND user_id = ?").run(serverId, userId);
    deleteMemberChannelOverwrites(serverId, userId);
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

function isMember(serverId, userId) {
  return Boolean(messageDb.prepare(
    "SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?"
  ).get(serverId, userId));
}

function getMemberIds(serverId) {
  return messageDb.prepare(
    "SELECT user_id FROM server_members WHERE server_id = ?"
  ).all(serverId).map((row) => row.user_id);
}

function getMembers(serverId) {
  return messageDb.prepare(`
    SELECT user_id, joined_at, timeout_until, nickname
    FROM server_members
    WHERE server_id = ?
    ORDER BY joined_at, user_id
  `).all(serverId);
}

// Per-server display name. Pass null/empty to clear it (falls back to the user's
// alias/username). Returns the cleaned value that was stored.
function setMemberNickname(serverId, userId, nickname) {
  const clean = nickname ? String(nickname).trim().slice(0, MAX_NICKNAME_LENGTH) : "";
  messageDb.prepare(
    "UPDATE server_members SET nickname = ? WHERE server_id = ? AND user_id = ?"
  ).run(clean || null, serverId, userId);
  return clean || null;
}

function setMemberTimeout(serverId, userId, untilIso) {
  messageDb.prepare(
    "UPDATE server_members SET timeout_until = ? WHERE server_id = ? AND user_id = ?"
  ).run(untilIso, serverId, userId);
}

function getMemberTimeoutUntil(serverId, userId) {
  const row = messageDb.prepare(
    "SELECT timeout_until FROM server_members WHERE server_id = ? AND user_id = ?"
  ).get(serverId, userId);
  return row?.timeout_until || null;
}

function countMembers(serverId) {
  return messageDb.prepare(
    "SELECT COUNT(*) AS total FROM server_members WHERE server_id = ?"
  ).get(serverId).total;
}

function shareServer(userIdA, userIdB) {
  return Boolean(messageDb.prepare(`
    SELECT 1
    FROM server_members a
    JOIN server_members b ON b.server_id = a.server_id
    WHERE a.user_id = ? AND b.user_id = ?
    LIMIT 1
  `).get(userIdA, userIdB));
}

// Up to `limit` distinct nicknames `targetId` uses in servers they share with
// `viewerId` - powers the "aka" line on a DM profile. Empty when none.
function getSharedServerNicknames(viewerId, targetId, limit = 5) {
  return messageDb.prepare(`
    SELECT DISTINCT t.nickname AS nickname
    FROM server_members t
    JOIN server_members v ON v.server_id = t.server_id AND v.user_id = ?
    WHERE t.user_id = ?
      AND t.nickname IS NOT NULL
      AND TRIM(t.nickname) <> ''
    ORDER BY t.nickname
    LIMIT ?
  `).all(viewerId, targetId, limit).map((row) => row.nickname);
}

function getSharedMemberIdsForUser(userId) {
  return messageDb.prepare(`
    SELECT DISTINCT other.user_id
    FROM server_members mine
    JOIN server_members other ON other.server_id = mine.server_id
    WHERE mine.user_id = ?
      AND other.user_id != ?
  `).all(userId, userId).map((row) => row.user_id);
}

// ── Channels ─────────────────────────────────────────────────────────────────

function createChannel(serverId, name, categoryId = null, isPrivate = false, type = "text") {
  const channelId = newId();
  const next = messageDb.prepare(
    "SELECT COALESCE(MAX(position), -1) + 1 AS position FROM server_channels WHERE server_id = ?"
  ).get(serverId).position;
  messageDb.prepare(`
    INSERT INTO server_channels (channel_id, server_id, name, position, category_id, is_private, type)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(channelId, serverId, name, next, categoryId, isPrivate ? 1 : 0, type === "voice" ? "voice" : "text");
  return getChannel(channelId);
}

function getChannel(channelId) {
  return messageDb.prepare(
    "SELECT channel_id, server_id, name, position, category_id, is_private, type, slowmode, auto_delete_seconds, about, created_at FROM server_channels WHERE channel_id = ?"
  ).get(channelId);
}

function listChannels(serverId) {
  return messageDb.prepare(`
    SELECT channel_id, name, position, category_id, is_private, type, slowmode, auto_delete_seconds, about, created_at
    FROM server_channels
    WHERE server_id = ?
    ORDER BY position, created_at
  `).all(serverId);
}

function setChannelAbout(channelId, about) {
  messageDb.prepare("UPDATE server_channels SET about = ? WHERE channel_id = ?").run(about || null, channelId);
}

function setChannelCategory(channelId, categoryId) {
  messageDb.prepare("UPDATE server_channels SET category_id = ? WHERE channel_id = ?").run(categoryId, channelId);
}

function updateChannelLayout(serverId, channels) {
  messageDb.exec("BEGIN");
  try {
    const update = messageDb.prepare(`
      UPDATE server_channels
      SET category_id = ?, position = ?
      WHERE server_id = ? AND channel_id = ?
    `);
    channels.forEach((channel, index) => {
      update.run(channel.categoryId || null, index, serverId, channel.channelId);
    });
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

// ── Categories ───────────────────────────────────────────────────────────────

function createCategory(serverId, name) {
  const categoryId = newId();
  const next = messageDb.prepare(
    "SELECT COALESCE(MAX(position), -1) + 1 AS position FROM server_categories WHERE server_id = ?"
  ).get(serverId).position;
  messageDb.prepare(`
    INSERT INTO server_categories (category_id, server_id, name, position)
    VALUES (?, ?, ?, ?)
  `).run(categoryId, serverId, name, next);
  return getCategory(categoryId);
}

function getCategory(categoryId) {
  return messageDb.prepare(
    "SELECT category_id, server_id, name, position FROM server_categories WHERE category_id = ?"
  ).get(categoryId);
}

function listCategories(serverId) {
  return messageDb.prepare(`
    SELECT category_id, name, position
    FROM server_categories
    WHERE server_id = ?
    ORDER BY position, created_at
  `).all(serverId);
}

function countCategories(serverId) {
  return messageDb.prepare(
    "SELECT COUNT(*) AS total FROM server_categories WHERE server_id = ?"
  ).get(serverId).total;
}

function renameCategory(categoryId, name) {
  messageDb.prepare("UPDATE server_categories SET name = ? WHERE category_id = ?").run(name, categoryId);
}

function deleteCategory(categoryId) {
  messageDb.exec("BEGIN");
  try {
    messageDb.prepare("UPDATE server_channels SET category_id = NULL WHERE category_id = ?").run(categoryId);
    messageDb.prepare("DELETE FROM server_categories WHERE category_id = ?").run(categoryId);
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

// Accepts [{ categoryId, position }] so the caller can encode section ranks
// (with gaps where the uncategorized section sits).
function updateCategoryLayout(serverId, categoryPositions) {
  messageDb.exec("BEGIN");
  try {
    const update = messageDb.prepare(`
      UPDATE server_categories
      SET position = ?
      WHERE server_id = ? AND category_id = ?
    `);
    categoryPositions.forEach(({ categoryId, position }) => {
      update.run(position, serverId, categoryId);
    });
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

function countChannels(serverId, type = null) {
  if (type === "voice" || type === "text") {
    return messageDb.prepare(
      "SELECT COUNT(*) AS total FROM server_channels WHERE server_id = ? AND type = ?"
    ).get(serverId, type).total;
  }
  return messageDb.prepare(
    "SELECT COUNT(*) AS total FROM server_channels WHERE server_id = ?"
  ).get(serverId).total;
}

function renameChannel(channelId, name) {
  messageDb.prepare("UPDATE server_channels SET name = ? WHERE channel_id = ?").run(name, channelId);
}

// Channel names are stored already-normalized (lowercase, hyphenated), so an
// exact match is a case-insensitive duplicate. excludeChannelId lets a rename
// keep its own name.
function channelNameExists(serverId, name, excludeChannelId = null) {
  const row = messageDb.prepare(
    "SELECT channel_id FROM server_channels WHERE server_id = ? AND name = ? AND channel_id != ?"
  ).get(serverId, name, excludeChannelId || "");
  return Boolean(row);
}

function setChannelPrivacy(channelId, isPrivate) {
  messageDb.prepare("UPDATE server_channels SET is_private = ? WHERE channel_id = ?").run(isPrivate ? 1 : 0, channelId);
}

function setChannelSlowmode(channelId, seconds) {
  messageDb.prepare("UPDATE server_channels SET slowmode = ? WHERE channel_id = ?").run(Number(seconds) || 0, channelId);
}

function setChannelAutoDelete(channelId, seconds) {
  messageDb.prepare("UPDATE server_channels SET auto_delete_seconds = ? WHERE channel_id = ?").run(Number(seconds) || 0, channelId);
}

// When (UTC) the user last sent a message in this channel - for slowmode checks.
// Returns a SQLite datetime string ("YYYY-MM-DD HH:MM:SS") or null.
function getLastChannelMessageAt(channelId, senderId) {
  const row = messageDb.prepare(
    "SELECT created_at FROM server_messages WHERE channel_id = ? AND sender_id = ? ORDER BY rowid DESC LIMIT 1"
  ).get(channelId, senderId);
  return row ? row.created_at : null;
}

// The reported user's last `limit` messages in a channel (oldest→newest), for the
// admin report snapshot. Server messages are plaintext server-side; DMs are E2E
// and never readable here.
function getRecentUserChannelMessages(channelId, senderId, limit = 10) {
  if (!channelId || !senderId) return [];
  return messageDb.prepare(`
    SELECT content, created_at FROM server_messages
    WHERE channel_id = ? AND sender_id = ?
    ORDER BY rowid DESC
    LIMIT ?
  `).all(channelId, senderId, limit).reverse().map(decryptRow);
}

// Like the above but across EVERY channel in a server (joined via server_channels),
// so an "automated activity" report captures spam that's spread over channels -
// not just the one it was filed from. Includes each message's channel name.
function getRecentUserServerMessages(serverId, senderId, limit = 30) {
  if (!serverId || !senderId) return [];
  return messageDb.prepare(`
    SELECT sm.content, sm.created_at, sc.name AS channel_name
    FROM server_messages sm
    JOIN server_channels sc ON sc.channel_id = sm.channel_id
    WHERE sc.server_id = ? AND sm.sender_id = ?
    ORDER BY sm.rowid DESC
    LIMIT ?
  `).all(serverId, senderId, limit).reverse().map(decryptRow);
}

function deleteChannel(channelId) {
  messageDb.exec("BEGIN");
  try {
    messageDb.prepare(`
      DELETE FROM message_reactions
      WHERE message_id IN (SELECT message_id FROM server_messages WHERE channel_id = ?)
    `).run(channelId);
    messageDb.prepare("DELETE FROM server_messages WHERE channel_id = ?").run(channelId);
    messageDb.prepare("DELETE FROM channel_overwrites WHERE channel_id = ?").run(channelId);
    messageDb.prepare("DELETE FROM server_channels WHERE channel_id = ?").run(channelId);
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

// How many messages a channel holds - used to estimate purge time up front.
function countChannelMessages(channelId) {
  const row = messageDb.prepare("SELECT COUNT(*) AS n FROM server_messages WHERE channel_id = ?").get(channelId);
  return row ? Number(row.n) : 0;
}

// Wipe every message (and its reactions) in a channel but keep the channel.
// Batched so a channel with a huge backlog can't freeze the server.
async function purgeChannelMessages(channelId) {
  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN server_messages sm ON sm.message_id = mr.message_id
      WHERE sm.channel_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [channelId]);
  await deleteInBatches(`
    DELETE FROM server_messages WHERE rowid IN (
      SELECT rowid FROM server_messages WHERE channel_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [channelId]);
}

// ── Channel messages ─────────────────────────────────────────────────────────

function saveServerMessage({ channelId, senderId, content, replyToMessageId = null, ttlSeconds = 0, webhookId = null, webhookName = null }) {
  const messageId = newId();
  // Only honour a reply target that's a real message in this same channel.
  let replyTo = null;
  if (replyToMessageId) {
    const target = messageDb.prepare(
      "SELECT message_id FROM server_messages WHERE message_id = ? AND channel_id = ?"
    ).get(replyToMessageId, channelId);
    if (target) replyTo = target.message_id;
  }
  // Compute attachment-ness from the PLAINTEXT (before encrypting), then store the
  // (possibly encrypted) content. has_attachment lets the auto-delete sweeps find
  // attachment messages without scanning ciphertext.
  const hasAttachment = isAttachmentMarker(content);
  const storedContent = encryptContent(content);
  // Auto-delete: stamp the death time once if the sender has server auto-delete
  // on (the controller passes the TTL, e.g. 24h). No per-message timer.
  if (ttlSeconds > 0) {
    messageDb.prepare(`
      INSERT INTO server_messages (message_id, channel_id, sender_id, content, has_attachment, reply_to_message_id, webhook_id, webhook_name, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))
    `).run(messageId, channelId, senderId, storedContent, hasAttachment, replyTo, webhookId, webhookName, `+${ttlSeconds} seconds`);
  } else {
    messageDb.prepare(`
      INSERT INTO server_messages (message_id, channel_id, sender_id, content, has_attachment, reply_to_message_id, webhook_id, webhook_name)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(messageId, channelId, senderId, storedContent, hasAttachment, replyTo, webhookId, webhookName);
  }
  return getServerMessage(messageId);
}

const SERVER_MESSAGE_COLS =
  "rowid AS seq, message_id, channel_id, sender_id, content, reply_to_message_id, webhook_id, webhook_name, edited_at, created_at, expires_at, pinned_at, pinned_by, suppressed_embeds";

// Discord caps pins per channel; we match a sane limit.
const MAX_PINS_PER_CHANNEL = 50;

function getServerMessage(messageId) {
  return decryptRow(messageDb.prepare(`
    SELECT ${SERVER_MESSAGE_COLS}
    FROM server_messages
    WHERE message_id = ?
  `).get(messageId));
}

// Pin / unpin a server message. Returns { ok } or { ok:false, reason } when the
// channel is already at the pin cap. pinned_at drives newest-first ordering.
function pinServerMessage(messageId, pinnedBy) {
  const msg = messageDb.prepare(
    "SELECT channel_id, pinned_at FROM server_messages WHERE message_id = ?"
  ).get(messageId);
  if (!msg) return { ok: false, reason: "not_found" };
  if (msg.pinned_at) return { ok: true }; // already pinned - idempotent
  const count = messageDb.prepare(
    "SELECT COUNT(*) AS n FROM server_messages WHERE channel_id = ? AND pinned_at IS NOT NULL"
  ).get(msg.channel_id).n;
  if (count >= MAX_PINS_PER_CHANNEL) return { ok: false, reason: "limit" };
  messageDb.prepare(
    "UPDATE server_messages SET pinned_at = datetime('now'), pinned_by = ? WHERE message_id = ?"
  ).run(pinnedBy, messageId);
  return { ok: true };
}

function unpinServerMessage(messageId) {
  messageDb.prepare(
    "UPDATE server_messages SET pinned_at = NULL, pinned_by = NULL WHERE message_id = ?"
  ).run(messageId);
  return { ok: true };
}

// Pinned messages for a channel, newest-pinned first (skips expired).
function getPinnedServerMessages(channelId) {
  return messageDb.prepare(`
    SELECT ${SERVER_MESSAGE_COLS}
    FROM server_messages
    WHERE channel_id = ? AND pinned_at IS NOT NULL
      AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY pinned_at DESC, rowid DESC
    LIMIT ${MAX_PINS_PER_CHANNEL}
  `).all(channelId).map(decryptRow);
}

// Reap expired server messages (and their reactions) in capped batches. Returns
// { senderId, content } for any expiring attachment-marker messages so the caller
// can also delete the underlying media (verifying ownership via senderId). A single
// `cutoff` covers both collect and delete.
async function sweepExpiredServerMessages() {
  const cutoff = messageDb.prepare("SELECT datetime('now') AS t").get().t;
  // has_attachment is the flag set at write/backfill time; the typeof()=text branch
  // is a transitional fallback for legacy plaintext rows not yet backfilled. content
  // is decrypted so parseAttachmentRefs (which needs plaintext JSON) still works.
  const attachments = messageDb.prepare(`
    SELECT sender_id, content FROM server_messages
    WHERE expires_at IS NOT NULL AND expires_at <= ?
      AND (has_attachment = 1
           OR (typeof(content) = 'text' AND content LIKE '{%' AND content LIKE '%"_att"%'))
  `).all(cutoff).map((row) => ({ senderId: row.sender_id, content: decryptContent(row.content) }));

  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN server_messages sm ON sm.message_id = mr.message_id
      WHERE sm.expires_at IS NOT NULL AND sm.expires_at <= ?
      LIMIT ${DELETE_BATCH_SIZE})
  `, [cutoff]);
  await deleteInBatches(`
    DELETE FROM server_messages WHERE rowid IN (
      SELECT rowid FROM server_messages
      WHERE expires_at IS NOT NULL AND expires_at <= ?
      LIMIT ${DELETE_BATCH_SIZE})
  `, [cutoff]);

  return attachments;
}

// Per-channel auto-delete: in any channel with auto_delete_seconds set, reap
// every message older than that age (regardless of sender). Reported messages
// are unaffected - their content is snapshotted into admin.db at report time.
// Returns { senderId, content } for the attachment-marker messages reaped, for
// ownership-checked media cleanup.
async function sweepChannelAutoDelete() {
  const channels = messageDb
    .prepare("SELECT channel_id, auto_delete_seconds FROM server_channels WHERE auto_delete_seconds > 0")
    .all();
  const attachments = [];
  for (const channel of channels) {
    // Snap the age cutoff to one timestamp so collect + delete see the same rows.
    const cutoff = messageDb.prepare("SELECT datetime('now', ?) AS t").get(`-${Number(channel.auto_delete_seconds)} seconds`).t;
    for (const row of messageDb.prepare(`
      SELECT sender_id, content FROM server_messages
      WHERE channel_id = ? AND created_at < ?
        AND (has_attachment = 1
             OR (typeof(content) = 'text' AND content LIKE '{%' AND content LIKE '%"_att"%'))
    `).all(channel.channel_id, cutoff)) {
      attachments.push({ senderId: row.sender_id, content: decryptContent(row.content) });
    }
    await deleteInBatches(`
      DELETE FROM message_reactions WHERE rowid IN (
        SELECT mr.rowid FROM message_reactions mr
        JOIN server_messages sm ON sm.message_id = mr.message_id
        WHERE sm.channel_id = ? AND sm.created_at < ?
        LIMIT ${DELETE_BATCH_SIZE})
    `, [channel.channel_id, cutoff]);
    await deleteInBatches(`
      DELETE FROM server_messages WHERE rowid IN (
        SELECT rowid FROM server_messages
        WHERE channel_id = ? AND created_at < ?
        LIMIT ${DELETE_BATCH_SIZE})
    `, [channel.channel_id, cutoff]);
  }
  return attachments;
}

// Ordering and pagination use the monotonic rowid, so messages in the same
// second always keep their true insertion order (created_at is second-precision).
function getChannelMessages(channelId, limit, beforeSeq) {
  if (beforeSeq) {
    return messageDb.prepare(`
      SELECT ${SERVER_MESSAGE_COLS}
      FROM server_messages
      WHERE channel_id = ? AND rowid < ?
        AND (expires_at IS NULL OR expires_at > datetime('now'))
      ORDER BY rowid DESC
      LIMIT ?
    `).all(channelId, beforeSeq, limit).reverse().map(decryptRow);
  }
  return messageDb.prepare(`
    SELECT ${SERVER_MESSAGE_COLS}
    FROM server_messages
    WHERE channel_id = ?
      AND (expires_at IS NULL OR expires_at > datetime('now'))
    ORDER BY rowid DESC
    LIMIT ?
  `).all(channelId, limit).reverse().map(decryptRow);
}

function deleteServerMessage(messageId) {
  // Reactions live in the shared message_reactions table - clean them up too.
  messageDb.prepare("DELETE FROM message_reactions WHERE message_id = ?").run(messageId);
  messageDb.prepare("DELETE FROM server_messages WHERE message_id = ?").run(messageId);
}

// Author edits their own message text; stamps edited_at. Returns the fresh row, or
// null if nothing matched (wrong id / not the author).
function updateServerMessageContent({ messageId, senderId, content }) {
  // Editing changes the content, so previously-suppressed embed indices are stale.
  // Re-derive has_attachment from the new plaintext and re-encrypt the stored copy.
  const info = messageDb.prepare(
    "UPDATE server_messages SET content = ?, has_attachment = ?, edited_at = datetime('now'), suppressed_embeds = NULL WHERE message_id = ? AND sender_id = ?"
  ).run(encryptContent(content), isAttachmentMarker(content), messageId, senderId);
  if (!info.changes) return null;
  return getServerMessage(messageId);
}

// Add an embed index to a server message's suppressed set (dedup + clamp 0..1).
// Returns the new array, or null if the message is gone. The caller authorizes
// (author or DELETE_MESSAGES); this just records the suppression.
function addSuppressedEmbed(messageId, index) {
  const row = messageDb.prepare("SELECT suppressed_embeds FROM server_messages WHERE message_id = ?").get(messageId);
  if (!row) return null;
  let list = [];
  try { list = JSON.parse(row.suppressed_embeds || "[]"); } catch { list = []; }
  const idx = Math.max(0, Math.min(1, Math.trunc(Number(index))));
  if (!Number.isFinite(idx)) return list;
  if (!list.includes(idx)) list.push(idx);
  list.sort((a, b) => a - b);
  messageDb.prepare("UPDATE server_messages SET suppressed_embeds = ? WHERE message_id = ?").run(JSON.stringify(list), messageId);
  return list;
}

// ── Webhooks ─────────────────────────────────────────────────────────────────

const MAX_WEBHOOKS_PER_CHANNEL = 5;

function countChannelWebhooks(channelId) {
  return messageDb.prepare(
    "SELECT COUNT(*) AS total FROM server_webhooks WHERE channel_id = ?"
  ).get(channelId).total;
}

function createWebhook({ serverId, channelId, name, createdBy }) {
  const webhookId = newId();
  const token = crypto.randomBytes(32).toString("base64url");
  messageDb.prepare(`
    INSERT INTO server_webhooks (webhook_id, server_id, channel_id, token, name, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(webhookId, serverId, channelId, token, name, createdBy);
  return getWebhook(webhookId);
}

function getWebhook(webhookId) {
  return messageDb.prepare(
    "SELECT * FROM server_webhooks WHERE webhook_id = ?"
  ).get(webhookId) || null;
}

function listChannelWebhooks(channelId) {
  return messageDb.prepare(
    "SELECT * FROM server_webhooks WHERE channel_id = ? ORDER BY created_at"
  ).all(channelId);
}

function updateWebhookName(webhookId, name) {
  messageDb.prepare("UPDATE server_webhooks SET name = ? WHERE webhook_id = ?").run(name, webhookId);
  return getWebhook(webhookId);
}

function updateWebhookAvatar(webhookId, avatarKey, avatarMime) {
  messageDb.prepare(
    "UPDATE server_webhooks SET avatar_key = ?, avatar_mime = ? WHERE webhook_id = ?"
  ).run(avatarKey, avatarMime, webhookId);
  return getWebhook(webhookId);
}

function deleteWebhook(webhookId) {
  messageDb.prepare("DELETE FROM server_webhooks WHERE webhook_id = ?").run(webhookId);
}

// Drop every webhook in a channel (used when the channel itself is deleted).
// Returns the rows first so the caller can clean up their B2 avatars.
function deleteChannelWebhooks(channelId) {
  const rows = listChannelWebhooks(channelId);
  messageDb.prepare("DELETE FROM server_webhooks WHERE channel_id = ?").run(channelId);
  return rows;
}

// ── Roles ────────────────────────────────────────────────────────────────────

function createRole({ serverId, name, color, permissions, hoist = false }) {
  const roleId = newId();
  const next = messageDb.prepare(
    "SELECT COALESCE(MAX(position), -1) + 1 AS position FROM server_roles WHERE server_id = ?"
  ).get(serverId).position;
  messageDb.prepare(`
    INSERT INTO server_roles (role_id, server_id, name, color, permissions, position, hoist)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(roleId, serverId, name, color, normalizeMergedPermissions(permissions), next, hoist ? 1 : 0);
  return getRole(roleId);
}

function getRole(roleId) {
  return messageDb.prepare(
    "SELECT role_id, server_id, name, color, permissions, position, hoist FROM server_roles WHERE role_id = ?"
  ).get(roleId);
}

function listRoles(serverId) {
  return messageDb.prepare(`
    SELECT role_id, name, color, permissions, position, hoist
    FROM server_roles
    WHERE server_id = ?
    ORDER BY position, created_at
  `).all(serverId);
}

// Persist a new role order. Accepts an array of role ids (top → bottom); each is
// written its index as `position`. Only ids belonging to the server are touched.
function reorderRoles(serverId, roleIds) {
  messageDb.exec("BEGIN");
  try {
    const update = messageDb.prepare(
      "UPDATE server_roles SET position = ? WHERE server_id = ? AND role_id = ?"
    );
    roleIds.forEach((roleId, index) => update.run(index, serverId, roleId));
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

function countRoles(serverId) {
  return messageDb.prepare(
    "SELECT COUNT(*) AS total FROM server_roles WHERE server_id = ?"
  ).get(serverId).total;
}

function isEveryoneRoleId(roleId) {
  return roleId === EVERYONE_ROLE_ID;
}

function isEveryoneRoleName(name) {
  return String(name || "").trim().toLowerCase() === EVERYONE_ROLE_NAME;
}

function updateRole(roleId, { name, color, permissions, hoist }) {
  const normalizedPermissions = normalizeMergedPermissions(permissions);
  // hoist is optional - leave it untouched when the caller doesn't pass it.
  if (hoist === undefined) {
    messageDb.prepare(`
      UPDATE server_roles
      SET name = ?, color = ?, permissions = ?
      WHERE role_id = ?
    `).run(name, color, normalizedPermissions, roleId);
    return;
  }
  messageDb.prepare(`
    UPDATE server_roles
    SET name = ?, color = ?, permissions = ?, hoist = ?
    WHERE role_id = ?
  `).run(name, color, normalizedPermissions, hoist ? 1 : 0, roleId);
}

function deleteRole(roleId) {
  messageDb.exec("BEGIN");
  try {
    messageDb.prepare("DELETE FROM server_member_roles WHERE role_id = ?").run(roleId);
    messageDb.prepare("DELETE FROM server_roles WHERE role_id = ?").run(roleId);
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

function setMemberRoles(serverId, userId, roleIds) {
  messageDb.exec("BEGIN");
  try {
    messageDb.prepare("DELETE FROM server_member_roles WHERE server_id = ? AND user_id = ?").run(serverId, userId);
    const insert = messageDb.prepare(
      "INSERT OR IGNORE INTO server_member_roles (server_id, user_id, role_id) VALUES (?, ?, ?)"
    );
    roleIds.forEach((roleId) => insert.run(serverId, userId, roleId));
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

function getMemberRoleIds(serverId, userId) {
  return messageDb.prepare(
    "SELECT role_id FROM server_member_roles WHERE server_id = ? AND user_id = ?"
  ).all(serverId, userId).map((row) => row.role_id);
}

function getAllMemberRoles(serverId) {
  return messageDb.prepare(
    "SELECT user_id, role_id FROM server_member_roles WHERE server_id = ?"
  ).all(serverId);
}

// ── Role hierarchy ───────────────────────────────────────────────────────────
// position 0 is the highest custom role (reorderRoles writes top→bottom indices);
// @everyone sits below all of them. A member's "top" rank is the lowest position
// among their custom roles, or +Infinity when they only have @everyone.
function getMemberTopRolePosition(serverId, userId) {
  const row = messageDb.prepare(`
    SELECT MIN(r.position) AS p
    FROM server_member_roles mr
    JOIN server_roles r ON r.role_id = mr.role_id
    WHERE mr.server_id = ? AND mr.user_id = ?
  `).get(serverId, userId);
  return row && row.p !== null && row.p !== undefined ? row.p : Number.POSITIVE_INFINITY;
}

// Can `actor` moderate (ban/kick/timeout/etc.) `target`? Owner outranks everyone
// and can never be targeted; otherwise the actor's highest role must sit strictly
// above the target's highest role (lower position number = higher).
function canModerateMember(serverId, actorId, targetId) {
  const server = getServer(serverId);
  if (!server || actorId === targetId) return false;
  if (server.owner_id === targetId) return false;
  if (server.owner_id === actorId) return true;
  return getMemberTopRolePosition(serverId, actorId) < getMemberTopRolePosition(serverId, targetId);
}

// Can `actor` edit/delete a custom role at `rolePosition`? Only roles strictly
// below their highest (owner bypasses). Stops editing your own highest role.
function canManageRolePosition(serverId, actorId, rolePosition) {
  const server = getServer(serverId);
  if (server && server.owner_id === actorId) return true;
  return rolePosition > getMemberTopRolePosition(serverId, actorId);
}

// ── Permissions ──────────────────────────────────────────────────────────────

function getMemberPermissions(serverId, userId) {
  const server = getServer(serverId);
  if (!server) return 0;
  if (server.owner_id === userId) return ALL_PERMISSIONS;
  if (!isMember(serverId, userId)) return 0;

  const rows = messageDb.prepare(`
    SELECT r.permissions
    FROM server_member_roles mr
    JOIN server_roles r ON r.role_id = mr.role_id
    WHERE mr.server_id = ? AND mr.user_id = ?
  `).all(serverId, userId);

  let mask = getEveryonePermissions(serverId);
  rows.forEach((row) => {
    mask |= normalizeMergedPermissions(row.permissions);
  });
  if (mask & PERMISSIONS.ADMINISTRATOR) return ALL_PERMISSIONS;
  return mask;
}

function hasPermission(mask, bit) {
  return (mask & bit) === bit;
}

// ── Per-channel permission overwrites ───────────────────────────────────────

function getChannelOverwrites(channelId) {
  return messageDb.prepare(
    "SELECT target_type, target_id, allow, deny FROM channel_overwrites WHERE channel_id = ?"
  ).all(channelId).map((row) => ({ ...row, ...normalizeMergedOverwrite(row.allow, row.deny) }));
}

// Upsert one target's overwrite. allow/deny are masked to the overridable bits.
// If both end up 0 the row is removed (back to pure inherit).
function setChannelOverwrite(channelId, targetType, targetId, allow, deny) {
  const normalized = normalizeMergedOverwrite(allow, deny);
  const a = normalized.allow & CHANNEL_OVERWRITE_PERMISSIONS;
  const d = normalized.deny & CHANNEL_OVERWRITE_PERMISSIONS & ~a; // allow wins over deny for the same bit
  if (a === 0 && d === 0) {
    messageDb.prepare(
      "DELETE FROM channel_overwrites WHERE channel_id = ? AND target_type = ? AND target_id = ?"
    ).run(channelId, targetType, targetId);
    return;
  }
  messageDb.prepare(`
    INSERT INTO channel_overwrites (channel_id, target_type, target_id, allow, deny)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(channel_id, target_type, target_id) DO UPDATE SET allow = excluded.allow, deny = excluded.deny
  `).run(channelId, targetType, targetId, a, d);
}

function deleteChannelOverwrite(channelId, targetType, targetId) {
  messageDb.prepare(
    "DELETE FROM channel_overwrites WHERE channel_id = ? AND target_type = ? AND target_id = ?"
  ).run(channelId, targetType, targetId);
}

// Effective permission mask for a user IN a specific channel. Layers per-channel
// overwrites on top of server permissions, Discord-style:
//   base (server roles + @everyone) → @everyone overwrite → role overwrites
//   (combined) → member overwrite. Owner/Administrator bypass all overwrites.
// With NO overwrites this returns the same effective access as before this
// feature existed (server perms, plus view gated by is_private), so existing
// channels behave identically.
function channelPermissionsFor(serverId, channel, userId) {
  const server = getServer(serverId);
  if (!server || !channel) return 0;
  if (server.owner_id === userId) return ALL_PERMISSIONS;
  if (!isMember(serverId, userId)) return 0;

  let base = getMemberPermissions(serverId, userId);
  if (base & PERMISSIONS.ADMINISTRATOR) return ALL_PERMISSIONS; // admin bypasses overwrites

  // Channel-level defaults: everyone may view + send unless overridden.
  base |= PERMISSIONS.VIEW_CHANNEL | PERMISSIONS.SEND_MESSAGES;
  // Voice channels: everyone may join, speak, and share screen/camera by default.
  if (channel.type === "voice") base |= PERMISSIONS.CONNECT | PERMISSIONS.SPEAK | PERMISSIONS.VIDEO;
  // Legacy privacy flag behaves like @everyone being denied View Channel.
  if (channel.is_private) base &= ~PERMISSIONS.VIEW_CHANNEL;

  const overwrites = getChannelOverwrites(channel.channel_id);
  if (!overwrites.length) return base;
  const byKey = new Map(overwrites.map((o) => [`${o.target_type}:${o.target_id}`, o]));

  // 1. @everyone
  const everyone = byKey.get(`role:${EVERYONE_ROLE_ID}`);
  if (everyone) base = (base & ~everyone.deny) | everyone.allow;

  // 2. roles the member has (all denies, then all allows)
  let roleDeny = 0;
  let roleAllow = 0;
  for (const roleId of getMemberRoleIds(serverId, userId)) {
    const ow = byKey.get(`role:${roleId}`);
    if (ow) { roleDeny |= ow.deny; roleAllow |= ow.allow; }
  }
  base = (base & ~roleDeny) | roleAllow;

  // 3. member-specific overwrite
  const member = byKey.get(`member:${userId}`);
  if (member) base = (base & ~member.deny) | member.allow;

  return base;
}

// Every text channel (across the user's servers) the user can VIEW, with its
// server context. Powers global search so message/channel results can never leak
// a private channel or a server the user was kicked from. Built from existing
// siblings (listServersForUser only returns servers you're a member of;
// channelPermissionsFor returns 0 for non-members) - no controller dependency.
function getViewableTextChannelsForUser(userId) {
  const out = [];
  for (const server of listServersForUser(userId)) {
    for (const channel of listChannels(server.server_id)) {
      if (channel.type !== "text") continue;
      const mask = channelPermissionsFor(server.server_id, channel, userId);
      if (!hasPermission(mask, PERMISSIONS.VIEW_CHANNEL)) continue;
      out.push({
        channelId: channel.channel_id,
        channelName: channel.name,
        serverId: server.server_id,
        serverName: server.name,
      });
    }
  }
  return out;
}

// Search server-channel message text within the given channel ids (the caller
// passes only channels the user may view). `query` is matched literally - % _ \
// are escaped so user input can't inject LIKE wildcards. Skips expired rows and
// attachment-marker messages. Newest first, capped.
// Most-recent rows scanned per query. Content is encrypted at rest, so matching
// can't happen in SQL (no LIKE on ciphertext) - we decrypt + substring-match in JS.
// This cap bounds the work; searches reach the most recent ~SEARCH_SCAN_CAP messages
// across the given channels rather than the entire history.
const SEARCH_SCAN_CAP = 2000;

function searchMessagesInChannels(channelIds, query, limit = 30) {
  if (!Array.isArray(channelIds) || channelIds.length === 0) return [];
  const needle = String(query || "").toLowerCase();
  if (!needle) return [];
  // Each id binds as a SQL variable; cap to stay well under SQLite's limit.
  const ids = channelIds.slice(0, 800);
  const placeholders = ids.map(() => "?").join(",");
  // Candidates: non-expired, non-attachment (has_attachment for new rows; the
  // typeof()=text LIKE branch excludes legacy plaintext attachment markers too).
  const rows = messageDb.prepare(`
    SELECT message_id, channel_id, sender_id, content, created_at
    FROM server_messages
    WHERE channel_id IN (${placeholders})
      AND (expires_at IS NULL OR expires_at > datetime('now'))
      AND has_attachment = 0
      AND NOT (typeof(content) = 'text' AND content LIKE '{%' AND content LIKE '%"_att"%')
    ORDER BY rowid DESC
    LIMIT ${SEARCH_SCAN_CAP}
  `).all(...ids);
  const out = [];
  for (const row of rows) {
    const content = decryptContent(row.content);
    if (content && content.toLowerCase().includes(needle)) {
      row.content = content;
      out.push(row);
      if (out.length >= limit) break;
    }
  }
  return out;
}

// ── Invites ──────────────────────────────────────────────────────────────────

// ttlMs === null → a permanent invite (far-future expiry). maxUses 0 = unlimited.
function createInvite(serverId, creatorId, { ttlMs = INVITE_TTL_MS, maxUses = 0 } = {}) {
  const code = newInviteCode(inviteCodeLengthForTtl(ttlMs));
  const expiresAt = ttlMs === null
    ? PERMANENT_EXPIRES_AT
    : new Date(Date.now() + ttlMs).toISOString();
  messageDb.prepare(`
    INSERT INTO server_invites (code, server_id, creator_id, expires_at, max_uses)
    VALUES (?, ?, ?, ?, ?)
  `).run(code, serverId, creatorId, expiresAt, Math.max(0, Math.floor(Number(maxUses) || 0)));
  return getInvite(code);
}

// Record that a user joined through an invite (idempotent), for the "who was
// invited" list. Kept even after the user leaves, until the invite is deleted.
function recordInviteUse(code, serverId, userId) {
  messageDb.prepare(`
    INSERT OR IGNORE INTO server_invite_uses (code, server_id, user_id)
    VALUES (?, ?, ?)
  `).run(code, serverId, userId);
}

// Internal user ids of everyone who joined via this invite, newest first.
function getInviteUserIds(code) {
  return messageDb.prepare(
    "SELECT user_id FROM server_invite_uses WHERE code = ? ORDER BY joined_at DESC"
  ).all(code).map((row) => row.user_id);
}

// Count a user's still-valid invites for one server. Expired codes are excluded
// (expires_at in the future only), so they no longer count against the cap.
function countActiveInvitesByCreator(serverId, creatorId) {
  return messageDb.prepare(`
    SELECT COUNT(*) AS total
    FROM server_invites
    WHERE server_id = ? AND creator_id = ? AND expires_at > ?
  `).get(serverId, creatorId, new Date().toISOString()).total;
}

function getInvite(code) {
  return messageDb.prepare(
    "SELECT code, server_id, creator_id, uses, max_uses, created_at, expires_at FROM server_invites WHERE code = ?"
  ).get(code);
}

function listInvites(serverId) {
  return messageDb.prepare(`
    SELECT i.code, i.creator_id, i.uses, i.max_uses, i.created_at, i.expires_at,
           (SELECT COUNT(*) FROM server_invite_uses u WHERE u.code = i.code) AS invited_count
    FROM server_invites i
    WHERE i.server_id = ?
    ORDER BY i.created_at DESC
  `).all(serverId);
}

function deleteInvite(code) {
  messageDb.prepare("DELETE FROM server_discovery WHERE invite_code = ?").run(code);
  messageDb.prepare("DELETE FROM server_invites WHERE code = ?").run(code);
  messageDb.prepare("DELETE FROM server_invite_uses WHERE code = ?").run(code);
}

// Revoke every invite for a server at once. Returns how many were removed.
function deleteInvitesForServer(serverId) {
  messageDb.prepare("DELETE FROM server_discovery WHERE server_id = ?").run(serverId);
  const removed = messageDb.prepare("DELETE FROM server_invites WHERE server_id = ?").run(serverId).changes || 0;
  messageDb.prepare("DELETE FROM server_invite_uses WHERE server_id = ?").run(serverId);
  return removed;
}

function deleteExpiredInvites() {
  const now = new Date().toISOString();
  messageDb.prepare(`
    DELETE FROM server_discovery
    WHERE invite_code IN (SELECT code FROM server_invites WHERE expires_at < ?)
  `).run(now);
  messageDb.prepare(
    "DELETE FROM server_invites WHERE expires_at < ?"
  ).run(now);
}

function incrementInviteUses(code) {
  messageDb.prepare("UPDATE server_invites SET uses = uses + 1 WHERE code = ?").run(code);
}

// Discovery servers are manually curated from the admin panel. Each row owns a
// dedicated permanent invite code, so users can join through the normal invite
// flow without bypassing bans, limits, or invite accounting.
function addServerToDiscovery(serverId, inviteCode, addedBy = "admin", about = "") {
  messageDb.prepare(`
    INSERT INTO server_discovery (server_id, invite_code, added_by, about)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(server_id) DO UPDATE SET
      invite_code = excluded.invite_code,
      added_by = excluded.added_by,
      about = excluded.about
  `).run(serverId, inviteCode, addedBy, String(about || "").trim());
  return getDiscoveryEntry(serverId);
}

function getDiscoveryEntry(serverId) {
  return messageDb.prepare(`
    SELECT d.server_id, d.invite_code, d.added_by, d.about, d.created_at,
           s.owner_id, s.name, s.icon_mime, s.banner_mime, s.created_at AS server_created_at, s.updated_at,
           i.uses, i.max_uses, i.expires_at
    FROM server_discovery d
    JOIN servers s ON s.server_id = d.server_id
    JOIN server_invites i ON i.code = d.invite_code
    WHERE d.server_id = ?
  `).get(serverId);
}

function listDiscoveryServers(query = "", limit = 30) {
  const cappedLimit = Math.max(1, Math.min(50, Number(limit) || 30));
  const cleanQuery = String(query || "").trim().toLowerCase().slice(0, 80);
  const params = [new Date().toISOString()];
  let where = "WHERE i.expires_at > ? AND (i.max_uses = 0 OR i.uses < i.max_uses) AND b.server_id IS NULL";
  if (cleanQuery) {
    where += " AND (lower(s.name) LIKE ? OR lower(s.server_id) LIKE ?)";
    const like = `%${cleanQuery}%`;
    params.push(like, like);
  }
  params.push(cappedLimit);
  return messageDb.prepare(`
    SELECT d.server_id, d.invite_code, d.added_by, d.about, d.created_at,
           s.owner_id, s.name, s.icon_mime, s.banner_mime, s.created_at AS server_created_at, s.updated_at,
           i.uses, i.max_uses, i.expires_at,
           (SELECT COUNT(*) FROM server_members m WHERE m.server_id = s.server_id) AS member_count
    FROM server_discovery d
    JOIN servers s ON s.server_id = d.server_id
    JOIN server_invites i ON i.code = d.invite_code
    LEFT JOIN server_discovery_blocks b ON b.server_id = d.server_id
    ${where}
    ORDER BY datetime(d.created_at) DESC, lower(s.name) ASC
    LIMIT ?
  `).all(...params);
}

function removeServerFromDiscovery(serverId) {
  const entry = messageDb.prepare("SELECT invite_code FROM server_discovery WHERE server_id = ?").get(serverId);
  messageDb.prepare("DELETE FROM server_discovery WHERE server_id = ?").run(serverId);
  return entry || null;
}

function submitDiscoveryApplication(serverId, requesterId, about) {
  messageDb.prepare(`
    INSERT INTO server_discovery_applications (server_id, requester_id, about, status, reviewed_by, reviewed_at, review_note, created_at, updated_at)
    VALUES (?, ?, ?, 'pending', NULL, NULL, NULL, datetime('now'), datetime('now'))
    ON CONFLICT(server_id) DO UPDATE SET
      requester_id = excluded.requester_id,
      about = excluded.about,
      status = 'pending',
      reviewed_by = NULL,
      reviewed_at = NULL,
      review_note = NULL,
      updated_at = datetime('now')
  `).run(serverId, requesterId, String(about || "").trim());
  return getDiscoveryApplication(serverId);
}

function getDiscoveryApplication(serverId) {
  return messageDb.prepare(`
    SELECT a.server_id, a.requester_id, a.about, a.status, a.reviewed_by, a.reviewed_at, a.review_note,
           a.created_at, a.updated_at, s.name, s.icon_mime, s.banner_mime, s.updated_at AS server_updated_at
    FROM server_discovery_applications a
    JOIN servers s ON s.server_id = a.server_id
    WHERE a.server_id = ?
  `).get(serverId);
}

function listDiscoveryApplications(status = "") {
  const cleanStatus = String(status || "").trim().toLowerCase();
  const params = [];
  let where = "";
  if (cleanStatus) {
    where = "WHERE a.status = ?";
    params.push(cleanStatus);
  }
  return messageDb.prepare(`
    SELECT a.server_id, a.requester_id, a.about, a.status, a.reviewed_by, a.reviewed_at, a.review_note,
           a.created_at, a.updated_at, s.name, s.icon_mime, s.banner_mime, s.updated_at AS server_updated_at,
           d.invite_code, b.created_at AS blocked_at
    FROM server_discovery_applications a
    JOIN servers s ON s.server_id = a.server_id
    LEFT JOIN server_discovery d ON d.server_id = a.server_id
    LEFT JOIN server_discovery_blocks b ON b.server_id = a.server_id
    ${where}
    ORDER BY CASE a.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
             datetime(a.updated_at) DESC
  `).all(...params);
}

function reviewDiscoveryApplication(serverId, status, reviewedBy, note = "") {
  messageDb.prepare(`
    UPDATE server_discovery_applications
    SET status = ?, reviewed_by = ?, reviewed_at = datetime('now'), review_note = ?, updated_at = datetime('now')
    WHERE server_id = ?
  `).run(status, reviewedBy, String(note || "").trim(), serverId);
  return getDiscoveryApplication(serverId);
}

function blockServerFromDiscovery(serverId, bannedBy, reason = "") {
  messageDb.prepare(`
    INSERT INTO server_discovery_blocks (server_id, banned_by, reason)
    VALUES (?, ?, ?)
    ON CONFLICT(server_id) DO UPDATE SET
      banned_by = excluded.banned_by,
      reason = excluded.reason,
      created_at = datetime('now')
  `).run(serverId, bannedBy, String(reason || "").trim());
  const entry = removeServerFromDiscovery(serverId);
  if (entry?.invite_code) deleteInvite(entry.invite_code);
  reviewDiscoveryApplication(serverId, "denied", bannedBy, reason || "Blocked from discovery.");
  return getDiscoveryBlock(serverId);
}

function unblockServerFromDiscovery(serverId) {
  messageDb.prepare("DELETE FROM server_discovery_blocks WHERE server_id = ?").run(serverId);
}

function getDiscoveryBlock(serverId) {
  return messageDb.prepare(`
    SELECT b.server_id, b.banned_by, b.reason, b.created_at, s.name
    FROM server_discovery_blocks b
    LEFT JOIN servers s ON s.server_id = b.server_id
    WHERE b.server_id = ?
  `).get(serverId);
}

function isDiscoveryBlocked(serverId) {
  return Boolean(messageDb.prepare("SELECT 1 FROM server_discovery_blocks WHERE server_id = ?").get(serverId));
}

function listDiscoveryBlocks() {
  return messageDb.prepare(`
    SELECT b.server_id, b.banned_by, b.reason, b.created_at, s.name
    FROM server_discovery_blocks b
    LEFT JOIN servers s ON s.server_id = b.server_id
    ORDER BY datetime(b.created_at) DESC
  `).all();
}

// ── Bans ─────────────────────────────────────────────────────────────────────

function addBan(serverId, userId, bannedBy, reason) {
  messageDb.prepare(`
    INSERT OR IGNORE INTO server_bans (server_id, user_id, banned_by, reason)
    VALUES (?, ?, ?, ?)
  `).run(serverId, userId, bannedBy, reason);
}

function removeBan(serverId, userId) {
  messageDb.prepare("DELETE FROM server_bans WHERE server_id = ? AND user_id = ?").run(serverId, userId);
}

function isBanned(serverId, userId) {
  return Boolean(messageDb.prepare(
    "SELECT 1 FROM server_bans WHERE server_id = ? AND user_id = ?"
  ).get(serverId, userId));
}

function listBans(serverId) {
  return messageDb.prepare(
    "SELECT user_id, banned_by, reason, created_at FROM server_bans WHERE server_id = ? ORDER BY created_at DESC"
  ).all(serverId);
}

// ── AutoMod ────────────────────────────────────────────────────────────────────
// One JSON config blob per server. Returns the raw string (or null); the caller
// parses + applies defaults so the schema can evolve without touching storage.
function getAutomodConfigRaw(serverId) {
  const row = messageDb.prepare("SELECT config FROM server_automod WHERE server_id = ?").get(serverId);
  return row ? row.config : null;
}

function setAutomodConfigRaw(serverId, configJson) {
  messageDb.prepare(`
    INSERT INTO server_automod (server_id, config, updated_at)
    VALUES (?, ?, datetime('now'))
    ON CONFLICT(server_id) DO UPDATE SET config = excluded.config, updated_at = datetime('now')
  `).run(serverId, configJson);
}

// ── Account deletion ───────────────────────────────────────────────────────────

// Servers this user owns (their B2 icon + banner keys included so the caller can delete them).
function listOwnedServers(userId) {
  return messageDb.prepare(
    "SELECT server_id, icon_key, banner_key FROM servers WHERE owner_id = ?"
  ).all(userId);
}

// Purge every trace of a user from the shared data.db, atomically. Covers DMs in
// both directions (so the copy in anyone else's DMs goes too), reactions the user
// placed or received, conversation rows, friendships, blocks, server membership +
// roles, the server messages they authored, and the invites/bans they created.
//
// NOTE: servers the user OWNS are handled separately by the caller via
// deleteServerCascade() (those wipe the whole server, not just this user's rows).
async function deleteAllUserData(userId) {
  // ── Potentially-unbounded tables: batched (a user could have millions of DMs) ──
  // DM reactions on any message in a conversation involving the user.
  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN messages m ON m.message_id = mr.message_id
      WHERE m.sender_id = ? OR m.receiver_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [userId, userId]);
  // Reactions the user placed anywhere (DM or server messages).
  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT rowid FROM message_reactions WHERE user_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [userId]);
  // Reactions on server messages the user authored.
  await deleteInBatches(`
    DELETE FROM message_reactions WHERE rowid IN (
      SELECT mr.rowid FROM message_reactions mr
      JOIN server_messages sm ON sm.message_id = mr.message_id
      WHERE sm.sender_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [userId]);
  // The DMs themselves - both sent and received (this is the big one).
  await deleteInBatches(`
    DELETE FROM messages WHERE rowid IN (
      SELECT rowid FROM messages WHERE sender_id = ? OR receiver_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [userId, userId]);
  // Server messages the user authored (in servers they don't own).
  await deleteInBatches(`
    DELETE FROM server_messages WHERE rowid IN (
      SELECT rowid FROM server_messages WHERE sender_id = ? LIMIT ${DELETE_BATCH_SIZE})
  `, [userId]);

  // ── Bounded rows (limited per user): one quick transaction is fine. ──
  messageDb.exec("BEGIN");
  try {
    messageDb.prepare("DELETE FROM dm_conversations WHERE user_id = ? OR partner_id = ?").run(userId, userId);
    messageDb.prepare("DELETE FROM friendships WHERE requester_id = ? OR addressee_id = ?").run(userId, userId);
    messageDb.prepare("DELETE FROM user_blocks WHERE blocker_id = ? OR blocked_id = ?").run(userId, userId);
    messageDb.prepare("DELETE FROM server_member_roles WHERE user_id = ?").run(userId);
    messageDb.prepare("DELETE FROM server_members WHERE user_id = ?").run(userId);
    messageDb.prepare("DELETE FROM server_privacy WHERE user_id = ?").run(userId);
    // Per-member channel overwrites across every server, so a deleted account
    // never lingers as "unknown member" in any channel's permission list.
    messageDb.prepare("DELETE FROM channel_overwrites WHERE target_type = 'member' AND target_id = ?").run(userId);
    messageDb.prepare("DELETE FROM server_invites WHERE creator_id = ?").run(userId);
    messageDb.prepare("DELETE FROM server_bans WHERE user_id = ? OR banned_by = ?").run(userId, userId);
    messageDb.exec("COMMIT");
  } catch (error) {
    messageDb.exec("ROLLBACK");
    throw error;
  }
}

module.exports = {
  PERMISSIONS,
  ALL_PERMISSIONS,
  CHANNEL_OVERWRITE_PERMISSIONS,
  getChannelOverwrites,
  normalizeMergedPermissions,
  setChannelOverwrite,
  deleteChannelOverwrite,
  channelPermissionsFor,
  DEFAULT_EVERYONE_PERMISSIONS,
  EVERYONE_ROLE_ID,
  EVERYONE_ROLE_NAME,
  MAX_SERVERS_PER_USER,
  MAX_SERVER_NAME_LENGTH,
  MAX_CHANNEL_NAME_LENGTH,
  MAX_CATEGORY_NAME_LENGTH,
  MAX_ROLE_NAME_LENGTH,
  MAX_NICKNAME_LENGTH,
  MAX_TEXT_CHANNELS_PER_SERVER,
  MAX_VOICE_CHANNELS_PER_SERVER,
  MAX_CATEGORIES_PER_SERVER,
  MAX_ROLES_PER_SERVER,
  MAX_INVITES_PER_USER_PER_SERVER,
  addBan,
  addServerToDiscovery,
  blockServerFromDiscovery,
  getAutomodConfigRaw,
  setAutomodConfigRaw,
  addMember,
  countActiveInvitesByCreator,
  countCategories,
  countChannels,
  countMembers,
  countRoles,
  countServersForUser,
  countAllServers,
  deleteAllUserData,
  listOwnedServers,
  createCategory,
  createChannel,
  createInvite,
  createRole,
  createServer,
  channelNameExists,
  deleteCategory,
  deleteChannel,
  deleteExpiredInvites,
  deleteInvite,
  deleteInvitesForServer,
  deleteRole,
  deleteServerCascade,
  deleteServerMessage,
  updateServerMessageContent,
  addSuppressedEmbed,
  pinServerMessage,
  unpinServerMessage,
  getPinnedServerMessages,
  purgeChannelMessages,
  countChannelMessages,
  MAX_WEBHOOKS_PER_CHANNEL,
  countChannelWebhooks,
  createWebhook,
  getWebhook,
  listChannelWebhooks,
  updateWebhookName,
  updateWebhookAvatar,
  deleteWebhook,
  deleteChannelWebhooks,
  getAllMemberRoles,
  getCategory,
  getChannel,
  getChannelMessages,
  getEveryonePermissions,
  getInvite,
  getDiscoveryEntry,
  getDiscoveryApplication,
  getDiscoveryBlock,
  getMemberIds,
  getMemberPermissions,
  getMemberRoleIds,
  getMemberTopRolePosition,
  canModerateMember,
  canManageRolePosition,
  getMemberTimeoutUntil,
  getMembers,
  setMemberTimeout,
  setMemberNickname,
  getSharedServerNicknames,
  getRole,
  getServer,
  getServerIcon,
  getServerBanner,
  updateServerBanner,
  getServerMessage,
  getSharedMemberIdsForUser,
  hasPermission,
  incrementInviteUses,
  recordInviteUse,
  getInviteUserIds,
  isBanned,
  isDiscoveryBlocked,
  isEveryoneRoleId,
  isEveryoneRoleName,
  isMember,
  listBans,
  listCategories,
  listChannels,
  listDiscoveryServers,
  listDiscoveryApplications,
  listDiscoveryBlocks,
  listInvites,
  listRoles,
  reorderRoles,
  listServersForUser,
  setServerRailOrder,
  removeBan,
  removeMember,
  removeServerFromDiscovery,
  reviewDiscoveryApplication,
  renameCategory,
  renameChannel,
  setChannelPrivacy,
  setChannelSlowmode,
  setChannelAutoDelete,
  setChannelAbout,
  getLastChannelMessageAt,
  getRecentUserChannelMessages,
  getRecentUserServerMessages,
  sweepChannelAutoDelete,
  saveServerMessage,
  sweepExpiredServerMessages,
  setChannelCategory,
  setUncategorizedPosition,
  setMemberRoles,
  submitDiscoveryApplication,
  shareServer,
  getViewableTextChannelsForUser,
  searchMessagesInChannels,
  updateRole,
  updateCategoryLayout,
  updateChannelLayout,
  updateEveryonePermissions,
  updateServerIcon,
  updateServerName,
  updateServerOwner,
  unblockServerFromDiscovery,
};
