const { DatabaseSync } = require("node:sqlite");
const path = require("path");
const fs = require("fs");
const { config } = require("./env");

const dbPath = config.messagesDbPath;

// Ensure the data directory exists
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const messageDb = new DatabaseSync(dbPath);

// Performance settings
messageDb.exec("PRAGMA journal_mode = DELETE");
messageDb.exec("PRAGMA foreign_keys = OFF"); // no cross-DB FK enforcement

// Create the messages table if it doesn't already exist
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    message_id  TEXT NOT NULL PRIMARY KEY,
    sender_id   TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    content     TEXT NOT NULL,
    reply_to_message_id TEXT,
    edited_at   TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_messages_conversation
    ON messages (sender_id, receiver_id, created_at);

  CREATE INDEX IF NOT EXISTS IX_messages_receiver
    ON messages (receiver_id, sender_id, created_at);

  CREATE TABLE IF NOT EXISTS dm_conversations (
    user_id      TEXT NOT NULL,
    partner_id   TEXT NOT NULL,
    opened_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_read_at TEXT,
    autodelete_exempt INTEGER NOT NULL DEFAULT 0,
    pinned_at    TEXT,
    PRIMARY KEY (user_id, partner_id)
  );

  CREATE INDEX IF NOT EXISTS IX_dm_conversations_user_opened
    ON dm_conversations (user_id, opened_at DESC);

  CREATE TABLE IF NOT EXISTS message_reactions (
    message_id TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    emoji      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (message_id, user_id, emoji)
  );

  CREATE INDEX IF NOT EXISTS IX_message_reactions_message
    ON message_reactions (message_id, emoji);

  CREATE TABLE IF NOT EXISTS friendships (
    friendship_id TEXT    NOT NULL PRIMARY KEY,
    requester_id  TEXT    NOT NULL,
    addressee_id  TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'pending',
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (requester_id, addressee_id)
  );

  CREATE INDEX IF NOT EXISTS IX_friendships_addressee_status
    ON friendships (addressee_id, status);

  CREATE INDEX IF NOT EXISTS IX_friendships_requester_status
    ON friendships (requester_id, status);

  CREATE TABLE IF NOT EXISTS user_blocks (
    blocker_id TEXT NOT NULL,
    blocked_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (blocker_id, blocked_id)
  );

  CREATE INDEX IF NOT EXISTS IX_user_blocks_blocked
    ON user_blocks (blocked_id, blocker_id);

  CREATE TABLE IF NOT EXISTS servers (
    server_id  TEXT NOT NULL PRIMARY KEY,
    owner_id   TEXT NOT NULL,
    name       TEXT NOT NULL,
    icon_key   TEXT,
    icon_mime  TEXT,
    banner_key  TEXT,
    banner_mime TEXT,
    everyone_permissions INTEGER NOT NULL DEFAULT 64,
    uncategorized_position INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS server_categories (
    category_id TEXT NOT NULL PRIMARY KEY,
    server_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_server_categories_server
    ON server_categories (server_id, position);

  CREATE INDEX IF NOT EXISTS IX_servers_owner
    ON servers (owner_id);

  CREATE TABLE IF NOT EXISTS server_members (
    server_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    joined_at     TEXT NOT NULL DEFAULT (datetime('now')),
    timeout_until TEXT,
    PRIMARY KEY (server_id, user_id)
  );

  CREATE INDEX IF NOT EXISTS IX_server_members_user
    ON server_members (user_id);

  CREATE TABLE IF NOT EXISTS server_channels (
    channel_id  TEXT NOT NULL PRIMARY KEY,
    server_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    category_id TEXT,
    is_private  INTEGER NOT NULL DEFAULT 0,
    type        TEXT NOT NULL DEFAULT 'text',
    slowmode    INTEGER NOT NULL DEFAULT 0,
    auto_delete_seconds INTEGER NOT NULL DEFAULT 0,
    about       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_server_channels_server
    ON server_channels (server_id, position);

  CREATE TABLE IF NOT EXISTS server_messages (
    message_id TEXT NOT NULL PRIMARY KEY,
    channel_id TEXT NOT NULL,
    sender_id  TEXT NOT NULL,
    content    TEXT NOT NULL,
    reply_to_message_id TEXT,
    edited_at  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_server_messages_channel
    ON server_messages (channel_id, created_at);

  -- Incoming webhooks: a channel-scoped token an external client POSTs to in
  -- order to drop a message into the channel under a custom name + avatar.
  CREATE TABLE IF NOT EXISTS server_webhooks (
    webhook_id  TEXT NOT NULL PRIMARY KEY,
    server_id   TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    token       TEXT NOT NULL,
    name        TEXT NOT NULL,
    avatar_key  TEXT,
    avatar_mime TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_server_webhooks_channel
    ON server_webhooks (channel_id);
  CREATE INDEX IF NOT EXISTS IX_server_webhooks_server
    ON server_webhooks (server_id);

  CREATE TABLE IF NOT EXISTS server_roles (
    role_id     TEXT NOT NULL PRIMARY KEY,
    server_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    color       TEXT,
    permissions INTEGER NOT NULL DEFAULT 0,
    position    INTEGER NOT NULL DEFAULT 0,
    hoist       INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_server_roles_server
    ON server_roles (server_id, position);

  CREATE TABLE IF NOT EXISTS server_member_roles (
    server_id TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    role_id   TEXT NOT NULL,
    PRIMARY KEY (server_id, user_id, role_id)
  );

  -- Per-channel permission overwrites (Discord-style). target_type is 'role'
  -- (role_id, or '@everyone') or 'member' (user internal id). allow/deny are
  -- bitmasks over the channel-overridable permission bits.
  CREATE TABLE IF NOT EXISTS channel_overwrites (
    channel_id  TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    allow       INTEGER NOT NULL DEFAULT 0,
    deny        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_id, target_type, target_id)
  );

  CREATE INDEX IF NOT EXISTS IX_channel_overwrites_channel
    ON channel_overwrites (channel_id);

  CREATE TABLE IF NOT EXISTS server_invites (
    code       TEXT NOT NULL PRIMARY KEY,
    server_id  TEXT NOT NULL,
    creator_id TEXT NOT NULL,
    uses       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS IX_server_invites_server
    ON server_invites (server_id);

  CREATE TABLE IF NOT EXISTS server_discovery (
    server_id   TEXT NOT NULL PRIMARY KEY,
    invite_code TEXT NOT NULL UNIQUE,
    added_by    TEXT NOT NULL,
    about       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_server_discovery_created
    ON server_discovery (created_at);

  CREATE TABLE IF NOT EXISTS server_discovery_applications (
    server_id   TEXT NOT NULL PRIMARY KEY,
    requester_id TEXT NOT NULL,
    about       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_note TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_server_discovery_applications_status
    ON server_discovery_applications (status, updated_at);

  CREATE TABLE IF NOT EXISTS server_discovery_blocks (
    server_id   TEXT NOT NULL PRIMARY KEY,
    banned_by   TEXT NOT NULL,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS server_bans (
    server_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    banned_by  TEXT NOT NULL,
    reason     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (server_id, user_id)
  );

`);

// Per-conversation auto-delete timer (Telegram-style). Keyed by the two INTERNAL
// user ids sorted and joined as "a b". ttl_seconds = 0 means off. applies_to:
// 'both' deletes everyone's messages in the chat; 'setter' only set_by's.
// (Kept in its own exec - node:sqlite's multi-statement exec mishandles inline
// SQL comments, which silently skipped this table when it lived in the block above.)
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS dm_auto_delete (
    pair_key    TEXT NOT NULL PRIMARY KEY,
    ttl_seconds INTEGER NOT NULL DEFAULT 0,
    applies_to  TEXT NOT NULL DEFAULT 'both',
    set_by      TEXT NOT NULL,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// User-uploaded DM attachments. The bytes live in Backblaze B2 (keyed by the
// uploader's public id); this table maps a public, shareable slug -> B2 object.
// A per-user 50 MB rolling budget evicts the oldest assets: the row stays (so the
// link still resolves) but b2_key is cleared and evicted=1, and the serve route
// returns 410 so the message shows "Attachment deleted". (Own exec block - see the
// node:sqlite inline-comment caveat above.)
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS assets (
    asset_id     TEXT NOT NULL PRIMARY KEY,
    owner_id     TEXT NOT NULL,
    slug         TEXT NOT NULL,
    b2_key       TEXT,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    filename     TEXT NOT NULL DEFAULT 'file',
    byte_size    INTEGER NOT NULL DEFAULT 0,
    evicted      INTEGER NOT NULL DEFAULT 0,
    group_id     TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
messageDb.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS IX_assets_owner_slug ON assets (owner_id, slug);
  CREATE INDEX IF NOT EXISTS IX_assets_owner_created ON assets (owner_id, created_at);
`);

// Starred media. A user can star any media item (their own OR someone else's),
// keyed by the asset's public (owner, slug). This is a BOOKMARK only: it copies a
// metadata snapshot (name/ct/size) so the Starred tab can render a tile even after
// the original message is gone, but it NEVER stores bytes and NEVER pins/protects
// the owner's asset from eviction. If the asset is later evicted/deleted the tile
// just resolves to "Attachment deleted". Own exec block - see the node:sqlite
// inline-comment caveat above.
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS starred_media (
    star_id    TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL,
    owner_id   TEXT NOT NULL,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT 'file',
    ct         TEXT NOT NULL DEFAULT 'application/octet-stream',
    size       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
messageDb.exec(`
  CREATE UNIQUE INDEX IF NOT EXISTS IX_starred_user_owner_slug ON starred_media (user_id, owner_id, slug);
  CREATE INDEX IF NOT EXISTS IX_starred_user_created ON starred_media (user_id, created_at);
`);

// AutoMod: one JSON config blob per server (keyword / link / spam filters and the
// punishment each carries). Stored as TEXT so the rule set can evolve without a
// migration. Own exec block - see the node:sqlite inline-comment caveat above.
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS server_automod (
    server_id  TEXT NOT NULL PRIMARY KEY,
    config     TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Per-member, per-server privacy ("Manage Privacy" on a server). Each row lets a
// member opt out of pings / DMs / friend requests that come from THIS server.
// Own exec block (no inline "--" comments - see the node:sqlite caveat above).
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS server_privacy (
    user_id           TEXT NOT NULL,
    server_id         TEXT NOT NULL,
    block_pings       INTEGER NOT NULL DEFAULT 0,
    block_dms         INTEGER NOT NULL DEFAULT 0,
    block_friend_reqs INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, server_id)
  );
`);
messageDb.exec("CREATE INDEX IF NOT EXISTS IX_server_privacy_server ON server_privacy (server_id)");

// Records which users joined a server through which invite code, so the invites
// tab can show "who was invited by what invite". Own exec block - see the
// node:sqlite inline-comment caveat above.
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS server_invite_uses (
    code      TEXT NOT NULL,
    server_id TEXT NOT NULL,
    user_id   TEXT NOT NULL,
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (code, user_id)
  );

  CREATE INDEX IF NOT EXISTS IX_server_invite_uses_code
    ON server_invite_uses (code);
`);

// Per-invite max uses (0 = unlimited). Lets an invite be single-use.
const serverInviteCols = messageDb.prepare("PRAGMA table_info(server_invites)").all();
if (serverInviteCols.length > 0 && !serverInviteCols.some((column) => column.name === "max_uses")) {
  messageDb.exec("ALTER TABLE server_invites ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 0");
}

const serverDiscoveryCols = messageDb.prepare("PRAGMA table_info(server_discovery)").all();
if (serverDiscoveryCols.length > 0 && !serverDiscoveryCols.some((column) => column.name === "about")) {
  messageDb.exec("ALTER TABLE server_discovery ADD COLUMN about TEXT NOT NULL DEFAULT ''");
}

// Auto-delete: each message carries the absolute moment it should vanish. Set
// once at send time (no per-message timers); expired rows are skipped on read
// and reaped in bulk by a background sweeper.
const messageColsForExpiry = messageDb.prepare("PRAGMA table_info(messages)").all();
if (!messageColsForExpiry.some((column) => column.name === "expires_at")) {
  messageDb.exec("ALTER TABLE messages ADD COLUMN expires_at TEXT");
}
const serverMsgColsForExpiry = messageDb.prepare("PRAGMA table_info(server_messages)").all();
if (serverMsgColsForExpiry.length > 0 && !serverMsgColsForExpiry.some((column) => column.name === "expires_at")) {
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN expires_at TEXT");
}
messageDb.exec(`
  CREATE INDEX IF NOT EXISTS IX_messages_expires_at
    ON messages (expires_at) WHERE expires_at IS NOT NULL;
  CREATE INDEX IF NOT EXISTS IX_server_messages_expires_at
    ON server_messages (expires_at) WHERE expires_at IS NOT NULL;
`);

const messageColumns = messageDb.prepare("PRAGMA table_info(messages)").all();
if (!messageColumns.some((column) => column.name === "edited_at")) {
  messageDb.exec("ALTER TABLE messages ADD COLUMN edited_at TEXT");
}
if (!messageColumns.some((column) => column.name === "reply_to_message_id")) {
  messageDb.exec("ALTER TABLE messages ADD COLUMN reply_to_message_id TEXT");
}

const serverMessageColumns = messageDb.prepare("PRAGMA table_info(server_messages)").all();
if (serverMessageColumns.length > 0 && !serverMessageColumns.some((column) => column.name === "reply_to_message_id")) {
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN reply_to_message_id TEXT");
}
// Webhook-authored messages: which webhook sent it, and the name it used at the
// time (kept on the row so history renders even if the webhook is renamed/deleted).
if (serverMessageColumns.length > 0 && !serverMessageColumns.some((column) => column.name === "webhook_id")) {
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN webhook_id TEXT");
}
if (serverMessageColumns.length > 0 && !serverMessageColumns.some((column) => column.name === "webhook_name")) {
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN webhook_name TEXT");
}
// At-rest encryption (server_messages.content may be stored as ChaCha20-Poly1305
// bytes). Once content is ciphertext, the old `content LIKE '{%"_att"%'` attachment
// test can't match, so attachment-ness is computed from plaintext at write time and
// stored here for the auto-delete sweeps to key on. Set at write + the backfill.
if (serverMessageColumns.length > 0 && !serverMessageColumns.some((column) => column.name === "has_attachment")) {
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN has_attachment INTEGER NOT NULL DEFAULT 0");
}

// Pinned messages (Discord-style). A nullable timestamp on the message row: NULL
// = not pinned, otherwise the moment it was pinned (pins list newest-first by it).
// Kept as a column rather than a side table so it travels with the message and is
// cleared automatically on delete/purge. pinned_by records who pinned it.
if (!messageColumns.some((column) => column.name === "pinned_at")) {
  messageDb.exec("ALTER TABLE messages ADD COLUMN pinned_at TEXT");
  messageDb.exec("ALTER TABLE messages ADD COLUMN pinned_by TEXT");
}
if (serverMessageColumns.length > 0 && !serverMessageColumns.some((column) => column.name === "pinned_at")) {
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN pinned_at TEXT");
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN pinned_by TEXT");
}
messageDb.exec(`
  CREATE INDEX IF NOT EXISTS IX_messages_pinned
    ON messages (sender_id, receiver_id, pinned_at) WHERE pinned_at IS NOT NULL;
  CREATE INDEX IF NOT EXISTS IX_server_messages_pinned
    ON server_messages (channel_id, pinned_at) WHERE pinned_at IS NOT NULL;
`);

// Cross-device DM read sync: each side's last-read timestamp per conversation.
const dmConversationColumns = messageDb.prepare("PRAGMA table_info(dm_conversations)").all();
if (dmConversationColumns.length > 0 && !dmConversationColumns.some((column) => column.name === "last_read_at")) {
  messageDb.exec("ALTER TABLE dm_conversations ADD COLUMN last_read_at TEXT");
}
// Per-DM "cancel auto-delete" opt-out: when set, this side's global DM auto-delete
// does not apply to this one conversation.
if (dmConversationColumns.length > 0 && !dmConversationColumns.some((column) => column.name === "autodelete_exempt")) {
  messageDb.exec("ALTER TABLE dm_conversations ADD COLUMN autodelete_exempt INTEGER NOT NULL DEFAULT 0");
}
// Cross-device sidebar pins: each account pins its own side of a DM thread.
if (dmConversationColumns.length > 0 && !dmConversationColumns.some((column) => column.name === "pinned_at")) {
  messageDb.exec("ALTER TABLE dm_conversations ADD COLUMN pinned_at TEXT");
}
messageDb.exec(`
  CREATE INDEX IF NOT EXISTS IX_dm_conversations_user_pinned
    ON dm_conversations (user_id, pinned_at) WHERE pinned_at IS NOT NULL;
`);

// Servers created before categories / cache-busting existed need the new columns.
const serverColumns = messageDb.prepare("PRAGMA table_info(servers)").all();
if (!serverColumns.some((column) => column.name === "updated_at")) {
  messageDb.exec("ALTER TABLE servers ADD COLUMN updated_at TEXT");
  messageDb.exec("UPDATE servers SET updated_at = created_at WHERE updated_at IS NULL");
}
if (!serverColumns.some((column) => column.name === "everyone_permissions")) {
  messageDb.exec("ALTER TABLE servers ADD COLUMN everyone_permissions INTEGER NOT NULL DEFAULT 64");
}
// One-time: grant the new SEND_EMBEDS (4096) bit to every existing server's
// @everyone so links keep embedding by default. Guarded by a marker column so it
// runs exactly once - an admin can uncheck "Send Embeds" afterwards and it sticks.
if (!serverColumns.some((column) => column.name === "embed_perm_seeded")) {
  messageDb.exec("ALTER TABLE servers ADD COLUMN embed_perm_seeded INTEGER NOT NULL DEFAULT 0");
  messageDb.exec("UPDATE servers SET everyone_permissions = everyone_permissions | 4096, embed_perm_seeded = 1");
}
if (!serverColumns.some((column) => column.name === "uncategorized_position")) {
  messageDb.exec("ALTER TABLE servers ADD COLUMN uncategorized_position INTEGER NOT NULL DEFAULT 0");
}
// Server icons moved to Backblaze B2 - the DB only keeps the object key now.
if (!serverColumns.some((column) => column.name === "icon_key")) {
  messageDb.exec("ALTER TABLE servers ADD COLUMN icon_key TEXT");
}
// Server banners (wide header image), also stored in B2 by object key.
if (!serverColumns.some((column) => column.name === "banner_key")) {
  messageDb.exec("ALTER TABLE servers ADD COLUMN banner_key TEXT");
}
if (!serverColumns.some((column) => column.name === "banner_mime")) {
  messageDb.exec("ALTER TABLE servers ADD COLUMN banner_mime TEXT");
}

const serverChannelColumns = messageDb.prepare("PRAGMA table_info(server_channels)").all();
if (serverChannelColumns.length > 0 && !serverChannelColumns.some((column) => column.name === "category_id")) {
  messageDb.exec("ALTER TABLE server_channels ADD COLUMN category_id TEXT");
}
if (serverChannelColumns.length > 0 && !serverChannelColumns.some((column) => column.name === "is_private")) {
  messageDb.exec("ALTER TABLE server_channels ADD COLUMN is_private INTEGER NOT NULL DEFAULT 0");
}

const serverMemberColumns = messageDb.prepare("PRAGMA table_info(server_members)").all();
if (serverMemberColumns.length > 0 && !serverMemberColumns.some((column) => column.name === "timeout_until")) {
  messageDb.exec("ALTER TABLE server_members ADD COLUMN timeout_until TEXT");
}
// Per-server nickname (overrides the global alias/username inside this server).
if (serverMemberColumns.length > 0 && !serverMemberColumns.some((column) => column.name === "nickname")) {
  messageDb.exec("ALTER TABLE server_members ADD COLUMN nickname TEXT");
}
// Per-user drag-to-reorder position for the server rail. Lower = higher on the
// rail. Default 0 so untouched members fall back to the joined_at tiebreaker
// (newest server on top); a drag rewrites these to 0..n-1 in the chosen order.
if (serverMemberColumns.length > 0 && !serverMemberColumns.some((column) => column.name === "rail_position")) {
  messageDb.exec("ALTER TABLE server_members ADD COLUMN rail_position INTEGER NOT NULL DEFAULT 0");
}

// Bans created before reasons existed need the new column.
const serverBanColumns = messageDb.prepare("PRAGMA table_info(server_bans)").all();
if (serverBanColumns.length > 0 && !serverBanColumns.some((column) => column.name === "reason")) {
  messageDb.exec("ALTER TABLE server_bans ADD COLUMN reason TEXT");
}

// "Display role in members": a hoisted role gets its own header in the member list
// (grouped by role hierarchy). 0 = not hoisted (default).
const serverRoleColumns = messageDb.prepare("PRAGMA table_info(server_roles)").all();
if (serverRoleColumns.length > 0 && !serverRoleColumns.some((column) => column.name === "hoist")) {
  messageDb.exec("ALTER TABLE server_roles ADD COLUMN hoist INTEGER NOT NULL DEFAULT 0");
}

// Channels predate voice channels - default existing rows to text.
if (serverChannelColumns.length > 0 && !serverChannelColumns.some((column) => column.name === "type")) {
  messageDb.exec("ALTER TABLE server_channels ADD COLUMN type TEXT NOT NULL DEFAULT 'text'");
}
// Per-channel slowmode (seconds between messages per non-exempt user). 0 = off.
if (serverChannelColumns.length > 0 && !serverChannelColumns.some((column) => column.name === "slowmode")) {
  messageDb.exec("ALTER TABLE server_channels ADD COLUMN slowmode INTEGER NOT NULL DEFAULT 0");
}
// Per-channel auto-delete (every message in the channel is reaped after this many
// seconds, regardless of sender). 0 = off.
if (serverChannelColumns.length > 0 && !serverChannelColumns.some((column) => column.name === "auto_delete_seconds")) {
  messageDb.exec("ALTER TABLE server_channels ADD COLUMN auto_delete_seconds INTEGER NOT NULL DEFAULT 0");
}
// Per-channel "about" / topic (≤100 chars) shown next to the channel name in the header.
if (serverChannelColumns.length > 0 && !serverChannelColumns.some((column) => column.name === "about")) {
  messageDb.exec("ALTER TABLE server_channels ADD COLUMN about TEXT");
}

// ── Group chats (group DMs) ──────────────────────────────────────────────────
// Discord-style group DMs: a named conversation with up to 20 members. Messages
// are E2E (content is the same encrypted-blob JSON as 1:1 DMs, but the per-message
// AES key is wrapped to EVERY current member's public key). The server only ever
// stores ciphertext. Own exec block (no inline "--" comments - see the node:sqlite
// caveat above) so every statement runs.
messageDb.exec(`
  CREATE TABLE IF NOT EXISTS group_conversations (
    group_id   TEXT NOT NULL PRIMARY KEY,
    name       TEXT,
    owner_id   TEXT NOT NULL,
    icon_key   TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS group_members (
    group_id     TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    joined_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_read_at TEXT,
    PRIMARY KEY (group_id, user_id)
  );

  CREATE INDEX IF NOT EXISTS IX_group_members_user
    ON group_members (user_id);

  CREATE TABLE IF NOT EXISTS group_messages (
    message_id TEXT NOT NULL PRIMARY KEY,
    group_id   TEXT NOT NULL,
    sender_id  TEXT NOT NULL,
    content    TEXT NOT NULL,
    reply_to_message_id TEXT,
    edited_at  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS IX_group_messages_group
    ON group_messages (group_id, created_at);
`);

// Group icons (uploaded to B2, like server icons): the icon_key column already
// exists; add icon_mime so the serve route knows the content type. Own statement
// outside the CREATE block so it runs on already-existing group tables too.
const groupConvCols = messageDb.prepare("PRAGMA table_info(group_conversations)").all();
if (groupConvCols.length > 0 && !groupConvCols.some((c) => c.name === "icon_mime")) {
  messageDb.exec("ALTER TABLE group_conversations ADD COLUMN icon_mime TEXT");
}

// Group message pins (mirrors DM pins): NULL pinned_at = not pinned, else the
// moment it was pinned (pins list newest-first by it); pinned_by records who.
const groupMsgCols = messageDb.prepare("PRAGMA table_info(group_messages)").all();
if (groupMsgCols.length > 0 && !groupMsgCols.some((c) => c.name === "pinned_at")) {
  messageDb.exec("ALTER TABLE group_messages ADD COLUMN pinned_at TEXT");
  messageDb.exec("ALTER TABLE group_messages ADD COLUMN pinned_by TEXT");
}

// Auto-delete: a group message carries the absolute moment it should vanish (set
// once at send time from the sender's DM auto-delete setting). Reads skip expired
// rows and the sweeper reaps them - same model as DM/server messages.
if (groupMsgCols.length > 0 && !groupMsgCols.some((c) => c.name === "expires_at")) {
  messageDb.exec("ALTER TABLE group_messages ADD COLUMN expires_at TEXT");
}

// Tag each asset with the group it was uploaded into (NULL for DMs), so a group's
// attachments can be hard-deleted wholesale when the group is purged. Added on
// already-existing asset tables; the index is created idempotently above.
const assetCols = messageDb.prepare("PRAGMA table_info(assets)").all();
if (assetCols.length > 0 && !assetCols.some((c) => c.name === "group_id")) {
  messageDb.exec("ALTER TABLE assets ADD COLUMN group_id TEXT");
}
// Create the index AFTER the column is guaranteed to exist (fresh DBs get the
// column from CREATE TABLE, existing DBs from the ALTER just above).
messageDb.exec("CREATE INDEX IF NOT EXISTS IX_assets_group ON assets (group_id)");

const removedFlagReactions = [
  "🚩", "🏳️", "🏴", "🏁", "🏴‍☠️", "🌈", "🇺🇸", "🇨🇦", "🇲🇽", "🇬🇧", "🇫🇷", "🇩🇪",
  "🇯🇵", "🇰🇷", "🇧🇷", "🇵🇭", "🇪🇸", "🇮🇹", "🇦🇺", "🇺🇦"
];
messageDb.prepare(`
  DELETE FROM message_reactions
  WHERE emoji IN (${removedFlagReactions.map(() => "?").join(",")})
`).run(...removedFlagReactions);

// Removable embeds: each message carries a JSON array of suppressed embed indices
// (which link/media previews the author - or server staff - hid). NULL = none.
// Index-based (not URL) so it stays content-free for E2E DM/group messages.
const dmSuppressCols = messageDb.prepare("PRAGMA table_info(messages)").all();
if (!dmSuppressCols.some((c) => c.name === "suppressed_embeds")) {
  messageDb.exec("ALTER TABLE messages ADD COLUMN suppressed_embeds TEXT");
}
const groupSuppressCols = messageDb.prepare("PRAGMA table_info(group_messages)").all();
if (groupSuppressCols.length > 0 && !groupSuppressCols.some((c) => c.name === "suppressed_embeds")) {
  messageDb.exec("ALTER TABLE group_messages ADD COLUMN suppressed_embeds TEXT");
}
const serverSuppressCols = messageDb.prepare("PRAGMA table_info(server_messages)").all();
if (serverSuppressCols.length > 0 && !serverSuppressCols.some((c) => c.name === "suppressed_embeds")) {
  messageDb.exec("ALTER TABLE server_messages ADD COLUMN suppressed_embeds TEXT");
}

module.exports = messageDb;
