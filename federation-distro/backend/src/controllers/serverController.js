const { config } = require("../config/env");
const dns = require("dns").promises;
const net = require("net");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const sendCipher = require("../security/sendCipher");
const userRepository = require("../repositories/userRepository");
const serverRepository = require("../repositories/serverRepository");
const serverPrivacyRepository = require("../repositories/serverPrivacyRepository");
const { broadcastToUser, broadcastToServerMembers } = require("../services/websocketServer");
const { generateInitialProfilePicture } = require("../services/profilePicture");
const { getUserBadges } = require("../services/badges");
const b2Storage = require("../services/b2Storage");
const messageService = require("../services/messageService");
const automod = require("../services/automod");
const { validateReactionEmoji } = require("./messageController");
const { toUtcIso } = require("../utils/time");
const { isPublicOnline, publicPresenceStatus } = require("../services/presence");

const {
  PERMISSIONS,
  EVERYONE_ROLE_ID,
  EVERYONE_ROLE_NAME,
  MAX_SERVERS_PER_USER,
  MAX_SERVER_NAME_LENGTH,
  MAX_CHANNEL_NAME_LENGTH,
  MAX_CATEGORY_NAME_LENGTH,
  MAX_ROLE_NAME_LENGTH,
  MAX_TEXT_CHANNELS_PER_SERVER,
  MAX_VOICE_CHANNELS_PER_SERVER,
  MAX_CATEGORIES_PER_SERVER,
  MAX_ROLES_PER_SERVER,
  MAX_INVITES_PER_USER_PER_SERVER,
} = serverRepository;

const MAX_MESSAGE_LENGTH = 2000;
const MAX_SERVER_AVATAR_BYTES = 3 * 1024 * 1024;
// Animated GIF server banners get a larger budget than static banners/icons.
const MAX_SERVER_BANNER_GIF_BYTES = 10 * 1024 * 1024;
const LINK_PREVIEW_MAX_BYTES = 768 * 1024;
const LINK_PREVIEW_IMAGE_MAX_BYTES = 5 * 1024 * 1024;
const LINK_PREVIEW_TIMEOUT_MS = 3500;
const LINK_PREVIEW_MAX_REDIRECTS = 3;
// Invite links are handed out on this server's own public address.
const PUBLIC_INVITE_ORIGIN = config.publicUrl;
const PUBLIC_INVITE_HOSTS = new Set([config.publicHost, `www.${config.publicHost}`]);
const INVITE_CODE_PATTERN = /^[A-Za-z0-9_-]{4,64}$/;
const MIN_DISCOVERY_ABOUT_LENGTH = 20;
const MAX_DISCOVERY_ABOUT_LENGTH = 700;
// Sentinel for the uncategorized "TEXT CHANNELS" section in a layout's section
// order. Must match TOP_LEVEL_SECTION_ID in js/server_view.js.
const UNCATEGORIZED_SECTION = "__top_level_text_channels__";

function publicPermissionBits() {
  const { SHARE_FILES, ...bits } = PERMISSIONS;
  return bits;
}

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}

async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

function getPublicId(userRow) {
  return userRow.public_user_id || userRow.user_id;
}

// Versioned avatar URL. The ?v= (the user's updated_at) busts the browser cache
// when they change their picture, so member lists / messages stop showing the
// stale avatar - mirrors how the banner URLs are already versioned.
function pfpUrl(userRow) {
  const publicId = getPublicId(userRow);
  return `/api/auth/profile-picture?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(userRow.updated_at || userRow.created_at || "")}`;
}

// True when a message body is an uploaded-file attachment marker (see
// js/attachments.js). Sharing one in a channel is covered by Send Embeds.
function isAttachmentMarker(content) {
  if (!content || content[0] !== "{") return false;
  try {
    const parsed = JSON.parse(content);
    return Boolean(parsed && parsed._att === 1 && typeof parsed.slug === "string" && typeof parsed.owner === "string");
  } catch {
    return false;
  }
}

function publicUserSummary(userRow) {
  const publicId = getPublicId(userRow);
  return {
    userId: publicId,
    username: userRow.username,
    alias: userRow.profile_alias || "",
    bio: userRow.bio || "",
    profilePictureUrl: pfpUrl(userRow),
    profileBannerUrl: userRow.profile_banner_mime
      ? `/api/auth/profile-banner?uid=${encodeURIComponent(publicId)}&v=${encodeURIComponent(userRow.updated_at || Date.now())}`
      : "",
    // Surfaced on the profile card so others know this person auto-deletes their
    // own server messages, and after how long.
    serverAutodelete: Boolean(userRow.server_autodelete),
    autodeleteSeconds: userRow.autodelete_seconds || 86400,
    badges: getUserBadges(userRow),
  };
}

function serverSummary(server, userId) {
  const owner = userRepository.findById(server.owner_id);
  return {
    serverId: server.server_id,
    name: server.name,
    ownerId: owner ? getPublicId(owner) : null,
    isOwner: server.owner_id === userId,
    iconUrl: `/api/servers/${encodeURIComponent(server.server_id)}/icon?v=${encodeURIComponent(server.updated_at || server.created_at || "")}`,
    hasIcon: Boolean(server.icon_mime),
    bannerUrl: `/api/servers/${encodeURIComponent(server.server_id)}/banner?v=${encodeURIComponent(server.updated_at || server.created_at || "")}`,
    hasBanner: Boolean(server.banner_mime),
  };
}

function normalizeInviteCode(value) {
  const code = String(value || "").trim();
  return INVITE_CODE_PATTERN.test(code) ? code : "";
}

function inviteUrl(code) {
  return `${PUBLIC_INVITE_ORIGIN}/invite/${encodeURIComponent(code)}`;
}

function publicInviteSummary(invite, server) {
  return {
    code: invite.code,
    url: inviteUrl(invite.code),
    serverName: server.name,
    expiresAt: toUtcIso(invite.expires_at) || invite.expires_at,
  };
}

function discoveryApplicationSummary(application, entry, block) {
  return {
    status: application?.status || (entry ? "approved" : "none"),
    about: application?.about || entry?.about || "",
    appliedAt: toUtcIso(application?.created_at) || application?.created_at || null,
    updatedAt: toUtcIso(application?.updated_at) || application?.updated_at || null,
    reviewedAt: toUtcIso(application?.reviewed_at) || application?.reviewed_at || null,
    reviewNote: application?.review_note || "",
    listed: Boolean(entry),
    blocked: Boolean(block),
    blockedReason: block?.reason || "",
  };
}

function countOnlineMembers(serverId) {
  return serverRepository.getMembers(serverId).reduce((total, member) => {
    const user = userRepository.findById(member.user_id);
    return total + (isPublicOnline(user) ? 1 : 0);
  }, 0);
}

function invitePreviewSummary(invite, server) {
  const hasServerIcon = Boolean(server.icon_mime);
  const hasServerBanner = Boolean(server.banner_mime);
  return {
    type: "server_invite",
    url: inviteUrl(invite.code),
    host: config.publicHost,
    siteName: config.serverDisplayName,
    title: server.name,
    serverName: server.name,
    // Lets a signed-in viewer who's already a member see "Go to Server" instead
    // of "Join Server" (the id isn't secret — members can copy it in-app).
    serverId: server.server_id,
    memberCount: serverRepository.countMembers(server.server_id),
    onlineCount: countOnlineMembers(server.server_id),
    createdAt: toUtcIso(server.created_at) || server.created_at,
    // Always provide an icon URL: the endpoint serves the custom icon if there is
    // one, otherwise a generated letter avatar - so the embed always shows a picture.
    serverIconUrl: `/api/servers/invites/${encodeURIComponent(invite.code)}/icon`,
    hasServerIcon,
    serverBannerUrl: hasServerBanner ? `/api/servers/invites/${encodeURIComponent(invite.code)}/banner` : "",
    hasServerBanner,
    isValidInvite: true,
    themeColor: "#5865f2",
  };
}

function getInviteServer(code) {
  const cleanCode = normalizeInviteCode(code);
  if (!cleanCode) return null;
  serverRepository.deleteExpiredInvites();
  const invite = serverRepository.getInvite(cleanCode);
  if (!invite || new Date(invite.expires_at).getTime() <= Date.now()) return null;
  // Single-/limited-use invite that's all used up - treat as gone (and reap it).
  if (invite.max_uses > 0 && invite.uses >= invite.max_uses) {
    serverRepository.deleteInvite(invite.code);
    return null;
  }
  const server = serverRepository.getServer(invite.server_id);
  if (!server) {
    serverRepository.deleteInvite(invite.code);
    return null;
  }
  return { invite, server };
}

// Allowed slowmode durations in seconds (0 = off). Mirrored on the client.
const SLOWMODE_OPTIONS = [0, 5, 10, 15, 30, 60, 180, 360, 600, 1800, 3600, 7200, 10800, 21600];

// Allowed channel auto-delete durations in seconds (0 = off): 8h, 12h, 24h.
// Mirrored on the client.
const AUTO_DELETE_OPTIONS = [0, 28800, 43200, 86400];

function publicChannel(channel) {
  return {
    channelId: channel.channel_id,
    name: channel.name,
    position: channel.position,
    categoryId: channel.category_id || null,
    isPrivate: Boolean(channel.is_private),
    type: channel.type === "voice" ? "voice" : "text",
    slowmode: Number(channel.slowmode) || 0,
    autoDelete: Number(channel.auto_delete_seconds) || 0,
    about: channel.about || "",
  };
}

const MAX_CHANNEL_ABOUT_LENGTH = 100;

// Whether a user can see a channel, honouring per-channel View Channel overwrites
// (and the legacy is_private flag). myPermissions is no longer needed.
function canViewChannel(server, channel, userId) {
  return serverRepository.hasPermission(
    serverRepository.channelPermissionsFor(server.server_id, channel, userId),
    PERMISSIONS.VIEW_CHANNEL
  );
}

// Broadcasts to everyone who can currently view the channel. Public channels with
// no overwrites take the fast path (all members); otherwise we resolve per member.
function broadcastToChannelViewers(server, channel, payload) {
  if (!channel.is_private && serverRepository.getChannelOverwrites(channel.channel_id).length === 0) {
    broadcastToServerMembers(server.server_id, payload);
    return;
  }
  serverRepository.getMemberIds(server.server_id).forEach((memberId) => {
    if (canViewChannel(server, channel, memberId)) broadcastToUser(memberId, payload);
  });
}

function publicCategory(category) {
  return {
    categoryId: category.category_id,
    name: category.name,
    position: category.position,
  };
}

function publicRole(role) {
  return {
    roleId: role.role_id,
    name: role.name,
    color: role.color || "",
    permissions: serverRepository.normalizeMergedPermissions(role.permissions),
    position: role.position,
    hoist: Boolean(role.hoist),
    isEveryone: Boolean(role.is_everyone),
  };
}

function publicEveryoneRole(server) {
  return publicRole({
    role_id: EVERYONE_ROLE_ID,
    name: EVERYONE_ROLE_NAME,
    color: "",
    permissions: serverRepository.getEveryonePermissions(server.server_id),
    position: -1,
    is_everyone: true,
  });
}

// Safely parse a message row's suppressed_embeds JSON into an array of indices.
function parseSuppressedEmbeds(raw) {
  if (!raw) return [];
  try { const arr = JSON.parse(raw); return Array.isArray(arr) ? arr : []; } catch { return []; }
}

function publicServerMessage(row, senderRow) {
  // Webhook-authored message: attribute it to the webhook (custom name + avatar),
  // not a user. The display name is frozen on the row so renames/deletes don't
  // rewrite history.
  if (row.webhook_id) {
    return {
      messageId: row.message_id,
      seq: row.seq,
      channelId: row.channel_id,
      senderId: row.webhook_id,
      senderUsername: "",
      senderName: row.webhook_name || "Webhook",
      senderBio: "",
      senderAvatarUrl: `/api/webhooks/${encodeURIComponent(row.webhook_id)}/avatar`,
      senderProfileBannerUrl: "",
      senderIsOnline: false,
      senderPresenceStatus: "offline",
      isWebhook: true,
      content: row.content,
      createdAt: toUtcIso(row.created_at),
      editedAt: row.edited_at ? toUtcIso(row.edited_at) : null,
      replyToMessageId: row.reply_to_message_id || null,
      expiresAt: row.expires_at ? toUtcIso(row.expires_at) : null,
      pinnedAt: row.pinned_at ? toUtcIso(row.pinned_at) : null,
      suppressedEmbeds: parseSuppressedEmbeds(row.suppressed_embeds),
      reactions: [],
    };
  }
  const sender = senderRow || userRepository.findById(row.sender_id);
  return {
    messageId: row.message_id,
    seq: row.seq,
    channelId: row.channel_id,
    senderId: sender ? getPublicId(sender) : "",
    senderUsername: sender?.username || "",
    senderName: sender?.profile_alias || sender?.username || "Unknown",
    senderBio: sender?.bio || "",
    senderAvatarUrl: sender ? pfpUrl(sender) : "",
    senderProfileBannerUrl: sender?.profile_banner_mime
      ? `/api/auth/profile-banner?uid=${encodeURIComponent(getPublicId(sender))}&v=${encodeURIComponent(sender.updated_at || Date.now())}`
      : "",
    senderIsOnline: isPublicOnline(sender),
    senderPresenceStatus: sender ? publicPresenceStatus(sender) : "offline",
    senderBadges: getUserBadges(sender),
    content: row.content,
    createdAt: toUtcIso(row.created_at),
    editedAt: row.edited_at ? toUtcIso(row.edited_at) : null,
    replyToMessageId: row.reply_to_message_id || null,
    expiresAt: row.expires_at ? toUtcIso(row.expires_at) : null,
    pinnedAt: row.pinned_at ? toUtcIso(row.pinned_at) : null,
    suppressedEmbeds: parseSuppressedEmbeds(row.suppressed_embeds),
    reactions: [],
  };
}

// Parse @mentions out of a message. `@everyone` only counts as a real ping when
// the author is allowed to use it (owner / admin / MENTION_EVERYONE) - otherwise
// it's just plain text. User mentions resolve only to actual members of THIS
// server (and never the author). Returns public ids the client can match itself.
function computeServerMentions(content, server, author, myPermissions) {
  const canEveryone = server.owner_id === author.user_id
    || serverRepository.hasPermission(myPermissions, PERMISSIONS.ADMINISTRATOR)
    || serverRepository.hasPermission(myPermissions, PERMISSIONS.MENTION_EVERYONE);
  const everyone = canEveryone && /(^|\s)@everyone\b/.test(content);

  const users = [];
  const seen = new Set();
  const pattern = /@([a-zA-Z0-9_]{2,32})/g;
  let match;
  while ((match = pattern.exec(content)) !== null) {
    const handle = match[1];
    const lower = handle.toLowerCase();
    if (lower === "everyone" || seen.has(lower)) continue;
    seen.add(lower);
    const target = userRepository.findByUsername(handle);
    if (target && target.user_id !== author.user_id && serverRepository.isMember(server.server_id, target.user_id)) {
      users.push(getPublicId(target));
    }
  }
  return { everyone, users };
}

function validateServerName(name) {
  if (!name || typeof name !== "string" || name.trim().length < 2) {
    return "Server name needs at least 2 characters.";
  }
  if (name.trim().length > MAX_SERVER_NAME_LENGTH) {
    return `Server name cannot exceed ${MAX_SERVER_NAME_LENGTH} characters.`;
  }
  return null;
}

function normalizeChannelName(name) {
  if (!name || typeof name !== "string") return "";
  const cleaned = name
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    // Allow letters, numbers, emoji and other unicode - only strip ASCII control
    // characters and angle brackets (so a name can't smuggle markup).
    .replace(/[\u0000-\u001f\u007f<>]/g, "")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "");
  // Cap by code points so a multi-code-unit emoji is never sliced in half.
  return Array.from(cleaned).slice(0, MAX_CHANNEL_NAME_LENGTH).join("");
}

function permissionsFitActor(permissions, { isOwner, myPermissions }) {
  const requested = serverRepository.normalizeMergedPermissions(permissions);
  const actorPermissions = serverRepository.normalizeMergedPermissions(myPermissions);
  return isOwner || (requested & ~actorPermissions) === 0;
}

function roleFitsActor(role, actor) {
  return permissionsFitActor(serverRepository.normalizeMergedPermissions(role.permissions), actor);
}

function validateRoleInput({ name, color, permissions }, actor) {
  if (!name || typeof name !== "string" || name.trim().length < 1) {
    return "Role name cannot be empty.";
  }
  if (name.trim().length > MAX_ROLE_NAME_LENGTH) {
    return `Role name cannot exceed ${MAX_ROLE_NAME_LENGTH} characters.`;
  }
  if (serverRepository.isEveryoneRoleName(name)) {
    return "You cannot create a role named @everyone.";
  }
  if (color && (typeof color !== "string" || !/^#[0-9a-fA-F]{6}$/.test(color))) {
    return "Role color must be a hex value like #5865f2.";
  }
  if (!Number.isInteger(permissions) || permissions < 0 || permissions > serverRepository.ALL_PERMISSIONS) {
    return "Invalid role permissions.";
  }
  if (!permissionsFitActor(permissions, actor)) {
    return "Roles can only include permissions you already have.";
  }
  return null;
}

function isPrivateIpv4(address) {
  const parts = address.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

function isPrivateAddress(address) {
  if (!address) return true;
  const family = net.isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) {
    const normalized = address.toLowerCase();
    if (normalized === "::1" || normalized === "::" || normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) return true;
    if (normalized.startsWith("::ffff:")) return isPrivateIpv4(normalized.slice(7));
    return false;
  }
  return true;
}

async function assertPublicPreviewUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    const err = new Error("Enter a valid http or https URL.");
    err.statusCode = 400;
    throw err;
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    const err = new Error("Only http and https links can be previewed.");
    err.statusCode = 400;
    throw err;
  }

  const addresses = await dns.lookup(parsed.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some((entry) => isPrivateAddress(entry.address))) {
    const err = new Error("This link cannot be previewed.");
    err.statusCode = 400;
    throw err;
  }

  return parsed;
}

async function fetchWithTimeout(url, accept = "text/html,application/xhtml+xml") {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), LINK_PREVIEW_TIMEOUT_MS);
  try {
    return await fetch(url, {
      headers: {
        Accept: accept,
        "User-Agent": "PrivateChatLinkPreview/1.0",
      },
      redirect: "manual",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function readLimitedBytes(response, maxBytes) {
  if (!response.body?.getReader) {
    const buffer = Buffer.from(await response.arrayBuffer());
    return buffer.subarray(0, maxBytes);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = maxBytes - received;
    if (remaining <= 0) break;
    chunks.push(Buffer.from(value.subarray(0, remaining)));
    received += Math.min(value.byteLength, remaining);
    if (received >= maxBytes) break;
  }
  return Buffer.concat(chunks);
}

async function readLimitedText(response) {
  if (!response.body?.getReader) {
    const text = await response.text();
    return text.slice(0, LINK_PREVIEW_MAX_BYTES);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = LINK_PREVIEW_MAX_BYTES - received;
    if (remaining <= 0) break;
    chunks.push(Buffer.from(value.slice(0, remaining)));
    received += Math.min(value.byteLength, remaining);
    if (received >= LINK_PREVIEW_MAX_BYTES) break;
  }
  return Buffer.concat(chunks).toString("utf8");
}

function decodeHtmlEntities(value) {
  return String(value || "")
    .replace(/&#(\d+);/g, (match, code) => {
      const point = Number.parseInt(code, 10);
      return Number.isInteger(point) && point >= 0 && point <= 0x10ffff ? String.fromCodePoint(point) : match;
    })
    .replace(/&#x([0-9a-f]+);/gi, (match, code) => {
      const point = Number.parseInt(code, 16);
      return Number.isInteger(point) && point >= 0 && point <= 0x10ffff ? String.fromCodePoint(point) : match;
    })
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function cleanPreviewText(value, maxLength = 240) {
  return decodeHtmlEntities(value)
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function getAttribute(tag, attr) {
  const match = tag.match(new RegExp(`${attr}\\s*=\\s*["']([^"']*)["']`, "i"));
  return match ? match[1] : "";
}

function findMetaContent(html, names, maxLength = 240) {
  const tags = html.match(/<meta\b[^>]*>/gi) || [];
  const wanted = new Set(names.map((name) => name.toLowerCase()));
  for (const tag of tags) {
    const key = getAttribute(tag, "property") || getAttribute(tag, "name");
    if (wanted.has(key.toLowerCase())) {
      const content = getAttribute(tag, "content");
      if (content) return cleanPreviewText(content, maxLength);
    }
  }
  return "";
}

function findTitle(html) {
  const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? cleanPreviewText(match[1], 120) : "";
}

function findJsonLdValues(html) {
  const scripts = html.match(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/gi) || [];
  const values = {};

  function visit(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (!values.title && (node.headline || node.name)) values.title = node.headline || node.name;
    if (!values.description && node.description) values.description = node.description;
    if (!values.image && node.image) {
      values.image = Array.isArray(node.image) ? node.image[0] : node.image.url || node.image;
    }
    Object.values(node).forEach(visit);
  }

  for (const script of scripts) {
    const body = script.replace(/^<script\b[^>]*>/i, "").replace(/<\/script>$/i, "");
    try {
      visit(JSON.parse(decodeHtmlEntities(body)));
    } catch {
      // Ignore malformed structured data and keep using Open Graph/Twitter tags.
    }
  }

  return {
    title: cleanPreviewText(values.title, 120),
    description: cleanPreviewText(values.description),
    image: cleanPreviewText(values.image, 500),
  };
}

async function resolvePublicPreviewAsset(rawUrl, baseUrl) {
  if (!rawUrl) return "";
  try {
    const parsed = await assertPublicPreviewUrl(new URL(rawUrl, baseUrl).href);
    return parsed.href;
  } catch {
    return "";
  }
}

function normalizeThemeColor(value) {
  const color = String(value || "").trim();
  if (/^#[0-9a-f]{3}([0-9a-f]{3})?$/i.test(color)) return color;
  if (/^rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}(?:\s*,\s*(?:0|1|0?\.\d+))?\s*\)$/i.test(color)) return color;
  return "";
}

function buildInternalInvitePreview(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }

  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || !PUBLIC_INVITE_HOSTS.has(parsed.hostname.toLowerCase())) {
    return null;
  }

  const match = parsed.pathname.match(/^\/invite\/([^/]+)\/?$/i);
  if (!match) return null;

  let code = "";
  try {
    code = decodeURIComponent(match[1]);
  } catch {
    return null;
  }

  const record = getInviteServer(code);
  if (!record) {
    return {
      type: "server_invite",
      url: inviteUrl(code),
      host: parsed.hostname,
      siteName: "PrivChat",
      title: "PrivChat Invite",
      description: "This invite is invalid or has expired.",
      imageAlt: "PrivChat",
      isValidInvite: false,
      themeColor: "#5865f2",
    };
  }

  return invitePreviewSummary(record.invite, record.server);
}

async function buildLinkPreview(rawUrl) {
  const internalInvite = buildInternalInvitePreview(rawUrl);
  if (internalInvite) return internalInvite;

  let current = await assertPublicPreviewUrl(rawUrl);
  let response = null;

  for (let redirects = 0; redirects <= LINK_PREVIEW_MAX_REDIRECTS; redirects += 1) {
    response = await fetchWithTimeout(current.href);
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      current = await assertPublicPreviewUrl(new URL(response.headers.get("location"), current.href).href);
      continue;
    }
    break;
  }

  const host = current.hostname.replace(/^www\./i, "");
  if (!response?.ok) {
    return { url: current.href, host, siteName: host, title: host, description: "" };
  }

  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("text/html") && !contentType.includes("application/xhtml+xml")) {
    return { url: current.href, host, siteName: host, title: host, description: "" };
  }

  const html = await readLimitedText(response);
  const jsonLd = findJsonLdValues(html);
  const siteName = findMetaContent(html, ["og:site_name"]) || host;
  const title = findMetaContent(html, ["og:title", "twitter:title"]) || jsonLd.title || findTitle(html) || host;
  const description = findMetaContent(html, ["og:description", "twitter:description", "description"]) || jsonLd.description;
  const rawImage =
    findMetaContent(html, ["og:image:secure_url", "og:image:url", "og:image", "twitter:image", "twitter:image:src"], 1000) ||
    jsonLd.image;
  const imageUrl = await resolvePublicPreviewAsset(rawImage, current.href);
  const imageAlt = findMetaContent(html, ["og:image:alt", "twitter:image:alt"]);
  const themeColor = normalizeThemeColor(findMetaContent(html, ["theme-color", "msapplication-TileColor"]));
  return { url: current.href, host, siteName, title, description, imageUrl, imageAlt, themeColor };
}

function detectImageMime(buffer, allowGif = false) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) return "image/png";
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "image/jpeg";
  if (buffer.toString("ascii", 0, 4) === "RIFF" && buffer.toString("ascii", 8, 12) === "WEBP") return "image/webp";
  // GIF87a / GIF89a - banners allow animated GIFs, like profile banners do.
  if (allowGif
    && buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38
    && (buffer[4] === 0x37 || buffer[4] === 0x39) && buffer[5] === 0x61) return "image/gif";
  return null;
}

/**
 * Loads the server and the requester's membership/permissions, writing the
 * error response itself when access is denied. Returns null in that case.
 */
async function requireServerAccess(req, res, { permission = null, ownerOnly = false } = {}) {
  const user = await requireAuth(req);
  if (!user) {
    res.status(401).json({ message: "Not signed in." });
    return null;
  }

  const server = serverRepository.getServer(req.params.serverId);
  if (!server) {
    res.status(404).json({ message: "Server not found." });
    return null;
  }

  if (!serverRepository.isMember(server.server_id, user.user_id)) {
    res.status(403).json({ message: "You are not a member of this server." });
    return null;
  }

  if (ownerOnly && server.owner_id !== user.user_id) {
    res.status(403).json({ message: "Only the server owner can do this." });
    return null;
  }

  const myPermissions = serverRepository.getMemberPermissions(server.server_id, user.user_id);
  if (permission && !serverRepository.hasPermission(myPermissions, permission)) {
    res.status(403).json({ message: "You do not have permission to do this." });
    return null;
  }

  return { user, server, myPermissions };
}

function notifyMemberUpdate(serverId) {
  broadcastToServerMembers(serverId, { type: "server_member_update", serverId });
}

function notifyServerUpdate(serverId) {
  broadcastToServerMembers(serverId, { type: "server_update", serverId });
}

// ── Servers ──────────────────────────────────────────────────────────────────

// Channels/categories a brand-new server starts with. Every path creates a real
// category + channel(s); the plain "Create My Own" path falls back to a "text
// channels" category with a single #general. Permissions use the existing
// per-channel overwrite system - no new permissions - on the @everyone role.
function applyServerTemplate(serverId, template) {
  if (template === "Friends") {
    // A relaxed hangout server: let @everyone ping @everyone, on top of the
    // default embed/file access they already get.
    const everyone = serverRepository.getEveryonePermissions(serverId);
    serverRepository.updateEveryonePermissions(
      serverId, everyone | PERMISSIONS.MENTION_EVERYONE
    );

    // text channels › #general, #moments
    const text = serverRepository.createCategory(serverId, "text channels");
    const general = serverRepository.createChannel(serverId, "general", text.category_id);
    const moments = serverRepository.createChannel(serverId, "moments", text.category_id);

    // voice channels › vc1, vc2
    const voice = serverRepository.createCategory(serverId, "voice channels");
    const vc1 = serverRepository.createChannel(serverId, "vc1", voice.category_id, false, "voice");
    const vc2 = serverRepository.createChannel(serverId, "vc2", voice.category_id, false, "voice");

    return [general, moments, vc1, vc2];
  }

  if (template === "Product Showcase") {
    // information › #announcements, #updates: @everyone can read but not post.
    const info = serverRepository.createCategory(serverId, "information");
    const announcements = serverRepository.createChannel(serverId, "announcements", info.category_id);
    serverRepository.setChannelOverwrite(announcements.channel_id, "role", EVERYONE_ROLE_ID, 0, PERMISSIONS.SEND_MESSAGES);
    const updates = serverRepository.createChannel(serverId, "updates", info.category_id);
    serverRepository.setChannelOverwrite(updates.channel_id, "role", EVERYONE_ROLE_ID, 0, PERMISSIONS.SEND_MESSAGES);

    // chat › #general (talk only, no embeds/files) + #media (embeds/files allowed).
    const chat = serverRepository.createCategory(serverId, "chat");
    const general = serverRepository.createChannel(serverId, "general", chat.category_id);
    serverRepository.setChannelOverwrite(general.channel_id, "role", EVERYONE_ROLE_ID, 0, PERMISSIONS.SEND_EMBEDS);
    const media = serverRepository.createChannel(serverId, "media", chat.category_id);
    serverRepository.setChannelOverwrite(media.channel_id, "role", EVERYONE_ROLE_ID, PERMISSIONS.SEND_EMBEDS, 0);

    // voice › discussion
    const voice = serverRepository.createCategory(serverId, "voice");
    const discussion = serverRepository.createChannel(serverId, "discussion", voice.category_id, false, "voice");

    return [announcements, updates, general, media, discussion];
  }

  if (template !== "IRC") {
    // Blank "Create My Own" server: make a REAL "text channels" category with
    // #general inside (exactly like the named templates above) instead of a
    // top-level uncategorized channel. An uncategorized channel renders under the
    // hardcoded, non-renameable "TEXT CHANNELS" section header - which looks like
    // a category but isn't one, so it can't be renamed. A real category can.
    const text = serverRepository.createCategory(serverId, "text channels");
    const general = serverRepository.createChannel(serverId, "general", text.category_id);
    return [general];
  }

  // important › #announcements: @everyone can read but not post.
  const important = serverRepository.createCategory(serverId, "important");
  const announcements = serverRepository.createChannel(serverId, "announcements", important.category_id);
  serverRepository.setChannelOverwrite(announcements.channel_id, "role", EVERYONE_ROLE_ID, 0, PERMISSIONS.SEND_MESSAGES);

  // chat › #general: everyone can talk, but no embeds/file uploads.
  const chat = serverRepository.createCategory(serverId, "chat");
  const general = serverRepository.createChannel(serverId, "general", chat.category_id);
  serverRepository.setChannelOverwrite(
    general.channel_id, "role", EVERYONE_ROLE_ID, 0, PERMISSIONS.SEND_EMBEDS
  );

  // chat › #media: everyone can talk AND share files/embeds. A 5s slowmode keeps
  // the upload spam down.
  const media = serverRepository.createChannel(serverId, "media", chat.category_id);
  serverRepository.setChannelOverwrite(media.channel_id, "role", EVERYONE_ROLE_ID, PERMISSIONS.SEND_EMBEDS, 0);
  serverRepository.setChannelSlowmode(media.channel_id, 5);

  return [announcements, general, media];
}

async function createServer(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const validationError = validateServerName(name);
    if (validationError) return res.status(400).json({ message: validationError });

    // A self-hosted box hosts exactly ONE community (one instance = one
    // IP/domain = one federation identity). Not configurable - hosting more
    // means running more instances.
    if (serverRepository.countAllServers() >= 1) {
      return res.status(403).json({
        message: "This server already hosts its community. A self-hosted server hosts one community per instance.",
      });
    }

    if (serverRepository.countServersForUser(user.user_id) >= MAX_SERVERS_PER_USER) {
      return res.status(403).json({
        message: `You are in the maximum of ${MAX_SERVERS_PER_USER} servers. Leave one before creating another.`,
      });
    }

    const server = serverRepository.createServer({ ownerId: user.user_id, name });
    serverRepository.addMember(server.server_id, user.user_id);
    const template = typeof req.body?.template === "string" ? req.body.template : "";
    const channels = applyServerTemplate(server.server_id, template);

    return res.status(201).json({
      server: serverSummary(server, user.user_id),
      channels: channels.map(publicChannel),
    });
  } catch (err) {
    return next(err);
  }
}

async function listMyServers(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const servers = serverRepository.listServersForUser(user.user_id)
      .map((server) => serverSummary(server, user.user_id));
    return res.json({ servers, maxServers: MAX_SERVERS_PER_USER });
  } catch (err) {
    return next(err);
  }
}

async function listDiscoveryServers(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const query = String(req.query.q || "").trim().slice(0, 80);
    const rows = serverRepository.listDiscoveryServers(query, 40)
      .filter((row) => !serverRepository.isBanned(row.server_id, user.user_id));
    const servers = rows.map((row) => ({
      serverId: row.server_id,
      name: row.name,
      iconUrl: `/api/servers/${encodeURIComponent(row.server_id)}/icon?v=${encodeURIComponent(row.updated_at || row.server_created_at || "")}`,
      hasIcon: Boolean(row.icon_mime),
      bannerUrl: `/api/servers/${encodeURIComponent(row.server_id)}/banner?v=${encodeURIComponent(row.updated_at || row.server_created_at || "")}`,
      hasBanner: Boolean(row.banner_mime),
      about: row.about || "",
      memberCount: row.member_count || 0,
      onlineCount: countOnlineMembers(row.server_id),
      joined: serverRepository.isMember(row.server_id, user.user_id),
      inviteCode: row.invite_code,
      inviteUrl: inviteUrl(row.invite_code),
    }));
    return res.json({ servers, query });
  } catch (err) {
    return next(err);
  }
}

async function getMyDiscoveryApplication(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { ownerOnly: true });
    if (!access) return undefined;
    const { server } = access;

    const application = serverRepository.getDiscoveryApplication(server.server_id);
    const entry = serverRepository.getDiscoveryEntry(server.server_id);
    const block = serverRepository.getDiscoveryBlock(server.server_id);
    return res.json({
      discovery: discoveryApplicationSummary(application, entry, block),
      limits: {
        minAboutLength: MIN_DISCOVERY_ABOUT_LENGTH,
        maxAboutLength: MAX_DISCOVERY_ABOUT_LENGTH,
      },
    });
  } catch (err) {
    return next(err);
  }
}

async function applyForDiscovery(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { ownerOnly: true });
    if (!access) return undefined;
    const { user, server } = access;

    if (serverRepository.isDiscoveryBlocked(server.server_id)) {
      return res.status(403).json({ message: "This server cannot apply for discovery right now." });
    }
    if (serverRepository.getDiscoveryEntry(server.server_id)) {
      return res.status(409).json({ message: "This server is already in discovery." });
    }

    const about = String(req.body?.about || "").trim().replace(/\s+/g, " ");
    if (about.length < MIN_DISCOVERY_ABOUT_LENGTH) {
      return res.status(400).json({ message: `Write at least ${MIN_DISCOVERY_ABOUT_LENGTH} characters about your server.` });
    }
    if (about.length > MAX_DISCOVERY_ABOUT_LENGTH) {
      return res.status(400).json({ message: `Keep it under ${MAX_DISCOVERY_ABOUT_LENGTH} characters.` });
    }

    const application = serverRepository.submitDiscoveryApplication(server.server_id, user.user_id, about);
    return res.status(201).json({
      discovery: discoveryApplicationSummary(application, null, null),
      limits: {
        minAboutLength: MIN_DISCOVERY_ABOUT_LENGTH,
        maxAboutLength: MAX_DISCOVERY_ABOUT_LENGTH,
      },
    });
  } catch (err) {
    return next(err);
  }
}

// Save the user's custom server-rail order (drag-to-reorder). Body: { serverIds:
// [...] } in top-to-bottom order. Only the caller's own membership rows are
// touched, so this can't affect anyone else's rail.
async function reorderServers(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const ids = Array.isArray(req.body?.serverIds) ? req.body.serverIds : null;
    if (!ids) return res.status(400).json({ message: "serverIds must be an array." });

    // De-dupe + keep only ids the caller is actually a member of, preserving the
    // requested order. Anything else is ignored rather than rejected.
    const seen = new Set();
    const ordered = [];
    for (const id of ids) {
      const serverId = String(id || "");
      if (!serverId || seen.has(serverId)) continue;
      seen.add(serverId);
      if (serverRepository.isMember(serverId, user.user_id)) ordered.push(serverId);
    }

    serverRepository.setServerRailOrder(user.user_id, ordered);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function getServerDetails(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const visibleChannels = serverRepository.listChannels(server.server_id)
      .filter((channel) => canViewChannel(server, channel, user.user_id, myPermissions));

    // Resolve each channel's effective permissions for this user (Discord-style,
    // honouring per-channel overwrites) and surface the few the client needs:
    //   - canSend / canShareFiles → hide the composer + attach button where you
    //     can't post or share files in that channel.
    //   - slowmodeExempt → Manage Channels bypasses the cooldown.
    const channelsForUser = visibleChannels.map((channel) => {
      const channelPerms = serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id);
      return {
        ...publicChannel(channel),
        canSend: serverRepository.hasPermission(channelPerms, PERMISSIONS.SEND_MESSAGES),
        canShareFiles: serverRepository.hasPermission(channelPerms, PERMISSIONS.SEND_EMBEDS),
        canSendEmbeds: serverRepository.hasPermission(channelPerms, PERMISSIONS.SEND_EMBEDS),
        canReact: serverRepository.hasPermission(channelPerms, PERMISSIONS.ADD_REACTIONS),
        slowmodeExempt: channel.slowmode > 0
          ? serverRepository.hasPermission(channelPerms, PERMISSIONS.MANAGE_CHANNELS)
          : true,
      };
    });

    return res.json({
      server: serverSummary(server, user.user_id),
      channels: channelsForUser,
      categories: serverRepository.listCategories(server.server_id).map(publicCategory),
      uncategorizedPosition: server.uncategorized_position || 0,
      roles: [publicEveryoneRole(server), ...serverRepository.listRoles(server.server_id).map(publicRole)],
      myPermissions,
      permissionBits: publicPermissionBits(),
      limits: {
        maxRoleNameLength: MAX_ROLE_NAME_LENGTH,
        maxChannelNameLength: MAX_CHANNEL_NAME_LENGTH,
        maxServerNameLength: MAX_SERVER_NAME_LENGTH,
      },
    });
  } catch (err) {
    return next(err);
  }
}

async function updateServer(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const { user, server } = access;

    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const validationError = validateServerName(name);
    if (validationError) return res.status(400).json({ message: validationError });

    serverRepository.updateServerName(server.server_id, name);
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true, name });
  } catch (err) {
    return next(err);
  }
}

async function deleteServer(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { ownerOnly: true });
    if (!access) return undefined;
    const { server } = access;

    // Grab the icon + banner keys before the row is gone so we can purge them
    // from B2 too - deletion should leave no trace of the server anywhere.
    const iconRef = serverRepository.getServerIcon(server.server_id);
    const bannerRef = serverRepository.getServerBanner(server.server_id);

    // Tell members before the membership rows disappear.
    broadcastToServerMembers(server.server_id, { type: "server_deleted", serverId: server.server_id });
    await serverRepository.deleteServerCascade(server.server_id);
    if (iconRef?.icon_key) await b2Storage.deleteMedia(iconRef.icon_key);
    if (bannerRef?.banner_key) await b2Storage.deleteMedia(bannerRef.banner_key);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// Hand the server to another member. Owner-only; the previous owner becomes a
// regular member afterward.
async function transferOwnership(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { ownerOnly: true });
    if (!access) return undefined;
    const { user, server } = access;

    const target = userRepository.findByAnyId(req.body?.userId);
    if (!target) {
      return res.status(404).json({ message: "That member could not be found." });
    }
    if (target.user_id === server.owner_id) {
      return res.status(400).json({ message: "You already own this server." });
    }
    if (!serverRepository.isMember(server.server_id, target.user_id)) {
      return res.status(400).json({ message: "You can only transfer ownership to a member of this server." });
    }

    serverRepository.updateServerOwner(server.server_id, target.user_id);
    notifyServerUpdate(server.server_id);
    notifyMemberUpdate(server.server_id);
    const newOwnerName = target.profile_alias || target.username || "the new owner";
    return res.json({ ok: true, newOwnerId: getPublicId(target), newOwnerName });
  } catch (err) {
    return next(err);
  }
}

// ── Icon ─────────────────────────────────────────────────────────────────────

async function uploadServerIcon(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const { user, server } = access;

    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ message: "Choose a server avatar to upload." });
    }
    if (req.body.length > MAX_SERVER_AVATAR_BYTES) {
      return res.status(413).json({ message: "Server avatar cannot be over 3 MB." });
    }

    const mime = detectImageMime(req.body);
    if (!mime) {
      return res.status(400).json({ message: "Icon must be a PNG, JPEG, or WEBP image." });
    }

    const iconKey = await b2Storage.uploadMedia({
      ownerId: user.public_user_id || user.user_id,
      buffer: req.body,
      contentType: mime,
      metadata: { "server-id": server.server_id },
    });
    serverRepository.updateServerIcon(server.server_id, iconKey, mime);
    const updatedServer = serverRepository.getServer(server.server_id) || server;
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true, server: serverSummary(updatedServer, user.user_id) });
  } catch (err) {
    return next(err);
  }
}

async function getServerIconImage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const record = serverRepository.getServerIcon(req.params.serverId);
    if (!record) return res.status(404).json({ message: "Server not found." });

    if (record.icon_key) {
      try {
        const media = await b2Storage.getMedia(record.icon_key);
        res.setHeader("Content-Type", media.contentType || record.icon_mime || "application/octet-stream");
        res.setHeader("Cache-Control", "private, max-age=60");
        return res.send(media.body);
      } catch {
        // Object missing/unreachable - fall back to the generated default below.
      }
    }

    const fallback = generateInitialProfilePicture(record.name, { square: true });
    res.setHeader("Content-Type", fallback.mimeType);
    res.setHeader("Cache-Control", "private, max-age=60");
    return res.send(fallback.data);
  } catch (err) {
    return next(err);
  }
}

// ── Banner ───────────────────────────────────────────────────────────────────

// Per-SERVER banner rate limit: at most 2 completed banner changes per hour.
// Enforced in-controller (after the permission check) so only authorized changes
// count and one server can't burn another's quota. In-memory + sliding window.
const BANNER_CHANGES_PER_HOUR = 2;
const BANNER_WINDOW_MS = 60 * 60 * 1000;
const bannerChangeLog = new Map(); // serverId -> number[] (ms timestamps)

function bannerChangesInWindow(serverId) {
  const now = Date.now();
  const recent = (bannerChangeLog.get(serverId) || []).filter((t) => now - t < BANNER_WINDOW_MS);
  if (recent.length) bannerChangeLog.set(serverId, recent);
  else bannerChangeLog.delete(serverId);
  return recent;
}

function recordBannerChange(serverId) {
  const recent = bannerChangesInWindow(serverId);
  recent.push(Date.now());
  bannerChangeLog.set(serverId, recent);
}

async function uploadServerBanner(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const { user, server } = access;

    // Rate limit (per server) before doing any upload work.
    if (bannerChangesInWindow(server.server_id).length >= BANNER_CHANGES_PER_HOUR) {
      return res.status(429).json({
        message: `You can only change this server's banner ${BANNER_CHANGES_PER_HOUR} times per hour. Please try again later.`,
      });
    }

    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ message: "Choose a server banner to upload." });
    }

    const mime = detectImageMime(req.body, true); // banners allow GIF too
    if (!mime) {
      return res.status(400).json({ message: "Banner must be a PNG, JPEG, WEBP, or GIF image." });
    }
    // Animated GIF banners get the larger budget; static banners keep the 3 MB cap.
    const bannerLimit = mime === "image/gif" ? MAX_SERVER_BANNER_GIF_BYTES : MAX_SERVER_AVATAR_BYTES;
    if (req.body.length > bannerLimit) {
      return res.status(413).json({ message: `Server banner cannot be over ${mime === "image/gif" ? 10 : 3} MB.` });
    }

    const bannerKey = await b2Storage.uploadMedia({
      ownerId: user.public_user_id || user.user_id,
      buffer: req.body,
      contentType: mime,
      metadata: { "server-id": server.server_id, "kind": "banner" },
    });

    // Remove the previous banner object once the new one is stored.
    const previous = serverRepository.getServerBanner(server.server_id);
    serverRepository.updateServerBanner(server.server_id, bannerKey, mime);
    recordBannerChange(server.server_id);
    if (previous?.banner_key) b2Storage.deleteMedia(previous.banner_key).catch(() => {});

    const updatedServer = serverRepository.getServer(server.server_id) || server;
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true, server: serverSummary(updatedServer, user.user_id) });
  } catch (err) {
    return next(err);
  }
}

async function getServerBannerImage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const record = serverRepository.getServerBanner(req.params.serverId);
    if (!record || !record.banner_key) return res.status(404).end();

    try {
      const media = await b2Storage.getMedia(record.banner_key);
      res.setHeader("Content-Type", media.contentType || record.banner_mime || "application/octet-stream");
      res.setHeader("Cache-Control", "private, max-age=60");
      return res.send(media.body);
    } catch {
      return res.status(404).end();
    }
  } catch (err) {
    return next(err);
  }
}

// ── Invites ──────────────────────────────────────────────────────────────────

async function createInvite(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.CREATE_INVITES });
    if (!access) return undefined;
    const { user, server } = access;

    serverRepository.deleteExpiredInvites();

    // Cap how many active invites one user can hold per server. Expired codes
    // were just cleared above and aren't counted, so slots free up over time.
    const activeInvites = serverRepository.countActiveInvitesByCreator(server.server_id, user.user_id);
    if (activeInvites >= MAX_INVITES_PER_USER_PER_SERVER) {
      return res.status(429).json({
        message: `You've reached your limit of ${MAX_INVITES_PER_USER_PER_SERVER} active invites for this server. Wait for some to expire or delete one before creating more.`,
      });
    }

    // Expiry options (ms; null = permanent) the create-invite GUI offers.
    const EXPIRY_OPTIONS = {
      "1h": 60 * 60 * 1000,
      "1d": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "14d": 14 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
      never: null,
    };
    const expiryKey = typeof req.body?.expiry === "string" && req.body.expiry in EXPIRY_OPTIONS ? req.body.expiry : "7d";
    const ttlMs = EXPIRY_OPTIONS[expiryKey];
    const maxUses = req.body?.singleUse ? 1 : 0;

    const invite = serverRepository.createInvite(server.server_id, user.user_id, { ttlMs, maxUses });
    return res.status(201).json({
      invite: {
        code: invite.code,
        url: inviteUrl(invite.code),
        expiresAt: toUtcIso(invite.expires_at) || invite.expires_at,
        maxUses: invite.max_uses,
      },
    });
  } catch (err) {
    return next(err);
  }
}

async function getPublicInvite(req, res, next) {
  try {
    const record = getInviteServer(req.params.code);
    if (!record) {
      return res.status(404).json({ message: "This invite is invalid or has expired." });
    }

    res.setHeader("Cache-Control", "no-store");
    return res.json({ invite: publicInviteSummary(record.invite, record.server) });
  } catch (err) {
    return next(err);
  }
}

async function getInviteIconImage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).end();

    const record = getInviteServer(req.params.code);
    if (!record) return res.status(404).end();
    if (serverRepository.isBanned(record.server.server_id, user.user_id)) return res.status(403).end();

    const icon = serverRepository.getServerIcon(record.server.server_id);
    if (icon?.icon_key) {
      try {
        const media = await b2Storage.getMedia(icon.icon_key);
        res.setHeader("Content-Type", media.contentType || icon.icon_mime || "application/octet-stream");
        res.setHeader("Cache-Control", "private, max-age=60");
        res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
        return res.send(media.body);
      } catch {
        // Object missing/unreachable - fall through to the generated default below.
      }
    }

    // No custom icon: serve the generated letter avatar (e.g. "S" for Steve, in the
    // server's color) so invite embeds always show a picture, like the server rail.
    const fallback = generateInitialProfilePicture(record.server.name, { square: true });
    res.setHeader("Content-Type", fallback.mimeType);
    res.setHeader("Cache-Control", "private, max-age=60");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    return res.send(fallback.data);
  } catch (err) {
    return next(err);
  }
}

async function getInviteBannerImage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).end();

    const record = getInviteServer(req.params.code);
    if (!record) return res.status(404).end();
    if (serverRepository.isBanned(record.server.server_id, user.user_id)) return res.status(403).end();

    const banner = serverRepository.getServerBanner(record.server.server_id);
    if (!banner?.banner_key) return res.status(404).end();

    try {
      const media = await b2Storage.getMedia(banner.banner_key);
      res.setHeader("Content-Type", media.contentType || banner.banner_mime || "application/octet-stream");
      res.setHeader("Cache-Control", "private, max-age=60");
      res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
      return res.send(media.body);
    } catch {
      return res.status(404).end();
    }
  } catch (err) {
    return next(err);
  }
}

async function listInvites(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const { server } = access;

    serverRepository.deleteExpiredInvites();
    const invites = serverRepository.listInvites(server.server_id).map((invite) => {
      const creator = userRepository.findById(invite.creator_id);
      return {
        code: invite.code,
        url: inviteUrl(invite.code),
        uses: invite.uses,
        maxUses: invite.max_uses || 0,
        invitedCount: invite.invited_count || 0,
        createdAt: toUtcIso(invite.created_at),
        expiresAt: toUtcIso(invite.expires_at) || invite.expires_at,
        createdBy: creator?.username || "unknown",
      };
    });
    return res.json({ invites });
  } catch (err) {
    return next(err);
  }
}

// Who joined the server through one specific invite. Manage Server only.
async function listInviteInvitees(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const { server } = access;

    const code = normalizeInviteCode(req.params.code);
    const invite = code ? serverRepository.getInvite(code) : null;
    if (!invite || invite.server_id !== server.server_id) {
      return res.status(404).json({ message: "Invite not found." });
    }

    const invitees = serverRepository.getInviteUserIds(invite.code)
      .map((userId) => userRepository.findById(userId))
      .filter(Boolean)
      .map((userRow) => {
        const summary = publicUserSummary(userRow);
        return {
          userId: summary.userId,
          username: summary.username,
          alias: summary.alias,
          profilePictureUrl: summary.profilePictureUrl,
          stillMember: serverRepository.isMember(server.server_id, userRow.user_id),
        };
      });
    return res.json({ invitees });
  } catch (err) {
    return next(err);
  }
}

async function revokeInvite(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const { server } = access;

    const code = normalizeInviteCode(req.params.code);
    const invite = code ? serverRepository.getInvite(code) : null;
    if (!invite || invite.server_id !== server.server_id) {
      return res.status(404).json({ message: "Invite not found." });
    }
    serverRepository.deleteInvite(invite.code);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// Revoke every invite for the server in one shot.
async function clearInvites(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const { server } = access;

    const removed = serverRepository.deleteInvitesForServer(server.server_id);
    return res.json({ ok: true, removed });
  } catch (err) {
    return next(err);
  }
}

async function joinByInvite(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const record = getInviteServer(req.params.code);
    if (!record) {
      return res.status(404).json({ message: "This invite is invalid or has expired." });
    }
    const { invite, server } = record;

    if (serverRepository.isBanned(server.server_id, user.user_id)) {
      return res.status(403).json({ message: "You are banned from this server." });
    }

    if (serverRepository.isMember(server.server_id, user.user_id)) {
      return res.json({ server: serverSummary(server, user.user_id), alreadyMember: true });
    }

    if (serverRepository.countServersForUser(user.user_id) >= MAX_SERVERS_PER_USER) {
      return res.status(403).json({
        message: `You are in the maximum of ${MAX_SERVERS_PER_USER} servers. Leave one before joining another.`,
      });
    }

    serverRepository.addMember(server.server_id, user.user_id);
    serverRepository.incrementInviteUses(invite.code);
    serverRepository.recordInviteUse(invite.code, server.server_id, user.user_id);
    // Burn a single-/limited-use invite the moment it's exhausted.
    if (invite.max_uses > 0 && invite.uses + 1 >= invite.max_uses) {
      serverRepository.deleteInvite(invite.code);
    }
    notifyMemberUpdate(server.server_id);

    return res.status(201).json({ server: serverSummary(server, user.user_id), alreadyMember: false });
  } catch (err) {
    return next(err);
  }
}

// ── Members ──────────────────────────────────────────────────────────────────

// Servers at or below this size load every member (online + offline). Larger
// ones only return ONLINE members, 50 at a time (the client scroll-loads more) -
// otherwise the list would mean thousands of cross-DB user lookups per open.
const LARGE_SERVER_THRESHOLD = 1000;
const MEMBERS_PAGE_SIZE = 50;

async function getMembers(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { server } = access;

    const roleAssignments = serverRepository.getAllMemberRoles(server.server_id);
    const rolesByUser = new Map();
    roleAssignments.forEach(({ user_id: userId, role_id: roleId }) => {
      if (!rolesByUser.has(userId)) rolesByUser.set(userId, []);
      rolesByUser.get(userId).push(roleId);
    });

    const now = Date.now();
    const memberRows = serverRepository.getMembers(server.server_id);
    const memberById = new Map(memberRows.map((m) => [m.user_id, m]));

    // If a channel is given, only list members who can actually VIEW it (so a
    // private channel shows exactly the people who can see it - owner, admins,
    // and anyone granted View via an overwrite). Public channels with no
    // overwrites skip this entirely (fast path: everyone can view).
    const channelId = req.query.channelId ? String(req.query.channelId) : null;
    const scopedChannel = channelId ? serverRepository.getChannel(channelId) : null;
    const channelOk = scopedChannel && scopedChannel.server_id === server.server_id;
    const restricted = channelOk
      && (scopedChannel.is_private || serverRepository.getChannelOverwrites(scopedChannel.channel_id).length > 0);
    const canMemberView = (userId) => !restricted
      || serverRepository.hasPermission(
        serverRepository.channelPermissionsFor(server.server_id, scopedChannel, userId), PERMISSIONS.VIEW_CHANNEL
      );

    const buildMember = (member) => {
      const userRow = userRepository.findById(member.user_id);
      if (!userRow) return null;
      // timeout_until is stored as a full ISO string (…Z), so parse it directly.
      const timeoutMs = member.timeout_until ? new Date(member.timeout_until).getTime() : 0;
      return {
        ...publicUserSummary(userRow),
        isOwner: member.user_id === server.owner_id,
        isOnline: isPublicOnline(userRow),
        presenceStatus: publicPresenceStatus(userRow),
        roleIds: rolesByUser.get(member.user_id) || [],
        joinedAt: toUtcIso(member.joined_at),
        timeoutUntil: timeoutMs > now ? toUtcIso(member.timeout_until) : null,
        nickname: member.nickname || null,
      };
    };

    // Settings "Members" tab: a manager can page through EVERY member (online and
    // offline) regardless of server size, to manage them. Gated behind a member-
    // management permission so it isn't a member-enumeration backdoor on huge servers.
    if (req.query.all === "1") {
      const isOwnerViewer = server.owner_id === access.user.user_id;
      const canManage = isOwnerViewer
        || serverRepository.hasPermission(access.myPermissions, PERMISSIONS.ADMINISTRATOR)
        || serverRepository.hasPermission(access.myPermissions, PERMISSIONS.MANAGE_SERVER)
        || serverRepository.hasPermission(access.myPermissions, PERMISSIONS.MANAGE_ROLES)
        || serverRepository.hasPermission(access.myPermissions, PERMISSIONS.KICK_MEMBERS)
        || serverRepository.hasPermission(access.myPermissions, PERMISSIONS.BAN_MEMBERS);
      if (canManage) {
        const ALL_PAGE = 100;
        const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
        const slice = memberRows.slice(offset, offset + ALL_PAGE);
        const members = slice.map(buildMember).filter(Boolean);
        return res.json({
          members,
          total: memberRows.length,
          onlineOnly: false,
          offset,
          hasMore: offset + slice.length < memberRows.length,
        });
      }
    }

    // Small server - return the whole list, grouped client-side as before.
    if (memberRows.length <= LARGE_SERVER_THRESHOLD) {
      const members = memberRows
        .filter((m) => canMemberView(m.user_id))
        .map(buildMember)
        .filter(Boolean);
      return res.json({ members, total: memberRows.length, onlineOnly: false, hasMore: false });
    }

    // Large server - online members only, paged (full user lookups only for the page).
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const { total: onlineTotal, ids: pageIds } = userRepository.filterOnlineMemberIds(
      memberRows.map((m) => m.user_id), MEMBERS_PAGE_SIZE, offset
    );
    const members = pageIds
      .filter((id) => canMemberView(id))
      .map((id) => memberById.get(id))
      .filter(Boolean)
      .map(buildMember)
      .filter(Boolean);

    return res.json({
      members,
      total: memberRows.length,
      online: onlineTotal,
      onlineOnly: true,
      offset,
      hasMore: offset + members.length < onlineTotal,
    });
  } catch (err) {
    return next(err);
  }
}

async function leaveServer(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server } = access;

    if (server.owner_id === user.user_id) {
      return res.status(400).json({ message: "Owners cannot leave their own server. Delete it instead." });
    }

    serverRepository.removeMember(server.server_id, user.user_id);
    notifyMemberUpdate(server.server_id);
    broadcastToUser(user.user_id, { type: "server_removed", serverId: server.server_id });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

function resolveTargetMember(req, res, server) {
  const target = userRepository.findByAnyId(req.params.userId);
  if (!target) {
    res.status(404).json({ message: "User not found." });
    return null;
  }
  if (target.user_id === server.owner_id) {
    res.status(403).json({ message: "You cannot remove the server owner." });
    return null;
  }
  return target;
}

async function kickMember(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.KICK_MEMBERS });
    if (!access) return undefined;
    const { user, server } = access;

    const target = resolveTargetMember(req, res, server);
    if (!target) return undefined;
    if (target.user_id === user.user_id) {
      return res.status(400).json({ message: "Use Leave Server instead." });
    }
    if (!serverRepository.isMember(server.server_id, target.user_id)) {
      return res.status(404).json({ message: "That user is not a member." });
    }
    if (!serverRepository.canModerateMember(server.server_id, user.user_id, target.user_id)) {
      return res.status(403).json({ message: "You can only kick members below your highest role." });
    }

    serverRepository.removeMember(server.server_id, target.user_id);
    broadcastToUser(target.user_id, { type: "server_removed", serverId: server.server_id });
    notifyMemberUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// Ban reasons are capped at 30 words; an empty reason falls back to "N/A".
function normalizeBanReason(raw) {
  if (typeof raw !== "string") return "N/A";
  const reason = raw.trim().split(/\s+/).filter(Boolean).slice(0, 30).join(" ").slice(0, 300);
  return reason || "N/A";
}

async function banMember(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.BAN_MEMBERS });
    if (!access) return undefined;
    const { user, server } = access;

    const target = resolveTargetMember(req, res, server);
    if (!target) return undefined;
    if (target.user_id === user.user_id) {
      return res.status(400).json({ message: "You cannot ban yourself." });
    }
    if (!serverRepository.canModerateMember(server.server_id, user.user_id, target.user_id)) {
      return res.status(403).json({ message: "You can only ban members below your highest role." });
    }

    serverRepository.addBan(server.server_id, target.user_id, user.user_id, normalizeBanReason(req.body?.reason));
    serverRepository.removeMember(server.server_id, target.user_id);
    broadcastToUser(target.user_id, { type: "server_removed", serverId: server.server_id });
    notifyMemberUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function unbanMember(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.BAN_MEMBERS });
    if (!access) return undefined;
    const { server } = access;

    const target = userRepository.findByAnyId(req.params.userId);
    if (!target) return res.status(404).json({ message: "User not found." });

    serverRepository.removeBan(server.server_id, target.user_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// Allowed timeout durations in milliseconds (0 = remove timeout):
// 30m, 1h, 4h, 6h, 12h, 24h, 3d.
const TIMEOUT_DURATIONS = new Set([0, 1800000, 3600000, 14400000, 21600000, 43200000, 86400000, 259200000]);

async function timeoutMember(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.KICK_MEMBERS });
    if (!access) return undefined;
    const { user, server } = access;

    const target = resolveTargetMember(req, res, server);
    if (!target) return undefined;
    if (target.user_id === user.user_id) {
      return res.status(400).json({ message: "You cannot time yourself out." });
    }
    if (!serverRepository.isMember(server.server_id, target.user_id)) {
      return res.status(404).json({ message: "That user is not a member." });
    }
    if (!serverRepository.canModerateMember(server.server_id, user.user_id, target.user_id)) {
      return res.status(403).json({ message: "You can only time out members below your highest role." });
    }

    const durationMs = Number(req.body?.durationMs);
    if (!Number.isInteger(durationMs) || !TIMEOUT_DURATIONS.has(durationMs)) {
      return res.status(400).json({ message: "Invalid timeout duration." });
    }

    const until = durationMs > 0 ? new Date(Date.now() + durationMs).toISOString() : null;
    serverRepository.setMemberTimeout(server.server_id, target.user_id, until);
    notifyMemberUpdate(server.server_id);
    return res.json({ ok: true, timeoutUntil: until });
  } catch (err) {
    return next(err);
  }
}

// ── AutoMod ────────────────────────────────────────────────────────────────────

// Carry out the punishment an AutoMod verdict calls for (the message itself is
// already blocked by the caller). "delete" needs nothing extra; the rest remove or
// restrict the sender, reusing the same primitives as manual moderation. AutoMod
// actions are attributed to the server owner in the ban log (there's no acting mod).
async function applyAutomodAction({ server, target, verdict }) {
  try {
    if (verdict.action === "timeout") {
      const until = new Date(Date.now() + verdict.timeoutMs).toISOString();
      serverRepository.setMemberTimeout(server.server_id, target.user_id, until);
      notifyMemberUpdate(server.server_id);
    } else if (verdict.action === "kick") {
      serverRepository.removeMember(server.server_id, target.user_id);
      broadcastToUser(target.user_id, { type: "server_removed", serverId: server.server_id });
      notifyMemberUpdate(server.server_id);
    } else if (verdict.action === "ban") {
      serverRepository.addBan(server.server_id, target.user_id, server.owner_id, normalizeBanReason(verdict.reason));
      serverRepository.removeMember(server.server_id, target.user_id);
      broadcastToUser(target.user_id, { type: "server_removed", serverId: server.server_id });
      notifyMemberUpdate(server.server_id);
    }
    // "delete": message already blocked, nothing further to do.
  } catch (err) {
    console.error("AutoMod action failed:", err);
  }
}

// GET the server's AutoMod config (owner / Manage Server only - it's a mod tool).
async function getAutomod(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    return res.json({ config: automod.loadConfig(access.server.server_id), timeoutOptions: automod.TIMEOUT_OPTIONS });
  } catch (err) {
    return next(err);
  }
}

// Replace the server's AutoMod config. The body is fully re-sanitised server-side
// (sanitizeConfig) so a tampered payload can't smuggle in an invalid action/duration.
async function updateAutomod(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_SERVER });
    if (!access) return undefined;
    const saved = automod.saveConfig(access.server.server_id, req.body?.config);
    return res.json({ ok: true, config: saved });
  } catch (err) {
    return next(err);
  }
}

// ── Per-server privacy ("Manage Privacy" on a server) ────────────────────────
// Any member can opt out of pings, DMs, and/or friend requests that reach them
// because of THIS server. DM + friend-request blocks are enforced server-side
// (friendService); the ping block is applied client-side (the message still
// arrives, it just doesn't ping). Stored per (member, server).
async function getServerPrivacy(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const privacy = serverPrivacyRepository.getForUserServer(access.user.user_id, access.server.server_id);
    return res.json({ ok: true, privacy });
  } catch (err) {
    return next(err);
  }
}

async function setServerPrivacy(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const body = req.body || {};
    const privacy = {
      blockPings: Boolean(body.blockPings),
      blockDms: Boolean(body.blockDms),
      blockFriendRequests: Boolean(body.blockFriendRequests),
    };
    serverPrivacyRepository.setForUserServer(access.user.user_id, access.server.server_id, privacy);
    return res.json({ ok: true, privacy });
  } catch (err) {
    return next(err);
  }
}

// The set of servers where the signed-in user has the ping block on, so the
// client can silence those mentions as they arrive (ping block is client-applied).
async function getMyPingBlockedServers(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    return res.json({ ok: true, pingBlocked: serverPrivacyRepository.getPingBlockedServerIds(user.user_id) });
  } catch (err) {
    return next(err);
  }
}

// Set (or clear) a member's per-server nickname. You can always change your own
// if you have Change Nickname (granted to @everyone by default); changing someone
// else's needs Manage Server / admin / owner. Nobody but the owner can rename the
// owner.
async function setMemberNickname(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const target = resolveTargetMember(req, res, server);
    if (!target) return undefined;
    if (!serverRepository.isMember(server.server_id, target.user_id)) {
      return res.status(404).json({ message: "That user is not a member." });
    }

    const isSelf = target.user_id === user.user_id;
    const isOwner = server.owner_id === user.user_id;
    const isAdmin = isOwner || serverRepository.hasPermission(myPermissions, PERMISSIONS.ADMINISTRATOR);
    const canManageOthers = isAdmin || serverRepository.hasPermission(myPermissions, PERMISSIONS.MANAGE_SERVER);
    const canChangeOwn = isAdmin || serverRepository.hasPermission(myPermissions, PERMISSIONS.CHANGE_NICKNAME);

    if (isSelf && !canChangeOwn) {
      return res.status(403).json({ message: "You don't have permission to change your nickname here." });
    }
    if (!isSelf && !canManageOthers) {
      return res.status(403).json({ message: "You need Manage Server to change other people's nicknames." });
    }
    if (!isSelf && target.user_id === server.owner_id && !isOwner) {
      return res.status(403).json({ message: "Only the owner can change the owner's nickname." });
    }

    const raw = typeof req.body?.nickname === "string" ? req.body.nickname.trim() : "";
    if (raw.length > serverRepository.MAX_NICKNAME_LENGTH) {
      return res.status(400).json({ message: `Nicknames can be at most ${serverRepository.MAX_NICKNAME_LENGTH} characters.` });
    }
    const nickname = serverRepository.setMemberNickname(server.server_id, target.user_id, raw);
    notifyMemberUpdate(server.server_id);
    return res.json({ ok: true, nickname });
  } catch (err) {
    return next(err);
  }
}

async function listBannedMembers(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.BAN_MEMBERS });
    if (!access) return undefined;
    const { server } = access;

    const bans = serverRepository.listBans(server.server_id)
      .map((ban) => {
        const userRow = userRepository.findById(ban.user_id);
        if (!userRow) return null;
        // Resolve who issued the ban (the owner before account transfer, a mod, etc.).
        const mod = ban.banned_by ? userRepository.findById(ban.banned_by) : null;
        const bannedBy = mod ? (mod.profile_alias || mod.username) : "Unknown";
        const bannedByAvatarUrl = mod ? pfpUrl(mod) : "";
        return { ...publicUserSummary(userRow), reason: ban.reason || "N/A", bannedAt: toUtcIso(ban.created_at), bannedBy, bannedByAvatarUrl };
      })
      .filter(Boolean);
    return res.json({ bans });
  } catch (err) {
    return next(err);
  }
}

// ── Roles ────────────────────────────────────────────────────────────────────

async function createRole(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_ROLES });
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const color = typeof req.body?.color === "string" && req.body.color ? req.body.color : null;
    const permissions = serverRepository.normalizeMergedPermissions(Number(req.body?.permissions ?? 0));
    const hoist = Boolean(req.body?.hoist);
    const validationError = validateRoleInput(
      { name, color, permissions },
      { isOwner: server.owner_id === user.user_id, myPermissions }
    );
    if (validationError) return res.status(400).json({ message: validationError });

    if (serverRepository.countRoles(server.server_id) >= MAX_ROLES_PER_SERVER) {
      return res.status(400).json({ message: `Servers can have at most ${MAX_ROLES_PER_SERVER} roles.` });
    }

    const role = serverRepository.createRole({ serverId: server.server_id, name, color, permissions, hoist });
    notifyServerUpdate(server.server_id);
    return res.status(201).json({ role: publicRole(role) });
  } catch (err) {
    return next(err);
  }
}

async function updateRole(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_ROLES });
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    if (serverRepository.isEveryoneRoleId(req.params.roleId)) {
      const isOwner = server.owner_id === user.user_id;
      const permissions = req.body?.permissions === undefined
        ? serverRepository.getEveryonePermissions(server.server_id)
        : serverRepository.normalizeMergedPermissions(Number(req.body.permissions));
      const validationError = validateRoleInput(
        { name: "everyone", color: null, permissions },
        { isOwner, myPermissions }
      );
      if (validationError) return res.status(400).json({ message: validationError });

      serverRepository.updateEveryonePermissions(server.server_id, permissions);
      notifyServerUpdate(server.server_id);
      notifyMemberUpdate(server.server_id);
      return res.json({ role: publicEveryoneRole(server) });
    }

    const role = serverRepository.getRole(req.params.roleId);
    if (!role || role.server_id !== server.server_id) {
      return res.status(404).json({ message: "Role not found." });
    }

    const isOwner = server.owner_id === user.user_id;
    const actor = { isOwner, myPermissions };
    if (!roleFitsActor(role, actor)) {
      return res.status(403).json({ message: "You can only edit roles with permissions you already have." });
    }
    if (!serverRepository.canManageRolePosition(server.server_id, user.user_id, role.position)) {
      return res.status(403).json({ message: "You can't edit your highest role - only roles below it." });
    }

    const name = typeof req.body?.name === "string" ? req.body.name.trim() : role.name;
    const color = typeof req.body?.color === "string" ? (req.body.color || null) : role.color;
    const permissions = req.body?.permissions === undefined
      ? serverRepository.normalizeMergedPermissions(role.permissions)
      : serverRepository.normalizeMergedPermissions(Number(req.body.permissions));
    const hoist = req.body?.hoist === undefined ? Boolean(role.hoist) : Boolean(req.body.hoist);
    const validationError = validateRoleInput({ name, color, permissions }, actor);
    if (validationError) return res.status(400).json({ message: validationError });

    serverRepository.updateRole(role.role_id, { name, color, permissions, hoist });
    notifyServerUpdate(server.server_id);
    notifyMemberUpdate(server.server_id);
    return res.json({ role: publicRole({ ...role, name, color, permissions, hoist }) });
  } catch (err) {
    return next(err);
  }
}

async function deleteRole(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_ROLES });
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    if (serverRepository.isEveryoneRoleId(req.params.roleId)) {
      return res.status(400).json({ message: "@everyone cannot be deleted." });
    }

    const role = serverRepository.getRole(req.params.roleId);
    if (!role || role.server_id !== server.server_id) {
      return res.status(404).json({ message: "Role not found." });
    }
    const isOwner = server.owner_id === user.user_id;
    if (!roleFitsActor(role, { isOwner, myPermissions })) {
      return res.status(403).json({ message: "You can only delete roles with permissions you already have." });
    }
    // Role hierarchy: a non-owner can only delete roles strictly below their
    // highest, so they can't delete their own highest role (self-demotion/lockout).
    if (!serverRepository.canManageRolePosition(server.server_id, user.user_id, role.position)) {
      return res.status(403).json({ message: "You can't delete your highest role - only roles below it." });
    }

    serverRepository.deleteRole(role.role_id);
    notifyServerUpdate(server.server_id);
    notifyMemberUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function setMemberRoles(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_ROLES });
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const target = userRepository.findByAnyId(req.params.userId);
    if (!target || !serverRepository.isMember(server.server_id, target.user_id)) {
      return res.status(404).json({ message: "That user is not a member." });
    }

    const roleIds = Array.isArray(req.body?.roleIds) ? [...new Set(req.body.roleIds.map(String))] : null;
    if (!roleIds || roleIds.length > MAX_ROLES_PER_SERVER) {
      return res.status(400).json({ message: "Invalid role list." });
    }
    if (roleIds.some((roleId) => serverRepository.isEveryoneRoleId(roleId))) {
      return res.status(400).json({ message: "@everyone is applied automatically." });
    }

    const serverRoles = new Map(
      serverRepository.listRoles(server.server_id).map((role) => [role.role_id, role])
    );
    const isOwner = server.owner_id === user.user_id;
    const actor = { isOwner, myPermissions };
    for (const roleId of roleIds) {
      const role = serverRoles.get(roleId);
      if (!role) return res.status(400).json({ message: "Invalid role list." });
    }

    const currentRoleIds = new Set(serverRepository.getMemberRoleIds(server.server_id, target.user_id));
    const requestedRoleIds = new Set(roleIds);
    for (const roleId of new Set([...currentRoleIds, ...requestedRoleIds])) {
      if (currentRoleIds.has(roleId) === requestedRoleIds.has(roleId)) continue;
      const role = serverRoles.get(roleId);
      if (role && !roleFitsActor(role, actor)) {
        return res.status(403).json({ message: "You can only assign roles with permissions you already have." });
      }
    }

    serverRepository.setMemberRoles(server.server_id, target.user_id, roleIds);
    notifyMemberUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// ── Channels ─────────────────────────────────────────────────────────────────

async function createChannel(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const { server } = access;

    const name = normalizeChannelName(req.body?.name);
    if (!name) return res.status(400).json({ message: "Channel name needs letters or numbers." });
    if (serverRepository.channelNameExists(server.server_id, name)) {
      return res.status(409).json({ message: "A channel with that name already exists." });
    }

    const type = req.body?.type === "voice" ? "voice" : "text";
    const typeLimit = type === "voice" ? MAX_VOICE_CHANNELS_PER_SERVER : MAX_TEXT_CHANNELS_PER_SERVER;
    if (serverRepository.countChannels(server.server_id, type) >= typeLimit) {
      const label = type === "voice" ? "voice" : "text";
      return res.status(400).json({ message: `Servers can have at most ${typeLimit} ${label} channels.` });
    }

    let categoryId = null;
    if (req.body?.categoryId) {
      const category = serverRepository.getCategory(req.body.categoryId);
      if (!category || category.server_id !== server.server_id) {
        return res.status(400).json({ message: "Invalid category." });
      }
      categoryId = category.category_id;
    }

    const isPrivate = Boolean(req.body?.isPrivate);
    const channel = serverRepository.createChannel(server.server_id, name, categoryId, isPrivate, type);
    notifyServerUpdate(server.server_id);
    return res.status(201).json({ channel: publicChannel(channel) });
  } catch (err) {
    return next(err);
  }
}

function validateCategoryName(name) {
  if (!name || typeof name !== "string" || name.trim().length < 1) {
    return "Category name cannot be empty.";
  }
  if (name.trim().length > MAX_CATEGORY_NAME_LENGTH) {
    return `Category name cannot exceed ${MAX_CATEGORY_NAME_LENGTH} characters.`;
  }
  return null;
}

async function createCategory(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const { server } = access;

    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const validationError = validateCategoryName(name);
    if (validationError) return res.status(400).json({ message: validationError });
    if (serverRepository.countCategories(server.server_id) >= MAX_CATEGORIES_PER_SERVER) {
      return res.status(400).json({ message: `Servers can have at most ${MAX_CATEGORIES_PER_SERVER} categories.` });
    }

    const category = serverRepository.createCategory(server.server_id, name);
    notifyServerUpdate(server.server_id);
    return res.status(201).json({ category: publicCategory(category) });
  } catch (err) {
    return next(err);
  }
}

function resolveCategory(req, res, server) {
  const category = serverRepository.getCategory(req.params.categoryId);
  if (!category || category.server_id !== server.server_id) {
    res.status(404).json({ message: "Category not found." });
    return null;
  }
  return category;
}

async function renameCategory(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const { server } = access;

    const category = resolveCategory(req, res, server);
    if (!category) return undefined;

    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    const validationError = validateCategoryName(name);
    if (validationError) return res.status(400).json({ message: validationError });

    serverRepository.renameCategory(category.category_id, name);
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true, name });
  } catch (err) {
    return next(err);
  }
}

async function deleteCategory(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const { server } = access;

    const category = resolveCategory(req, res, server);
    if (!category) return undefined;

    // Channels in the category are kept but moved to uncategorized.
    serverRepository.deleteCategory(category.category_id);
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

function resolveChannel(req, res, server) {
  const channel = serverRepository.getChannel(req.params.channelId);
  if (!channel || channel.server_id !== server.server_id) {
    res.status(404).json({ message: "Channel not found." });
    return null;
  }
  return channel;
}

async function renameChannel(req, res, next) {
  try {
    const access = await requireServerAccess(req, res); // membership; per-channel manage checked below
    if (!access) return undefined;
    const { user, server } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!serverRepository.hasPermission(
      serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id), PERMISSIONS.MANAGE_CHANNELS
    )) {
      return res.status(403).json({ message: "You don't have permission to manage this channel." });
    }

    const name = normalizeChannelName(req.body?.name);
    if (!name) return res.status(400).json({ message: "Channel name needs letters or numbers." });
    if (serverRepository.channelNameExists(server.server_id, name, channel.channel_id)) {
      return res.status(409).json({ message: "A channel with that name already exists." });
    }

    // Optional slowmode change, validated against the allowed set.
    if (req.body?.slowmode !== undefined) {
      const seconds = Number(req.body.slowmode);
      if (!SLOWMODE_OPTIONS.includes(seconds)) {
        return res.status(400).json({ message: "Invalid slowmode value." });
      }
      serverRepository.setChannelSlowmode(channel.channel_id, seconds);
    }

    // Optional channel auto-delete change, validated against the allowed set.
    if (req.body?.autoDelete !== undefined) {
      const seconds = Number(req.body.autoDelete);
      if (!AUTO_DELETE_OPTIONS.includes(seconds)) {
        return res.status(400).json({ message: "Invalid auto-delete value." });
      }
      serverRepository.setChannelAutoDelete(channel.channel_id, seconds);
    }

    // Optional channel "about" / topic (shown next to the channel name). Trimmed,
    // capped at 100 chars; an empty string clears it.
    if (req.body?.about !== undefined) {
      const about = typeof req.body.about === "string" ? req.body.about.trim() : "";
      if (about.length > MAX_CHANNEL_ABOUT_LENGTH) {
        return res.status(400).json({ message: `Channel about cannot exceed ${MAX_CHANNEL_ABOUT_LENGTH} characters.` });
      }
      serverRepository.setChannelAbout(channel.channel_id, about);
    }

    serverRepository.renameChannel(channel.channel_id, name);
    // Optional privacy change (public ↔ private) from the Manage Channel dialog.
    if (typeof req.body?.isPrivate === "boolean") {
      serverRepository.setChannelPrivacy(channel.channel_id, req.body.isPrivate);
    }
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true, name });
  } catch (err) {
    return next(err);
  }
}

// Pick a free, normalized name for a clone of `baseName` in this server, e.g.
// "general" → "general-2", "general-3", … (the original always exists).
function uniqueCloneName(serverId, baseName) {
  for (let i = 2; i < 1000; i += 1) {
    const suffix = `-${i}`;
    const trimmed = baseName.slice(0, MAX_CHANNEL_NAME_LENGTH - suffix.length).replace(/-+$/, "");
    const candidate = `${trimmed || baseName.slice(0, 1)}${suffix}`;
    if (!serverRepository.channelNameExists(serverId, candidate)) return candidate;
  }
  return null;
}

// Duplicate a channel - its type, category, privacy and all permission
// overwrites - but NOT its messages. The copy gets a unique "<name>-N" name.
async function cloneChannel(req, res, next) {
  try {
    const access = await requireServerAccess(req, res); // membership; per-channel manage checked below
    if (!access) return undefined;
    const { user, server } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!serverRepository.hasPermission(
      serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id), PERMISSIONS.MANAGE_CHANNELS
    )) {
      return res.status(403).json({ message: "You don't have permission to manage this channel." });
    }

    const type = channel.type === "voice" ? "voice" : "text";
    const typeLimit = type === "voice" ? MAX_VOICE_CHANNELS_PER_SERVER : MAX_TEXT_CHANNELS_PER_SERVER;
    if (serverRepository.countChannels(server.server_id, type) >= typeLimit) {
      return res.status(400).json({ message: `Servers can have at most ${typeLimit} ${type} channels.` });
    }

    const name = uniqueCloneName(server.server_id, channel.name);
    if (!name) return res.status(400).json({ message: "Could not find a free name for the clone." });

    const clone = serverRepository.createChannel(
      server.server_id, name, channel.category_id || null, Boolean(channel.is_private), type
    );
    if (channel.slowmode > 0) serverRepository.setChannelSlowmode(clone.channel_id, channel.slowmode);
    if (channel.auto_delete_seconds > 0) serverRepository.setChannelAutoDelete(clone.channel_id, channel.auto_delete_seconds);
    serverRepository.getChannelOverwrites(channel.channel_id).forEach((o) => {
      serverRepository.setChannelOverwrite(clone.channel_id, o.target_type, o.target_id, o.allow, o.deny);
    });
    notifyServerUpdate(server.server_id);
    return res.status(201).json({ channel: publicChannel(clone) });
  } catch (err) {
    return next(err);
  }
}

async function deleteChannel(req, res, next) {
  try {
    const access = await requireServerAccess(req, res); // membership; per-channel manage checked below
    if (!access) return undefined;
    const { user, server } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!serverRepository.hasPermission(
      serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id), PERMISSIONS.MANAGE_CHANNELS
    )) {
      return res.status(403).json({ message: "You don't have permission to manage this channel." });
    }
    if (serverRepository.countChannels(server.server_id) <= 1) {
      return res.status(400).json({ message: "Servers need at least one channel." });
    }

    // Clean up the channel's webhooks (and their B2 avatars) before dropping it.
    serverRepository.deleteChannelWebhooks(channel.channel_id).forEach((hook) => {
      if (hook.avatar_key) b2Storage.deleteMedia(hook.avatar_key).catch(() => {});
    });
    serverRepository.deleteChannel(channel.channel_id);
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// Rough ETA for the batched purge. The repository deletes ~1000 rows per batch
// with a short pause between, across a reactions pass and a messages pass - call
// it ~40ms per batch, two passes. Floored at 1s so tiny channels read sensibly.
function estimatePurgeSeconds(messageCount) {
  const batchesPerPass = Math.ceil(Math.max(0, Number(messageCount) || 0) / 1000);
  return Math.max(1, Math.ceil((batchesPerPass * 2 * 40) / 1000));
}

// Wipe all messages in a channel (keep the channel). Allowed for the owner, or
// anyone with Manage Channels or Delete Messages.
async function purgeChannel(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;

    const channelPerms = serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id);
    const allowed = serverRepository.hasPermission(channelPerms, PERMISSIONS.MANAGE_CHANNELS)
      || serverRepository.hasPermission(myPermissions, PERMISSIONS.DELETE_MESSAGES);
    if (!allowed) {
      return res.status(403).json({ message: "You don't have permission to purge this channel." });
    }

    // The delete is batched (slow on huge channels), so don't make the client
    // wait on it. Reply right away with a size + time estimate, run the purge in
    // the background, and broadcast `channel_purged` once it's actually finished.
    const messageCount = serverRepository.countChannelMessages(channel.channel_id);
    res.json({ ok: true, messageCount, estimateSeconds: estimatePurgeSeconds(messageCount) });
    serverRepository.purgeChannelMessages(channel.channel_id)
      .then(() => broadcastToChannelViewers(server, channel, {
        type: "channel_purged",
        serverId: server.server_id,
        channelId: channel.channel_id,
      }))
      .catch((err) => console.error("purgeChannel background delete failed:", err));
    return undefined;
  } catch (err) {
    return next(err);
  }
}

// ── Per-channel permission overwrites ──────────────────────────────────────

// Only someone who can Manage Permissions ON THIS CHANNEL may view/edit its
// overwrites (owner/admin always can).
function canManageChannelPermissions(server, channel, userId) {
  return serverRepository.hasPermission(
    serverRepository.channelPermissionsFor(server.server_id, channel, userId), PERMISSIONS.MANAGE_ROLES
  );
}

async function getChannelPermissions(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server } = access;
    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!canManageChannelPermissions(server, channel, user.user_id)) {
      return res.status(403).json({ message: "You don't have permission to manage this channel's permissions." });
    }
    // Enrich each overwrite with a display name (and map member ids to public ids
    // so the client can line them up with its member list).
    const roleById = new Map(serverRepository.listRoles(server.server_id).map((r) => [r.role_id, r]));
    const overwrites = [];
    for (const o of serverRepository.getChannelOverwrites(channel.channel_id)) {
      if (o.target_type === "role") {
        const isEveryone = o.target_id === serverRepository.EVERYONE_ROLE_ID;
        const role = roleById.get(o.target_id);
        overwrites.push({
          targetType: "role",
          targetId: o.target_id,
          name: isEveryone ? "@everyone" : (role?.name || "deleted role"),
          color: isEveryone ? "" : (role?.color || ""),
          allow: o.allow,
          deny: o.deny,
        });
        continue;
      }
      const member = userRepository.findByAnyId(o.target_id);
      if (!member) {
        // Account was deleted - prune the orphaned overwrite so it stops showing
        // as "unknown member". Self-heals rows left behind before cleanup existed.
        serverRepository.deleteChannelOverwrite(channel.channel_id, "member", o.target_id);
        continue;
      }
      overwrites.push({
        targetType: "member",
        targetId: getPublicId(member),
        name: member.profile_alias || member.username,
        allow: o.allow,
        deny: o.deny,
      });
    }
    return res.json({
      overwrites,
      permissionBits: {
        VIEW_CHANNEL: PERMISSIONS.VIEW_CHANNEL,
        SEND_MESSAGES: PERMISSIONS.SEND_MESSAGES,
        SEND_EMBEDS: PERMISSIONS.SEND_EMBEDS,
        ADD_REACTIONS: PERMISSIONS.ADD_REACTIONS,
        CONNECT: PERMISSIONS.CONNECT,
        SPEAK: PERMISSIONS.SPEAK,
        VIDEO: PERMISSIONS.VIDEO,
      },
    });
  } catch (err) {
    return next(err);
  }
}

async function setChannelPermission(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server } = access;
    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!canManageChannelPermissions(server, channel, user.user_id)) {
      return res.status(403).json({ message: "You don't have permission to manage this channel's permissions." });
    }

    const targetType = req.body?.targetType === "member" ? "member" : "role";
    const targetId = String(req.body?.targetId || "");
    const allow = Number(req.body?.allow) || 0;
    const deny = Number(req.body?.deny) || 0;
    if (!targetId) return res.status(400).json({ message: "Pick a role or member." });

    // Validate the target belongs to this server.
    if (targetType === "role") {
      const validRole = targetId === serverRepository.EVERYONE_ROLE_ID
        || serverRepository.listRoles(server.server_id).some((r) => r.role_id === targetId);
      if (!validRole) return res.status(400).json({ message: "Unknown role." });
    } else {
      const member = userRepository.findByAnyId(targetId);
      if (!member || !serverRepository.isMember(server.server_id, member.user_id)) {
        return res.status(400).json({ message: "That member isn't in this server." });
      }
      // Normalize to the internal id the engine compares against.
      serverRepository.setChannelOverwrite(channel.channel_id, "member", member.user_id, allow, deny);
      notifyServerUpdate(server.server_id);
      return res.json({ ok: true });
    }

    serverRepository.setChannelOverwrite(channel.channel_id, "role", targetId, allow, deny);
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// ── Channel messages ─────────────────────────────────────────────────────────

async function reorderChannelLayout(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const { server } = access;

    const channels = Array.isArray(req.body?.channels) ? req.body.channels : null;
    if (!channels) {
      return res.status(400).json({ message: "Invalid channel layout." });
    }

    const existingCategories = serverRepository.listCategories(server.server_id);
    const existingChannels = serverRepository.listChannels(server.server_id);
    const categoryIds = new Set(existingCategories.map((category) => category.category_id));
    const channelIds = new Set(existingChannels.map((channel) => channel.channel_id));

    // sectionOrder is the full top-to-bottom order of sections, where the
    // uncategorized "TEXT CHANNELS" section is the UNCATEGORIZED_SECTION sentinel.
    // Fall back to the plain category list (old clients) with the section on top.
    const sectionOrder = Array.isArray(req.body?.sectionOrder)
      ? req.body.sectionOrder.map(String)
      : [UNCATEGORIZED_SECTION, ...(Array.isArray(req.body?.categories) ? req.body.categories.map(String) : [])];

    const orderedCategoryIds = sectionOrder.filter((id) => id !== UNCATEGORIZED_SECTION);
    const seenCategories = new Set(orderedCategoryIds);
    if (seenCategories.size !== categoryIds.size || orderedCategoryIds.some((id) => !categoryIds.has(id))) {
      return res.status(400).json({ message: "Invalid category order." });
    }

    const seenChannels = new Set();
    const channelLayout = [];
    for (const item of channels) {
      const channelId = String(item?.channelId || "");
      const categoryId = item?.categoryId ? String(item.categoryId) : null;
      if (!channelIds.has(channelId) || seenChannels.has(channelId)) {
        return res.status(400).json({ message: "Invalid channel order." });
      }
      if (categoryId && !categoryIds.has(categoryId)) {
        return res.status(400).json({ message: "Invalid channel category." });
      }
      seenChannels.add(channelId);
      channelLayout.push({ channelId, categoryId });
    }

    if (seenChannels.size !== channelIds.size) {
      return res.status(400).json({ message: "Invalid channel order." });
    }

    // Each category's stored position is its rank in the full section order, so
    // empty categories keep their place relative to the uncategorized section.
    const categoryPositions = sectionOrder
      .map((id, position) => ({ categoryId: id, position }))
      .filter((entry) => entry.categoryId !== UNCATEGORIZED_SECTION);
    const uncategorizedPosition = Math.max(0, sectionOrder.indexOf(UNCATEGORIZED_SECTION));

    serverRepository.updateCategoryLayout(server.server_id, categoryPositions);
    serverRepository.setUncategorizedPosition(server.server_id, uncategorizedPosition);
    serverRepository.updateChannelLayout(server.server_id, channelLayout);
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// Persist a new role order (top → bottom). @everyone is synthesized and isn't a
// stored role, so it's just ignored if sent.
async function reorderRoles(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_ROLES });
    if (!access) return undefined;
    const { server } = access;

    const roleIds = Array.isArray(req.body?.roleIds) ? req.body.roleIds.map(String) : null;
    if (!roleIds) {
      return res.status(400).json({ message: "Invalid role order." });
    }

    // Keep only real roles of this server, preserving the requested order.
    const valid = new Set(serverRepository.listRoles(server.server_id).map((role) => role.role_id));
    const ordered = roleIds.filter((id) => valid.has(id));
    serverRepository.reorderRoles(server.server_id, ordered);
    notifyServerUpdate(server.server_id);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function getChannelMessages(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }

    // `before` is a rowid cursor (the seq of the oldest message the client has).
    const beforeSeq = Number.parseInt(req.query.before, 10);
    const cursor = Number.isInteger(beforeSeq) && beforeSeq > 0 ? beforeSeq : null;
    const rows = serverRepository.getChannelMessages(channel.channel_id, 50, cursor);
    const reactionsByMessage = await messageService.getReactionsForMessages(
      rows.map((row) => row.message_id),
      user.user_id
    );
    const senderCache = new Map();
    const embedCache = new Map(); // authorId -> can their links embed in this channel
    const messages = rows.map((row) => {
      if (!senderCache.has(row.sender_id)) {
        senderCache.set(row.sender_id, userRepository.findById(row.sender_id));
      }
      const message = publicServerMessage(row, senderCache.get(row.sender_id));
      message.reactions = reactionsByMessage[row.message_id] || [];
      // Webhook posts always embed; for member messages, gate on Send Embeds.
      if (!row.webhook_id) {
        if (!embedCache.has(row.sender_id)) {
          embedCache.set(row.sender_id, serverRepository.hasPermission(
            serverRepository.channelPermissionsFor(server.server_id, channel, row.sender_id),
            PERMISSIONS.SEND_EMBEDS
          ));
        }
        message.canEmbed = embedCache.get(row.sender_id);
      }
      return message;
    });

    return res.json({ messages, hasMore: rows.length === 50 });
  } catch (err) {
    return next(err);
  }
}

async function getLinkPreview(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;

    const rawUrl = typeof req.query.url === "string" ? req.query.url.trim() : "";
    if (!rawUrl) return res.status(400).json({ message: "Link URL is required." });

    const preview = await buildLinkPreview(rawUrl);
    return res.json({ preview });
  } catch (err) {
    if (err.statusCode) return res.status(err.statusCode).json({ message: err.message });
    return next(err);
  }
}

// Streams an embed's image through our own origin. This satisfies the strict
// img-src 'self' CSP and keeps the viewer's IP off the external host.
async function streamLinkPreviewImage(rawUrl, res) {
  let current = await assertPublicPreviewUrl(rawUrl);
  let response = null;
  for (let redirects = 0; redirects <= LINK_PREVIEW_MAX_REDIRECTS; redirects += 1) {
    response = await fetchWithTimeout(current.href, "image/*");
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      current = await assertPublicPreviewUrl(new URL(response.headers.get("location"), current.href).href);
      continue;
    }
    break;
  }

  const contentType = (response?.headers.get("content-type") || "").toLowerCase();
  if (!response?.ok || !contentType.startsWith("image/")) {
    return res.status(404).end();
  }

  const buffer = await readLimitedBytes(response, LINK_PREVIEW_IMAGE_MAX_BYTES);
  res.setHeader("Content-Type", contentType.split(";")[0].trim());
  res.setHeader("Cache-Control", "private, max-age=86400");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  return res.send(buffer);
}

async function getLinkPreviewImage(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;

    const rawUrl = typeof req.query.url === "string" ? req.query.url.trim() : "";
    if (!rawUrl) return res.status(400).end();
    return await streamLinkPreviewImage(rawUrl, res);
  } catch (err) {
    if (err.statusCode) return res.status(err.statusCode).end();
    return next(err);
  }
}

// Auth-only link preview (no server membership) - used for DMs. The URL is
// supplied by the client (DM content is E2EE, so the server never sees it).
async function getUserLinkPreview(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const rawUrl = typeof req.query.url === "string" ? req.query.url.trim() : "";
    if (!rawUrl) return res.status(400).json({ message: "Link URL is required." });

    const preview = await buildLinkPreview(rawUrl);
    return res.json({ preview });
  } catch (err) {
    if (err.statusCode) return res.status(err.statusCode).json({ message: err.message });
    return next(err);
  }
}

async function getUserLinkPreviewImage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).end();

    const rawUrl = typeof req.query.url === "string" ? req.query.url.trim() : "";
    if (!rawUrl) return res.status(400).end();
    return await streamLinkPreviewImage(rawUrl, res);
  } catch (err) {
    if (err.statusCode) return res.status(err.statusCode).end();
    return next(err);
  }
}

// GET /servers/send-key - hands the client this session's AES key (over TLS) for
// encrypting the server-message send body. One key per session, reused per tab.
async function getServerSendKey(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const key = sendCipher.keyFor(hashSessionToken(getSessionToken(req)));
    return res.json({ key: key.toString("base64") });
  } catch (err) {
    return next(err);
  }
}

async function sendChannelMessage(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (channel.type === "voice") {
      return res.status(400).json({ message: "Voice channels cannot hold text messages." });
    }
    const channelPerms = serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id);
    if (!serverRepository.hasPermission(channelPerms, PERMISSIONS.VIEW_CHANNEL)) {
      return res.status(403).json({ message: "This channel is private." });
    }
    if (!serverRepository.hasPermission(channelPerms, PERMISSIONS.SEND_MESSAGES)) {
      return res.status(403).json({ message: "You don't have permission to send messages in this channel." });
    }

    // The server owner is never timed out; everyone else is checked.
    if (server.owner_id !== user.user_id) {
      const timeoutUntil = serverRepository.getMemberTimeoutUntil(server.server_id, user.user_id);
      if (timeoutUntil && new Date(timeoutUntil).getTime() > Date.now()) {
        return res.status(403).json({ message: "You are timed out in this server." });
      }
    }

    // Slowmode: rate-limit messages per user. Anyone with Manage Channels (which
    // owner/admin always have here) is exempt.
    const slowmode = Number(channel.slowmode) || 0;
    if (slowmode > 0 && !serverRepository.hasPermission(channelPerms, PERMISSIONS.MANAGE_CHANNELS)) {
      const lastAt = serverRepository.getLastChannelMessageAt(channel.channel_id, user.user_id);
      if (lastAt) {
        const lastMs = Date.parse(`${lastAt.replace(" ", "T")}Z`); // SQLite UTC string → epoch
        const elapsed = (Date.now() - lastMs) / 1000;
        if (Number.isFinite(elapsed) && elapsed < slowmode) {
          const retryAfter = Math.max(1, Math.ceil(slowmode - elapsed));
          return res.status(429).json({ message: `Slow mode is enabled. Try again in ${retryAfter}s.`, retryAfter });
        }
      }
    }

    // App-layer AES on the SEND path (defense-in-depth over TLS, parity with the
    // encrypted WS receive path). The client may send the body as `enc` (a base64
    // AES-GCM frame keyed by GET /servers/send-key); decrypt it here to plaintext
    // before the message is validated + stored. Plain `content` is still accepted
    // (older clients / handshake failed → graceful fallback).
    let bodyContent = req.body?.content;
    if (typeof req.body?.enc === "string" && req.body.enc) {
      const decrypted = sendCipher.tryDecrypt(hashSessionToken(getSessionToken(req)), req.body.enc);
      if (decrypted === null) {
        // code lets the client transparently re-fetch its send-key and retry once.
        return res.status(400).json({ message: "Could not decrypt message. Refresh the page and try again.", code: "send_key_stale" });
      }
      bodyContent = decrypted;
    }
    const content = typeof bodyContent === "string" ? bodyContent.trim() : "";
    if (!content) return res.status(400).json({ message: "Message cannot be empty." });
    if (content.length > MAX_MESSAGE_LENGTH) {
      return res.status(400).json({ message: `Message cannot exceed ${MAX_MESSAGE_LENGTH} characters.` });
    }

    // Uploaded files are governed by the merged Send Embeds/files permission.
    if (isAttachmentMarker(content) && !serverRepository.hasPermission(channelPerms, PERMISSIONS.SEND_EMBEDS)) {
      return res.status(403).json({ message: "You don't have permission to send embeds or files in this channel." });
    }

    // AutoMod: the owner and anyone who can manage the server (i.e. moderators) are
    // exempt - automatic filters should never punish staff. Everyone else's plain
    // text is run through the configured keyword/link/spam filters; a match blocks
    // the message (it's never saved/broadcast) and may also punish the sender.
    const automodExempt = server.owner_id === user.user_id
      || serverRepository.hasPermission(myPermissions, PERMISSIONS.ADMINISTRATOR)
      || serverRepository.hasPermission(myPermissions, PERMISSIONS.MANAGE_SERVER);
    if (!automodExempt && !isAttachmentMarker(content)) {
      const verdict = automod.evaluate({ serverId: server.server_id, channelId: channel.channel_id, userId: user.user_id, content });
      if (verdict?.blocked) {
        await applyAutomodAction({ server, target: user, verdict });
        return res.status(403).json({ message: verdict.userMessage, automod: true, filter: verdict.filter });
      }
    }

    const replyToMessageId = typeof req.body?.replyToMessageId === "string" ? req.body.replyToMessageId : null;
    // Auto-delete: if the sender enabled it for servers, their own server messages
    // vanish after their configured duration (their messages only).
    const senderAd = userRepository.getAutoDeleteSettings(user.user_id);
    const ttlSeconds = senderAd.servers ? senderAd.seconds : 0;
    const row = serverRepository.saveServerMessage({
      channelId: channel.channel_id,
      senderId: user.user_id,
      content,
      replyToMessageId,
      ttlSeconds,
    });
    const message = publicServerMessage(row, user);
    // Who got pinged (computed at send time, gated by permission). Lives only on
    // the live broadcast - history doesn't re-ping.
    message.mentions = computeServerMentions(content, server, user, myPermissions);
    // Links only embed if the author has Send Embeds in this channel.
    message.canEmbed = serverRepository.hasPermission(channelPerms, PERMISSIONS.SEND_EMBEDS);

    broadcastToChannelViewers(server, channel, {
      type: "server_message",
      serverId: server.server_id,
      channelId: channel.channel_id,
      message,
    });

    return res.status(201).json({ message });
  } catch (err) {
    return next(err);
  }
}

async function deleteChannelMessage(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;

    const row = serverRepository.getServerMessage(req.params.messageId);
    if (!row || row.channel_id !== channel.channel_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }

    const canModerate = serverRepository.hasPermission(myPermissions, PERMISSIONS.DELETE_MESSAGES);
    if (row.sender_id !== user.user_id && !canModerate) {
      return res.status(403).json({ message: "You do not have permission to delete this message." });
    }

    // If the author has an open "automated" (bot-spam) report, keep our own copy
    // before this message vanishes for everyone - so the reviewer can still see
    // what was scrubbed. Best-effort: never let it block the delete.
    if (!row.webhook_id) {
      try {
        const reportRepository = require("../repositories/reportRepository");
        const author = userRepository.findById(row.sender_id);
        const ids = author ? [author.user_id, author.public_user_id] : [row.sender_id];
        if (reportRepository.hasOpenAutomatedReport(ids)) {
          reportRepository.preserveDeletedMessage({
            reportedUserId: author ? (author.public_user_id || author.user_id) : row.sender_id,
            messageId: row.message_id,
            channelId: channel.channel_id,
            channelName: channel.name,
            content: String(row.content || "").slice(0, 500),
            createdAt: row.created_at,
          });
        }
      } catch { /* preservation is best-effort */ }
    }

    serverRepository.deleteServerMessage(row.message_id);
    broadcastToChannelViewers(server, channel, {
      type: "server_message_delete",
      serverId: server.server_id,
      channelId: channel.channel_id,
      messageId: row.message_id,
    });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// POST /api/servers/:serverId/channels/:channelId/messages/:messageId/suppress-embed
// Hide one embed (by index) on a channel message. Author can hide their own;
// staff with DELETE_MESSAGES (and the owner, who has all perms) can hide anyone's -
// same authorization as deleting a message. Persisted + broadcast to channel viewers.
async function suppressChannelMessageEmbed(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;

    const row = serverRepository.getServerMessage(req.params.messageId);
    if (!row || row.channel_id !== channel.channel_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }

    const canModerate = serverRepository.hasPermission(myPermissions, PERMISSIONS.DELETE_MESSAGES);
    if (row.sender_id !== user.user_id && !canModerate) {
      return res.status(403).json({ message: "You do not have permission to hide this embed." });
    }

    const index = Number(req.body?.index);
    if (!Number.isInteger(index) || index < 0 || index > 1) {
      return res.status(400).json({ message: "Invalid embed index." });
    }

    const suppressedEmbeds = serverRepository.addSuppressedEmbed(row.message_id, index);
    if (!suppressedEmbeds) return res.status(404).json({ message: "Message not found." });

    broadcastToChannelViewers(server, channel, {
      type: "server_message_embed_suppressed",
      serverId: server.server_id,
      channelId: channel.channel_id,
      messageId: row.message_id,
      suppressedEmbeds,
    });
    return res.json({ suppressedEmbeds });
  } catch (err) {
    return next(err);
  }
}

// PATCH /api/servers/:serverId/channels/:channelId/messages/:messageId
// Author edits their own channel message. Mirrors sendChannelMessage's transport
// decrypt + validation + automod; only the author can edit (moderators can delete,
// not rewrite). Attachments aren't editable.
async function editChannelMessage(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;

    const row = serverRepository.getServerMessage(req.params.messageId);
    if (!row || row.channel_id !== channel.channel_id) {
      return res.status(404).json({ message: "Message not found." });
    }
    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }
    if (row.webhook_id || row.sender_id !== user.user_id) {
      return res.status(403).json({ message: "You can only edit your own messages." });
    }
    if (isAttachmentMarker(row.content)) {
      return res.status(400).json({ message: "Attachments can't be edited." });
    }

    // Transport decrypt (parity with the send path), then validate.
    let bodyContent = req.body?.content;
    if (typeof req.body?.enc === "string" && req.body.enc) {
      const decrypted = sendCipher.tryDecrypt(hashSessionToken(getSessionToken(req)), req.body.enc);
      if (decrypted === null) {
        return res.status(400).json({ message: "Could not decrypt message. Refresh the page and try again.", code: "send_key_stale" });
      }
      bodyContent = decrypted;
    }
    const content = typeof bodyContent === "string" ? bodyContent.trim() : "";
    if (!content) return res.status(400).json({ message: "Message cannot be empty." });
    if (content.length > MAX_MESSAGE_LENGTH) {
      return res.status(400).json({ message: `Message cannot exceed ${MAX_MESSAGE_LENGTH} characters.` });
    }
    if (isAttachmentMarker(content)) {
      return res.status(400).json({ message: "Message cannot be edited into an attachment." });
    }

    // Run automod on the new text, same exemptions as sending.
    const automodExempt = server.owner_id === user.user_id
      || serverRepository.hasPermission(myPermissions, PERMISSIONS.ADMINISTRATOR)
      || serverRepository.hasPermission(myPermissions, PERMISSIONS.MANAGE_SERVER);
    if (!automodExempt) {
      const verdict = automod.evaluate({ serverId: server.server_id, channelId: channel.channel_id, userId: user.user_id, content });
      if (verdict?.blocked) {
        await applyAutomodAction({ server, target: user, verdict });
        return res.status(403).json({ message: verdict.userMessage, automod: true, filter: verdict.filter });
      }
    }

    const updated = serverRepository.updateServerMessageContent({
      messageId: row.message_id,
      senderId: user.user_id,
      content,
    });
    if (!updated) return res.status(404).json({ message: "Message not found." });

    const message = publicServerMessage(updated, user);
    const channelPerms = serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id);
    message.canEmbed = serverRepository.hasPermission(channelPerms, PERMISSIONS.SEND_EMBEDS);

    broadcastToChannelViewers(server, channel, {
      type: "server_message_update",
      serverId: server.server_id,
      channelId: channel.channel_id,
      message,
    });

    return res.json({ message });
  } catch (err) {
    return next(err);
  }
}

// Per-server pin rate limits (in-memory, rolling 1-hour window), keyed by server
// across all its users + channels - i.e. "N per hour per server". Guards against
// a moderator (or a hijacked session) spamming pins/unpins.
const PIN_RATE_WINDOW_MS = 60 * 60 * 1000;
const PIN_RATE_LIMITS = { pin: 50, unpin: 200 };
const pinRateBuckets = new Map(); // serverId -> { pin: number[], unpin: number[] }

function allowPinAction(serverId, kind) {
  const now = Date.now();
  let bucket = pinRateBuckets.get(serverId);
  if (!bucket) { bucket = { pin: [], unpin: [] }; pinRateBuckets.set(serverId, bucket); }
  const hits = bucket[kind];
  while (hits.length && now - hits[0] > PIN_RATE_WINDOW_MS) hits.shift(); // drop expired
  if (hits.length >= PIN_RATE_LIMITS[kind]) return false;
  hits.push(now);
  return true;
}

// Pin a channel message. Gated by Manage Channels (Administrator + the owner get
// every permission bit, so they pass too). Broadcasts so every viewer's pin panel
// + in-line pin state updates live.
async function pinChannelMessage(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }
    if (!serverRepository.hasPermission(myPermissions, PERMISSIONS.MANAGE_CHANNELS)) {
      return res.status(403).json({ message: "You do not have permission to pin messages." });
    }

    const row = serverRepository.getServerMessage(req.params.messageId);
    if (!row || row.channel_id !== channel.channel_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    if (!allowPinAction(server.server_id, "pin")) {
      return res.status(429).json({ message: "Too many pins in this server right now - try again later." });
    }

    const wasAlreadyPinned = Boolean(row.pinned_at);
    const result = serverRepository.pinServerMessage(row.message_id, user.user_id);
    if (!result.ok && result.reason === "limit") {
      return res.status(409).json({ message: "This channel has reached the pin limit (50)." });
    }

    const pinned = serverRepository.getServerMessage(row.message_id);
    const message = publicServerMessage(pinned);
    broadcastToChannelViewers(server, channel, {
      type: "server_message_pin",
      serverId: server.server_id,
      channelId: channel.channel_id,
      message,
    });

    // Persisted "X pinned a message to this channel" system notice - posted once,
    // only on a NEW pin. Rendered as a centered grey line in the channel.
    if (result.ok && !wasAlreadyPinned) {
      const actor = user.profile_alias || user.username || "Someone";
      const noticeRow = serverRepository.saveServerMessage({
        channelId: channel.channel_id,
        senderId: user.user_id,
        // `target` = the pinned message, so clicking the notice can jump to it.
        content: JSON.stringify({ system: true, kind: "pin", actor, target: row.message_id }),
        ttlSeconds: 0, // the notice itself never auto-deletes
      });
      broadcastToChannelViewers(server, channel, {
        type: "server_message",
        serverId: server.server_id,
        channelId: channel.channel_id,
        message: publicServerMessage(noticeRow, user),
      });
    }
    return res.json({ ok: true, message });
  } catch (err) {
    return next(err);
  }
}

async function unpinChannelMessage(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }
    if (!serverRepository.hasPermission(myPermissions, PERMISSIONS.MANAGE_CHANNELS)) {
      return res.status(403).json({ message: "You do not have permission to unpin messages." });
    }

    const row = serverRepository.getServerMessage(req.params.messageId);
    if (!row || row.channel_id !== channel.channel_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    if (!allowPinAction(server.server_id, "unpin")) {
      return res.status(429).json({ message: "Too many unpins in this server right now - try again later." });
    }

    serverRepository.unpinServerMessage(row.message_id);
    broadcastToChannelViewers(server, channel, {
      type: "server_message_unpin",
      serverId: server.server_id,
      channelId: channel.channel_id,
      messageId: row.message_id,
    });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

// List a channel's pinned messages, newest-pinned first. Any member who can view
// the channel can read its pins (like Discord).
async function getChannelPins(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }

    const rows = serverRepository.getPinnedServerMessages(channel.channel_id);
    const messages = rows.map((row) => {
      const base = publicServerMessage(row);
      // Attach who pinned it so the panel can show their avatar + name. Only one
      // lookup per pinned row (≤50), and only when pinned_by is set.
      if (row.pinned_by) {
        const pinner = userRepository.findById(row.pinned_by);
        if (pinner) {
          const pinnerPublicId = getPublicId(pinner);
          base.pinnedBy = pinnerPublicId;
          base.pinnedByName = pinner.profile_alias || pinner.username || "Someone";
          base.pinnedByAvatarUrl = pfpUrl(pinner);
        }
      }
      return base;
    });
    return res.json({ messages });
  } catch (err) {
    return next(err);
  }
}

async function toggleChannelReaction(req, res, next) {
  try {
    const access = await requireServerAccess(req, res);
    if (!access) return undefined;
    const { user, server, myPermissions } = access;

    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (channel.type === "voice") {
      return res.status(400).json({ message: "Voice channels have no messages." });
    }
    if (!canViewChannel(server, channel, user.user_id, myPermissions)) {
      return res.status(403).json({ message: "This channel is private." });
    }
    // Reacting needs Add Reactions (independent of Send Messages, so it still
    // works in read-only channels like #announcements unless it's removed).
    if (!serverRepository.hasPermission(
      serverRepository.channelPermissionsFor(server.server_id, channel, user.user_id),
      PERMISSIONS.ADD_REACTIONS
    )) {
      return res.status(403).json({ message: "You don't have permission to react in this channel." });
    }

    const row = serverRepository.getServerMessage(req.params.messageId);
    if (!row || row.channel_id !== channel.channel_id) {
      return res.status(404).json({ message: "Message not found." });
    }

    const emoji = typeof req.body?.emoji === "string" ? req.body.emoji.trim() : "";
    const validationError = validateReactionEmoji(emoji);
    if (validationError) return res.status(400).json({ message: validationError });

    const result = await messageService.toggleReaction({ messageId: row.message_id, userId: user.user_id, emoji });
    if (result.blocked) {
      return res.status(409).json({ message: "This message already has 5 different reactions." });
    }

    const reactions = (await messageService.getReactionsForMessages([row.message_id], user.user_id))[row.message_id] || [];
    // Broadcast counts only - each client keeps its own `me` highlight.
    broadcastToChannelViewers(server, channel, {
      type: "server_reaction_update",
      serverId: server.server_id,
      channelId: channel.channel_id,
      messageId: row.message_id,
      reactions: reactions.map((reaction) => ({ emoji: reaction.emoji, count: reaction.count })),
    });

    return res.json({ ok: true, action: result.action, reactions });
  } catch (err) {
    return next(err);
  }
}

// ── Webhooks ─────────────────────────────────────────────────────────────────
// Webhook URLs are handed out on this server's public address. If your reverse
// proxy 301-redirects between hosts (e.g. bare domain → www), make sure
// PUBLIC_URL is the canonical one - a 301 turns a webhook POST into a GET.
const WEBHOOK_PUBLIC_ORIGIN = config.publicUrl;
const MAX_WEBHOOK_NAME_LENGTH = 80;
const WEBHOOK_MAX_PAYLOAD_BYTES = 4096;        // 4 KB max per webhook POST
const WEBHOOK_MESSAGES_PER_MINUTE = 30;        // server-wide, not per-channel
const WEBHOOK_REQUESTS_PER_WEBHOOK = 15;       // per individual webhook (defeats IP rotation)
const WEBHOOK_WINDOW_MS = 60 * 1000;
const webhookSendLog = new Map();              // serverId -> number[] (ms timestamps)
const webhookHitLog = new Map();               // webhookId -> number[] (ms timestamps)

function webhookSendsInWindow(serverId) {
  const now = Date.now();
  const recent = (webhookSendLog.get(serverId) || []).filter((t) => now - t < WEBHOOK_WINDOW_MS);
  if (recent.length) webhookSendLog.set(serverId, recent);
  else webhookSendLog.delete(serverId);
  return recent;
}

function recordWebhookSend(serverId) {
  const recent = webhookSendsInWindow(serverId);
  recent.push(Date.now());
  webhookSendLog.set(serverId, recent);
}

// Per-webhook request counter, keyed by webhook id (NOT IP). This is what stops
// someone holding a webhook URL from spamming it through rotating proxies: every
// authenticated request to that one webhook counts toward the same window no
// matter where it comes from.
function webhookHitsInWindow(webhookId) {
  const now = Date.now();
  const recent = (webhookHitLog.get(webhookId) || []).filter((t) => now - t < WEBHOOK_WINDOW_MS);
  if (recent.length) webhookHitLog.set(webhookId, recent);
  else webhookHitLog.delete(webhookId);
  return recent;
}

function recordWebhookHit(webhookId) {
  const recent = webhookHitsInWindow(webhookId);
  recent.push(Date.now());
  webhookHitLog.set(webhookId, recent);
}

function publicWebhook(webhook) {
  return {
    webhookId: webhook.webhook_id,
    channelId: webhook.channel_id,
    name: webhook.name,
    avatarUrl: `/api/webhooks/${encodeURIComponent(webhook.webhook_id)}/avatar`,
    hasAvatar: Boolean(webhook.avatar_key),
    url: `${WEBHOOK_PUBLIC_ORIGIN}/api/webhooks/${webhook.webhook_id}/${webhook.token}`,
    createdAt: toUtcIso(webhook.created_at),
  };
}

async function listWebhooks(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const channel = resolveChannel(req, res, access.server);
    if (!channel) return undefined;
    return res.json({ webhooks: serverRepository.listChannelWebhooks(channel.channel_id).map(publicWebhook) });
  } catch (err) { return next(err); }
}

async function createWebhook(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const { user, server } = access;
    const channel = resolveChannel(req, res, server);
    if (!channel) return undefined;
    if (channel.type === "voice") {
      return res.status(400).json({ message: "Voice channels can't have webhooks." });
    }
    if (serverRepository.countChannelWebhooks(channel.channel_id) >= serverRepository.MAX_WEBHOOKS_PER_CHANNEL) {
      return res.status(400).json({ message: `A channel can have at most ${serverRepository.MAX_WEBHOOKS_PER_CHANNEL} webhooks.` });
    }
    let name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    if (!name) name = "Webhook";
    if (name.length > MAX_WEBHOOK_NAME_LENGTH) {
      return res.status(400).json({ message: `Webhook name cannot exceed ${MAX_WEBHOOK_NAME_LENGTH} characters.` });
    }
    const webhook = serverRepository.createWebhook({
      serverId: server.server_id,
      channelId: channel.channel_id,
      name,
      createdBy: user.user_id,
    });
    return res.status(201).json({ webhook: publicWebhook(webhook) });
  } catch (err) { return next(err); }
}

// Resolve a webhook that belongs to the channel addressed in the route, or send
// a 404. Returns the webhook row, or undefined (response already sent).
function resolveChannelWebhook(req, res, channel) {
  const webhook = serverRepository.getWebhook(req.params.webhookId);
  if (!webhook || webhook.channel_id !== channel.channel_id) {
    res.status(404).json({ message: "Webhook not found." });
    return undefined;
  }
  return webhook;
}

async function renameWebhook(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const channel = resolveChannel(req, res, access.server);
    if (!channel) return undefined;
    const webhook = resolveChannelWebhook(req, res, channel);
    if (!webhook) return undefined;
    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    if (!name) return res.status(400).json({ message: "Webhook name cannot be empty." });
    if (name.length > MAX_WEBHOOK_NAME_LENGTH) {
      return res.status(400).json({ message: `Webhook name cannot exceed ${MAX_WEBHOOK_NAME_LENGTH} characters.` });
    }
    return res.json({ webhook: publicWebhook(serverRepository.updateWebhookName(webhook.webhook_id, name)) });
  } catch (err) { return next(err); }
}

async function deleteWebhook(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const channel = resolveChannel(req, res, access.server);
    if (!channel) return undefined;
    const webhook = resolveChannelWebhook(req, res, channel);
    if (!webhook) return undefined;
    if (webhook.avatar_key) b2Storage.deleteMedia(webhook.avatar_key).catch(() => {});
    serverRepository.deleteWebhook(webhook.webhook_id);
    return res.json({ ok: true });
  } catch (err) { return next(err); }
}

async function uploadWebhookAvatar(req, res, next) {
  try {
    const access = await requireServerAccess(req, res, { permission: PERMISSIONS.MANAGE_CHANNELS });
    if (!access) return undefined;
    const { user } = access;
    const channel = resolveChannel(req, res, access.server);
    if (!channel) return undefined;
    const webhook = resolveChannelWebhook(req, res, channel);
    if (!webhook) return undefined;
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ message: "Choose an image to upload." });
    }
    if (req.body.length > MAX_SERVER_AVATAR_BYTES) {
      return res.status(413).json({ message: "Avatar cannot be over 3 MB." });
    }
    const mime = detectImageMime(req.body);
    if (!mime) {
      return res.status(400).json({ message: "Avatar must be a PNG, JPEG, or WEBP image." });
    }
    const avatarKey = await b2Storage.uploadMedia({
      ownerId: user.public_user_id || user.user_id,
      buffer: req.body,
      contentType: mime,
      metadata: { "webhook-id": webhook.webhook_id },
    });
    if (webhook.avatar_key) b2Storage.deleteMedia(webhook.avatar_key).catch(() => {});
    return res.json({ webhook: publicWebhook(serverRepository.updateWebhookAvatar(webhook.webhook_id, avatarKey, mime)) });
  } catch (err) { return next(err); }
}

// PUBLIC - no session/CSRF. Anyone with the id + token in the path can post.
async function getWebhookAvatarImage(req, res, next) {
  try {
    const webhook = serverRepository.getWebhook(req.params.webhookId);
    if (!webhook) return res.status(404).end();
    if (webhook.avatar_key) {
      try {
        const media = await b2Storage.getMedia(webhook.avatar_key);
        res.setHeader("Content-Type", media.contentType || webhook.avatar_mime || "application/octet-stream");
        res.setHeader("Cache-Control", "public, max-age=300");
        return res.send(media.body);
      } catch { /* object missing - fall back to the generated default */ }
    }
    const fallback = generateInitialProfilePicture(webhook.name);
    res.setHeader("Content-Type", fallback.mimeType);
    res.setHeader("Cache-Control", "public, max-age=300");
    return res.send(fallback.data);
  } catch (err) { return next(err); }
}

// PUBLIC - external clients POST here with the webhook id + token in the path.
async function executeWebhook(req, res, next) {
  try {
    const webhook = serverRepository.getWebhook(req.params.webhookId);
    if (!webhook || webhook.token !== req.params.token) {
      return res.status(404).json({ message: "Unknown webhook." });
    }
    // 4 KB payload cap - reject early on the declared length, then re-check the
    // parsed body (covers chunked requests with no Content-Length).
    if (Number(req.headers["content-length"] || 0) > WEBHOOK_MAX_PAYLOAD_BYTES) {
      return res.status(413).json({ message: "Webhook payload cannot exceed 4 KB." });
    }
    // Per-webhook rate limit: 15 requests/min for THIS webhook, keyed by its id
    // (not IP). Checked right after token auth and counted on every authenticated
    // request - so proxy/IP rotation can't spam a single webhook past this cap,
    // and malformed posts count too. The per-IP webhookLimiter is the outer guard.
    if (webhookHitsInWindow(webhook.webhook_id).length >= WEBHOOK_REQUESTS_PER_WEBHOOK) {
      return res.status(429).json({ message: `This webhook is limited to ${WEBHOOK_REQUESTS_PER_WEBHOOK} requests per minute.` });
    }
    recordWebhookHit(webhook.webhook_id);
    const server = serverRepository.getServer(webhook.server_id);
    const channel = serverRepository.getChannel(webhook.channel_id);
    if (!server || !channel || channel.type === "voice") {
      return res.status(404).json({ message: "This webhook's channel no longer exists." });
    }
    // Server-wide rate limit: 30 webhook messages per minute across the server.
    if (webhookSendsInWindow(server.server_id).length >= WEBHOOK_MESSAGES_PER_MINUTE) {
      return res.status(429).json({ message: `This server's webhooks are limited to ${WEBHOOK_MESSAGES_PER_MINUTE} messages per minute.` });
    }
    if (Buffer.byteLength(JSON.stringify(req.body || {})) > WEBHOOK_MAX_PAYLOAD_BYTES) {
      return res.status(413).json({ message: "Webhook payload cannot exceed 4 KB." });
    }
    const content = typeof req.body?.content === "string" ? req.body.content.trim() : "";
    if (!content) return res.status(400).json({ message: "A 'content' string is required." });
    if (content.length > MAX_MESSAGE_LENGTH) {
      return res.status(400).json({ message: `content cannot exceed ${MAX_MESSAGE_LENGTH} characters.` });
    }
    // Optional per-message display-name override (Discord-style "username").
    let displayName = webhook.name;
    if (typeof req.body?.username === "string" && req.body.username.trim()) {
      displayName = req.body.username.trim().slice(0, MAX_WEBHOOK_NAME_LENGTH);
    }
    recordWebhookSend(server.server_id);
    const row = serverRepository.saveServerMessage({
      channelId: channel.channel_id,
      senderId: webhook.webhook_id, // satisfies sender_id NOT NULL; webhook_id flags it
      content,
      webhookId: webhook.webhook_id,
      webhookName: displayName,
    });
    const message = publicServerMessage(row);
    broadcastToChannelViewers(server, channel, {
      type: "server_message",
      serverId: server.server_id,
      channelId: channel.channel_id,
      message,
    });
    return res.status(204).end();
  } catch (err) { return next(err); }
}

// PUBLIC - GET the webhook's identity (id + token in the path, same auth as
// execute). Lets a client tag its posts with the destination channel name. It
// returns nothing a token-holder doesn't already control by being able to post.
async function getWebhookInfo(req, res, next) {
  try {
    const webhook = serverRepository.getWebhook(req.params.webhookId);
    if (!webhook || webhook.token !== req.params.token) {
      return res.status(404).json({ message: "Unknown webhook." });
    }
    const server = serverRepository.getServer(webhook.server_id);
    const channel = serverRepository.getChannel(webhook.channel_id);
    return res.json({
      id: webhook.webhook_id,
      name: webhook.name,
      channelId: webhook.channel_id,
      channelName: channel ? channel.name : null,
      serverId: webhook.server_id,
      serverName: server ? server.name : null,
    });
  } catch (err) { return next(err); }
}

module.exports = {
  banMember,
  cloneChannel,
  createCategory,
  listWebhooks,
  createWebhook,
  renameWebhook,
  deleteWebhook,
  uploadWebhookAvatar,
  getWebhookAvatarImage,
  executeWebhook,
  getWebhookInfo,
  applyForDiscovery,
  createChannel,
  createInvite,
  createRole,
  createServer,
  deleteCategory,
  deleteChannel,
  purgeChannel,
  deleteChannelMessage,
  suppressChannelMessageEmbed,
  editChannelMessage,
  getServerSendKey,
  pinChannelMessage,
  unpinChannelMessage,
  getChannelPins,
  toggleChannelReaction,
  deleteRole,
  deleteServer,
  getChannelMessages,
  getLinkPreview,
  getLinkPreviewImage,
  getUserLinkPreview,
  getUserLinkPreviewImage,
  getMembers,
  getInviteIconImage,
  getInviteBannerImage,
  getMyDiscoveryApplication,
  getPublicInvite,
  getServerDetails,
  getServerIconImage,
  getServerBannerImage,
  uploadServerBanner,
  joinByInvite,
  kickMember,
  leaveServer,
  listBannedMembers,
  listInvites,
  listInviteInvitees,
  listMyServers,
  listDiscoveryServers,
  reorderServers,
  renameCategory,
  renameChannel,
  reorderChannelLayout,
  reorderRoles,
  getChannelPermissions,
  setChannelPermission,
  revokeInvite,
  clearInvites,
  sendChannelMessage,
  getAutomod,
  updateAutomod,
  getServerPrivacy,
  setServerPrivacy,
  getMyPingBlockedServers,
  setMemberRoles,
  timeoutMember,
  setMemberNickname,
  unbanMember,
  updateRole,
  updateServer,
  transferOwnership,
  uploadServerIcon,
};
