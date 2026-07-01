const crypto = require("crypto");
const { config } = require("../config/env");

// At-rest encryption for SERVER channel message content (server_messages.content).
// This is NOT end-to-end: the server holds the key and decrypts on read, so every
// feature (search, embeds, moderation, auto-delete media cleanup) keeps working.
// It exists so a stolen DB file / disk / backup is unreadable. DMs and group chats
// keep their own client-side E2E - this never touches them.
//
// Cipher: ChaCha20-Poly1305 (AEAD), native to Node. Stored as raw BYTES (a BLOB),
// never base64, so there's no ~33% text inflation. On-disk blob layout:
//   version(1) || nonce(12) || ciphertext(len = plaintext) || tag(16)
// Overhead is a flat 29 bytes/message regardless of size.
//
// The KEY IS THE ON-SWITCH. With SERVER_MSG_KEY_BASE64 unset, encryptContent is a
// pass-through (content stays plaintext TEXT, exactly like before) so the code is
// safe to deploy before the key exists. Set the key + restart to start encrypting
// new messages; run the backfill script to convert old ones. decryptContent always
// handles BOTH forms (a string is legacy/plaintext; a Buffer is ciphertext), so a
// mixed table during rollout reads correctly.

const ALGORITHM = "chacha20-poly1305";
const VERSION = 0x01;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

const key = config.serverMsgKey || null; // 32-byte Buffer, or null when disabled

function encryptionEnabled() {
  return Boolean(key);
}

// Returns a Buffer (encrypted) when a key is configured, otherwise the plaintext
// string unchanged (encryption disabled). Callers store whatever comes back; a
// string binds as TEXT, a Buffer binds as a BLOB.
function encryptContent(plaintext) {
  const text = plaintext == null ? "" : String(plaintext);
  if (!key) return text;
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
  const ciphertext = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([VERSION]), nonce, ciphertext, tag]);
}

// Accepts whatever the DB returned for the content column. A string is legacy
// plaintext (or encryption-disabled) and is returned as-is. A Buffer/Uint8Array is
// ciphertext and is decrypted. Never throws to the caller: a key/corruption problem
// returns a placeholder + logs, so one bad row can't sink a whole channel fetch.
function decryptContent(value) {
  if (value == null) return value;
  if (typeof value === "string") return value;
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (buf.length < 1 + NONCE_BYTES + TAG_BYTES || buf[0] !== VERSION) {
    // Not our format - treat as already-plaintext bytes.
    return buf.toString("utf8");
  }
  if (!key) {
    console.error("[at-rest] encrypted server message but SERVER_MSG_KEY_BASE64 is not set");
    return "[message unavailable]";
  }
  try {
    const nonce = buf.subarray(1, 1 + NONCE_BYTES);
    const tag = buf.subarray(buf.length - TAG_BYTES);
    const ciphertext = buf.subarray(1 + NONCE_BYTES, buf.length - TAG_BYTES);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  } catch (err) {
    console.error("[at-rest] server message decrypt failed:", err.message);
    return "[message unavailable]";
  }
}

// Whether a message is an uploaded-file attachment marker. Mirrors
// assetService.parseAttachmentRefs EXACTLY (JSON with _att===1 and at least one
// {owner, slug}) so the stored has_attachment flag means precisely "this row has a
// purgeable B2 attachment". A looser check would mislabel ordinary JSON/system
// messages and wrongly route them to media purge / exclude them from search.
function isAttachmentMarker(plaintext) {
  if (!plaintext || typeof plaintext !== "string" || plaintext[0] !== "{") return 0;
  let parsed;
  try { parsed = JSON.parse(plaintext); } catch { return 0; }
  if (!parsed || parsed._att !== 1) return 0;
  const items = Array.isArray(parsed.items) ? parsed.items : [parsed];
  for (const it of items) {
    if (it && typeof it.owner === "string" && typeof it.slug === "string") return 1;
  }
  return 0;
}

module.exports = { encryptContent, decryptContent, isAttachmentMarker, encryptionEnabled };
