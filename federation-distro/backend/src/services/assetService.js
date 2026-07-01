// DM attachment storage. Files are uploaded to Backblaze B2 (keyed by the
// uploader's public id) and tracked in the `assets` table by a random public
// slug. Two hard limits:
//   • each file is capped at 10 MB;
//   • each user has a 50 MB rolling budget - a new upload that pushes them over
//     evicts their oldest assets (bytes freed from B2, row kept + flagged) until
//     they're back under budget.
const crypto = require("crypto");
const b2Storage = require("./b2Storage");
const assetRepository = require("../repositories/assetRepository");

const MAX_ASSET_BYTES = 10 * 1024 * 1024; // 10 MB per file
const USER_STORAGE_BUDGET = 50 * 1024 * 1024; // 50 MB rolling per user

// URL-safe random slug (~22 chars) - the public part of /asset/<owner>/<slug>.
function makeSlug() {
  return crypto.randomBytes(16).toString("base64url");
}

function sanitizeFilename(name) {
  const base = String(name || "file")
    .replace(/[\r\n\t"]/g, "")
    .split(/[\\/]/)
    .pop()
    .trim();
  return (base || "file").slice(0, 120);
}

async function uploadAsset({ ownerId, buffer, contentType, filename, groupId = null }) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    const err = new Error("No file received.");
    err.statusCode = 400;
    throw err;
  }
  if (buffer.length > MAX_ASSET_BYTES) {
    const err = new Error("Files can be at most 10 MB.");
    err.statusCode = 413;
    throw err;
  }

  const safeName = sanitizeFilename(filename);
  const ct = String(contentType || "application/octet-stream").slice(0, 120);

  const b2Key = await b2Storage.uploadMedia({
    ownerId,
    buffer,
    contentType: ct,
    metadata: { "asset-name": safeName },
    folder: "uploads", // chat attachment -> the quota'd/purgeable "uploads" space
  });

  // Insert the asset row with a unique public slug (retry on the rare collision).
  let row = null;
  for (let attempt = 0; attempt < 4 && !row; attempt++) {
    try {
      row = assetRepository.createAsset({
        ownerId,
        slug: makeSlug(),
        b2Key,
        contentType: ct,
        filename: safeName,
        byteSize: buffer.length,
        groupId: groupId || null,
      });
    } catch (err) {
      if (attempt === 3) {
        await b2Storage.deleteMedia(b2Key);
        throw err;
      }
    }
  }

  const evicted = await enforceBudget(ownerId);
  return { asset: row, evicted };
}

async function enforceBudget(ownerId) {
  const evicted = [];
  let total = assetRepository.getLiveBytes(ownerId);
  if (total <= USER_STORAGE_BUDGET) return evicted;

  for (const asset of assetRepository.getOldestLive(ownerId, 100)) {
    if (total <= USER_STORAGE_BUDGET) break;
    await b2Storage.deleteMedia(asset.b2_key);
    assetRepository.markEvicted(asset.asset_id);
    total -= Number(asset.byte_size) || 0;
    evicted.push({ slug: asset.slug, filename: asset.filename });
  }
  return evicted;
}

// Hard-delete every asset a user uploaded (anywhere - DMs and groups), freeing
// the B2 bytes and the rows. Used by account deletion and "purge my DMs", so a
// user's files leave no remnant. Best-effort on B2 (orphan objects are harmless).
async function purgeOwnerAssets(ownerId) {
  if (!ownerId) return;
  for (const key of assetRepository.getLiveB2KeysByOwner(ownerId)) {
    try { await b2Storage.deleteMedia(key); } catch { /* best-effort */ }
  }
  await assetRepository.deleteByOwnerInBatches(ownerId);
}

// Hard-delete every asset uploaded into a particular group - for the group purge
// (inactivity auto-delete / owner delete). Same best-effort B2 cleanup.
async function purgeGroupAssets(groupId) {
  if (!groupId) return;
  for (const key of assetRepository.getLiveB2KeysByGroup(groupId)) {
    try { await b2Storage.deleteMedia(key); } catch { /* best-effort */ }
  }
  await assetRepository.deleteByGroupInBatches(groupId);
}

// Extract the {owner, slug} references from a message's content when it's an
// uploaded-file attachment marker. The marker is stored as plaintext JSON
// (`{"_att":1,...}`) - one attachment (owner/slug at the top level) or many
// ({items:[...]}) - so DM and server-channel attachments are server-visible. Any
// non-marker / E2E-ciphertext content yields no refs (so this is safe to call on
// every deleted message). See js/attachments.js for the marker shape.
function parseAttachmentRefs(content) {
  if (!content || typeof content !== "string" || content[0] !== "{") return [];
  let parsed;
  try { parsed = JSON.parse(content); } catch { return []; }
  if (!parsed || parsed._att !== 1) return [];
  const items = Array.isArray(parsed.items) ? parsed.items : [parsed];
  const refs = [];
  for (const it of items) {
    if (it && typeof it.owner === "string" && typeof it.slug === "string") {
      refs.push({ owner: it.owner, slug: it.slug });
    }
  }
  return refs;
}

// Hard-delete a set of attachments by {owner, slug}: free the B2 bytes AND drop
// the asset row, so auto-deleted media is gone rather than lingering behind a dead
// link. Best-effort and de-duped (the same file referenced twice is deleted once).
// SECURITY: callers must only pass refs the deleted message's sender actually
// OWNS - never trust a marker's owner blindly, or one user could delete another's
// media just by referencing their slug. Returns the number of assets removed.
async function purgeAttachments(refs) {
  if (!Array.isArray(refs) || refs.length === 0) return 0;
  const seen = new Set();
  let removed = 0;
  for (const ref of refs) {
    if (!ref || typeof ref.owner !== "string" || typeof ref.slug !== "string") continue;
    const key = `${ref.owner} ${ref.slug}`;
    if (seen.has(key)) continue;
    seen.add(key);
    try {
      const row = assetRepository.getBySlug(ref.owner, ref.slug);
      if (!row) continue;
      if (row.b2_key) {
        try { await b2Storage.deleteMedia(row.b2_key); } catch { /* best-effort B2 free */ }
      }
      if (assetRepository.deleteBySlug(ref.owner, ref.slug)) removed += 1;
    } catch { /* best-effort per attachment */ }
  }
  return removed;
}

// Resolves an asset for the public serve route. Returns one of:
//   { status: "missing" } | { status: "evicted", row } |
//   { status: "ok", row, body, contentType }
async function getAssetForServe(ownerId, slug) {
  const row = assetRepository.getBySlug(ownerId, slug);
  if (!row) return { status: "missing" };
  if (row.evicted || !row.b2_key) return { status: "evicted", row };
  try {
    const media = await b2Storage.getMedia(row.b2_key);
    return { status: "ok", row, body: media.body, contentType: row.content_type || media.contentType };
  } catch {
    return { status: "missing", row };
  }
}

module.exports = {
  uploadAsset,
  getAssetForServe,
  purgeOwnerAssets,
  purgeGroupAssets,
  purgeAttachments,
  parseAttachmentRefs,
  MAX_ASSET_BYTES,
  USER_STORAGE_BUDGET,
};
