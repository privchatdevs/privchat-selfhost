// DM attachment assets. The bytes live in Backblaze B2 (see services/b2Storage);
// this table maps a public, shareable slug -> B2 object key, plus the metadata
// needed to render/serve it. Rows are never hard-deleted: when the owner's 50 MB
// rolling budget reclaims an asset, the row is marked `evicted` (b2_key cleared)
// so the public link still resolves to an honest "Attachment deleted".
const { randomUUID } = require("crypto");
const messageDb = require("../config/messageDb");

// Batched hard-deletes (node:sqlite is synchronous; a prolific uploader can have
// thousands of rows), mirroring messageRepository.
const DELETE_BATCH_SIZE = 1000;
const DELETE_BATCH_PAUSE_MS = 25;
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

const insertStmt = messageDb.prepare(`
  INSERT INTO assets (asset_id, owner_id, slug, b2_key, content_type, filename, byte_size, group_id)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

function createAsset({ ownerId, slug, b2Key, contentType, filename, byteSize, groupId = null }) {
  const assetId = randomUUID();
  insertStmt.run(assetId, ownerId, slug, b2Key, contentType, filename, byteSize, groupId || null);
  return { assetId, ownerId, slug, b2Key, contentType, filename, byteSize, groupId: groupId || null };
}

function getBySlug(ownerId, slug) {
  return messageDb
    .prepare("SELECT * FROM assets WHERE owner_id = ? AND slug = ?")
    .get(ownerId, slug) || null;
}

function getLiveBytes(ownerId) {
  const row = messageDb
    .prepare("SELECT COALESCE(SUM(byte_size), 0) AS total FROM assets WHERE owner_id = ? AND evicted = 0")
    .get(ownerId);
  return row ? Number(row.total) || 0 : 0;
}

function getOldestLive(ownerId, limit = 50) {
  return messageDb
    .prepare("SELECT * FROM assets WHERE owner_id = ? AND evicted = 0 ORDER BY created_at ASC, asset_id ASC LIMIT ?")
    .all(ownerId, limit);
}

// The owner's live (non-evicted) uploads, newest first - for the "My Uploads" tab
// of the media library, where a past upload can be re-shared by reference (no new
// bytes). Served by IX_assets_owner_created.
function listLiveByOwner(ownerId, limit = 300) {
  return messageDb
    .prepare("SELECT slug, content_type, filename, byte_size, created_at FROM assets WHERE owner_id = ? AND evicted = 0 ORDER BY created_at DESC, asset_id DESC LIMIT ?")
    .all(ownerId, limit);
}

function markEvicted(assetId) {
  messageDb.prepare("UPDATE assets SET b2_key = NULL, evicted = 1 WHERE asset_id = ?").run(assetId);
}

// Hard-delete a single asset by owner + slug. Used when the message carrying the
// attachment is auto-deleted, so the media is actually removed (not just left as a
// dead link). The caller frees the B2 bytes first via the row's b2_key.
function deleteBySlug(ownerId, slug) {
  return messageDb.prepare("DELETE FROM assets WHERE owner_id = ? AND slug = ?").run(ownerId, slug).changes || 0;
}

// ── Wholesale purges (account deletion / DM purge / group purge) ────────────────
// These HARD-delete rows (not the soft "evicted" path) because the owning user or
// group is going away entirely - no link should resolve afterward. The B2 bytes
// are freed by the service layer first, using the keys returned here.

// Live B2 keys for everything a user uploaded (evicted rows already have none).
function getLiveB2KeysByOwner(ownerId) {
  return messageDb
    .prepare("SELECT b2_key FROM assets WHERE owner_id = ? AND b2_key IS NOT NULL")
    .all(ownerId)
    .map((row) => row.b2_key);
}

function deleteByOwnerInBatches(ownerId) {
  return deleteRowsInBatches(
    "DELETE FROM assets WHERE rowid IN (SELECT rowid FROM assets WHERE owner_id = ? LIMIT " + DELETE_BATCH_SIZE + ")",
    [ownerId]
  );
}

// Live B2 keys for everything uploaded into a particular group.
function getLiveB2KeysByGroup(groupId) {
  return messageDb
    .prepare("SELECT b2_key FROM assets WHERE group_id = ? AND b2_key IS NOT NULL")
    .all(groupId)
    .map((row) => row.b2_key);
}

function deleteByGroupInBatches(groupId) {
  return deleteRowsInBatches(
    "DELETE FROM assets WHERE rowid IN (SELECT rowid FROM assets WHERE group_id = ? LIMIT " + DELETE_BATCH_SIZE + ")",
    [groupId]
  );
}

async function deleteRowsInBatches(sql, params) {
  const stmt = messageDb.prepare(sql);
  for (;;) {
    const info = stmt.run(...params);
    if (!info.changes) break;
    await sleep(DELETE_BATCH_PAUSE_MS);
  }
}

module.exports = {
  createAsset,
  getBySlug,
  getLiveBytes,
  getOldestLive,
  listLiveByOwner,
  markEvicted,
  deleteBySlug,
  getLiveB2KeysByOwner,
  deleteByOwnerInBatches,
  getLiveB2KeysByGroup,
  deleteByGroupInBatches,
};
