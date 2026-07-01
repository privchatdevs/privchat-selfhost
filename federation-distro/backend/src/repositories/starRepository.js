// Starred media bookmarks. A row says "user_id starred the asset (owner_id, slug)"
// and snapshots its name/ct/size so the Starred tab can render a tile even after
// the original message disappears. This NEVER touches the `assets` table and never
// stores bytes - starring is a pure bookmark, so it can't pin or protect another
// user's storage. See messageDb.js (starred_media) for the schema.
const { randomUUID } = require("crypto");
const messageDb = require("../config/messageDb");

// Idempotent: re-starring the same asset refreshes its metadata snapshot instead
// of erroring (the UNIQUE(user_id, owner_id, slug) index drives the upsert).
const insertStmt = messageDb.prepare(`
  INSERT INTO starred_media (star_id, user_id, owner_id, slug, name, ct, size)
  VALUES (?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(user_id, owner_id, slug)
  DO UPDATE SET name = excluded.name, ct = excluded.ct, size = excluded.size
`);

function addStar({ userId, ownerId, slug, name, ct, size }) {
  insertStmt.run(
    randomUUID(),
    userId,
    ownerId,
    slug,
    name || "file",
    ct || "application/octet-stream",
    Number(size) || 0,
  );
}

function removeStar(userId, ownerId, slug) {
  return messageDb
    .prepare("DELETE FROM starred_media WHERE user_id = ? AND owner_id = ? AND slug = ?")
    .run(userId, ownerId, slug).changes || 0;
}

function listStars(userId, limit = 300) {
  return messageDb
    .prepare("SELECT owner_id, slug, name, ct, size, created_at FROM starred_media WHERE user_id = ? ORDER BY created_at DESC, star_id DESC LIMIT ?")
    .all(userId, limit);
}

function isStarred(userId, ownerId, slug) {
  return !!messageDb
    .prepare("SELECT 1 FROM starred_media WHERE user_id = ? AND owner_id = ? AND slug = ?")
    .get(userId, ownerId, slug);
}

module.exports = { addStar, removeStar, listStars, isStarred };
