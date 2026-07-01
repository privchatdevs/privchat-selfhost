// DM attachment endpoints:
//   POST /api/assets               - upload a file (auth + CSRF), returns a slug+url
//   GET  /asset/:owner/:slug       - public, shareable download/preview
//   HEAD /asset/:owner/:slug       - cheap existence/eviction probe (no B2 fetch)
//
// User-uploaded files are served from our own origin, so the GET response is
// hardened: nosniff, a sandbox CSP that neuters active content, and only images
// and plain-text previews render inline - everything else downloads.
const { config } = require("../config/env");
const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");
const assetService = require("../services/assetService");
const assetRepository = require("../repositories/assetRepository");
const starRepository = require("../repositories/starRepository");
const groupRepository = require("../repositories/groupRepository");

// Image types we render inline. SVG is deliberately excluded (it can carry
// script) - it's served as text/plain instead.
const INLINE_IMAGE = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/avif",
]);

const TEXT_CONTENT_TYPES = new Set([
  "application/json", "application/javascript", "application/xml",
  "application/x-yaml", "application/x-sh", "application/x-httpd-php",
]);

// Video files we render inline. .mov (video/quicktime) and .m4v are served as
// video/mp4 so browsers play the (near-universal) H.264 payload.
const VIDEO_CONTENT_TYPES = new Set(["video/mp4", "video/webm", "video/ogg", "video/quicktime"]);
const VIDEO_EXTENSIONS = new Set(["mp4", "m4v", "mov", "webm", "ogv"]);

const TEXT_EXTENSIONS = new Set([
  "txt", "py", "css", "js", "mjs", "cjs", "ts", "tsx", "jsx", "json", "md",
  "markdown", "html", "htm", "xml", "yml", "yaml", "csv", "tsv", "log", "ini",
  "cfg", "conf", "toml", "sh", "bash", "zsh", "bat", "ps1", "c", "h", "cpp",
  "cc", "hpp", "cs", "java", "kt", "go", "rs", "rb", "php", "pl", "lua", "r",
  "sql", "svg", "env", "gitignore", "dockerfile", "makefile",
]);

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}

async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

function decodeFilenameHeader(value) {
  if (!value) return "file";
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function isTextType(contentType, filename) {
  const ct = (contentType || "").toLowerCase();
  if (ct.startsWith("text/")) return true;
  if (TEXT_CONTENT_TYPES.has(ct)) return true;
  const ext = String(filename || "").split(".").pop().toLowerCase();
  return TEXT_EXTENSIONS.has(ext);
}

// Returns the content-type to serve a video under, or null if it isn't a video.
function videoContentType(contentType, filename) {
  const ct = (contentType || "").toLowerCase();
  const ext = String(filename || "").split(".").pop().toLowerCase();
  if (!VIDEO_CONTENT_TYPES.has(ct) && !VIDEO_EXTENSIONS.has(ext)) return null;
  if (ct === "video/webm" || ext === "webm") return "video/webm";
  if (ct === "video/ogg" || ext === "ogv") return "video/ogg";
  return "video/mp4"; // mp4 / m4v / mov / quicktime → H.264 plays as mp4
}

// RFC 6266-ish disposition: an ASCII fallback plus a UTF-8 encoded name.
function contentDisposition(filename, inline) {
  const fallback = String(filename || "file").replace(/[^\x20-\x7E]/g, "_").replace(/["\\]/g, "_");
  const encoded = encodeURIComponent(filename || "file");
  return `${inline ? "inline" : "attachment"}; filename="${fallback}"; filename*=UTF-8''${encoded}`;
}

function applyAssetSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox; frame-ancestors 'none'");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
}

// Is this request a top-level browser navigation (someone visiting the link)
// rather than an <img>/<video> subresource load? Fetch Metadata is exact; the
// Accept header is the fallback for browsers that don't send Sec-Fetch-Dest.
function isTopLevelNavigation(req) {
  const dest = req.get("Sec-Fetch-Dest");
  if (dest) return dest === "document";
  return (req.get("Accept") || "").includes("text/html");
}

function isRawAssetRequest(req) {
  return req.query?.raw === "1";
}

function escapeHtmlAttr(value) {
  return String(value || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// A minimal dark page that centers the image, served when an image link is opened
// directly in the browser. The <img> re-requests the same URL as an image
// subresource, which falls through to the real bytes.
function imageViewerPage(owner, slug, filename) {
  const src = `/asset/${encodeURIComponent(owner)}/${encodeURIComponent(slug)}?raw=1`;
  const title = escapeHtmlAttr(filename || "image");
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title>`
    + `<style>html,body{margin:0;height:100%;background:#0b0b0d;}`
    + `body{display:flex;align-items:center;justify-content:center;}`
    + `img{max-width:100vw;max-height:100vh;object-fit:contain;display:block;}</style></head>`
    + `<body><img src="${src}" alt="${title}"></body></html>`;
}

/** POST /api/assets - raw body upload. */
async function uploadAsset(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const buffer = Buffer.isBuffer(req.body) ? req.body : null;
    const filename = decodeFilenameHeader(req.get("X-Filename"));
    // The file is uploaded as octet-stream (so the global JSON parser never
    // intercepts an application/json file); the real MIME rides in X-Content-Type.
    const contentType = req.get("X-Content-Type") || "application/octet-stream";
    const ownerId = user.public_user_id || user.user_id;

    // Optional: tag this asset with the group it was uploaded into, so the group's
    // attachments can be wiped wholesale when the group is purged. Only honoured if
    // the uploader is actually a member (group_members keys on the internal id).
    const rawGroupId = req.get("X-Group-Id");
    const groupId = rawGroupId && groupRepository.isMember(rawGroupId, user.user_id) ? rawGroupId : null;

    const { asset, evicted } = await assetService.uploadAsset({ ownerId, buffer, contentType, filename, groupId });

    return res.status(201).json({
      asset: {
        owner: ownerId,
        slug: asset.slug,
        name: asset.filename,
        ct: asset.contentType,
        size: asset.byteSize,
        url: `/asset/${encodeURIComponent(ownerId)}/${encodeURIComponent(asset.slug)}`,
      },
      evicted: evicted.length,
    });
  } catch (err) {
    if (err.statusCode) return res.status(err.statusCode).json({ message: err.message });
    return next(err);
  }
}

/** GET /api/assets/usage - the signed-in user's storage usage + limits (bytes). */
async function getStorageUsage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const ownerId = user.public_user_id || user.user_id;
    return res.json({
      usedBytes: assetRepository.getLiveBytes(ownerId),
      budgetBytes: assetService.USER_STORAGE_BUDGET,
      maxFileBytes: assetService.MAX_ASSET_BYTES,
    });
  } catch (err) {
    return next(err);
  }
}

/** POST /api/assets/purge - permanently delete ALL of the signed-in user's
 *  uploaded media (frees the B2 bytes + drops the rows). Runs in the background so
 *  a big purge never blocks the response; deleteByOwnerInBatches paces the row
 *  deletes and the B2 deletes are best-effort. */
async function purgeStorage(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const ownerId = user.public_user_id || user.user_id;
    // Fire-and-forget: respond immediately, free the storage in the background.
    assetService.purgeOwnerAssets(ownerId).catch((err) => console.error("Storage purge failed:", err));
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/** GET /api/assets/library - the signed-in user's own live uploads (newest first).
 *  Powers the "My Uploads" tab, where a past upload can be re-shared by reference. */
async function getLibrary(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const ownerId = user.public_user_id || user.user_id;
    const items = assetRepository.listLiveByOwner(ownerId, 300).map((r) => ({
      owner: ownerId,
      slug: r.slug,
      name: r.filename || "file",
      ct: r.content_type || "application/octet-stream",
      size: r.byte_size || 0,
      createdAt: r.created_at,
    }));
    return res.json({ items });
  } catch (err) {
    return next(err);
  }
}

/** GET /api/assets/starred - media the signed-in user has starred (own or others'). */
async function getStarred(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const userId = user.public_user_id || user.user_id;
    const items = starRepository.listStars(userId, 300).map((r) => ({
      owner: r.owner_id,
      slug: r.slug,
      name: r.name || "file",
      ct: r.ct || "application/octet-stream",
      size: r.size || 0,
      createdAt: r.created_at,
    }));
    return res.json({ items });
  } catch (err) {
    return next(err);
  }
}

/** POST /api/assets/star - star a media item. Body: { owner, slug, name, ct, size }.
 *  Touches only the caller's own star rows; never mutates the assets table, so you
 *  can star someone else's media without affecting their storage. */
async function starMedia(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const userId = user.public_user_id || user.user_id;
    const body = req.body || {};
    const owner = typeof body.owner === "string" ? body.owner.slice(0, 80) : "";
    const slug = typeof body.slug === "string" ? body.slug.slice(0, 80) : "";
    if (!owner || !slug) return res.status(400).json({ message: "owner and slug are required." });
    const name = typeof body.name === "string" ? body.name.slice(0, 200) : "file";
    const ct = typeof body.ct === "string" ? body.ct.slice(0, 120) : "application/octet-stream";
    const size = Number(body.size) || 0;
    starRepository.addStar({ userId, ownerId: owner, slug, name, ct, size });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/** DELETE /api/assets/star - unstar a media item. Body: { owner, slug }. */
async function unstarMedia(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });
    const userId = user.public_user_id || user.user_id;
    const body = req.body || {};
    const owner = typeof body.owner === "string" ? body.owner : "";
    const slug = typeof body.slug === "string" ? body.slug : "";
    if (!owner || !slug) return res.status(400).json({ message: "owner and slug are required." });
    starRepository.removeStar(userId, owner, slug);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

/** GET /asset/:owner/:slug - public, shareable. */
async function serveAsset(req, res, next) {
  try {
    // Opening an image link directly in the browser → serve a dark, centered
    // viewer page instead of the bare top-left image. Decided from the DB row so
    // we never fetch the bytes from B2 just to render the wrapper; the <img> it
    // contains re-requests this URL as an image subresource and gets the bytes.
    if (!isRawAssetRequest(req) && isTopLevelNavigation(req)) {
      const meta = assetRepository.getBySlug(req.params.owner, req.params.slug);
      if (meta && !meta.evicted && meta.b2_key && INLINE_IMAGE.has((meta.content_type || "").toLowerCase())) {
        applyAssetSecurityHeaders(res);
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
        res.setHeader("Cache-Control", "private, max-age=86400");
        res.setHeader("Vary", "Sec-Fetch-Dest, Accept");
        return res.status(200).send(imageViewerPage(req.params.owner, req.params.slug, meta.filename));
      }
    }

    const result = await assetService.getAssetForServe(req.params.owner, req.params.slug);
    applyAssetSecurityHeaders(res);

    if (result.status === "missing") {
      return res.status(404).type("text/plain").send("Attachment not found.");
    }
    if (result.status === "evicted") {
      // 410 Gone - the bytes were reclaimed by the owner's 50 MB storage budget.
      return res.status(410).type("text/plain").send("Attachment deleted.");
    }

    const { row, body } = result;
    const ct = (result.contentType || "application/octet-stream").toLowerCase();
    const videoCt = videoContentType(ct, row.filename);

    let serveType;
    let inline;
    if (INLINE_IMAGE.has(ct)) {
      serveType = ct;
      inline = true;
    } else if (videoCt) {
      serveType = videoCt;
      inline = true;
    } else if (isTextType(ct, row.filename)) {
      serveType = "text/plain; charset=utf-8";
      inline = true;
    } else {
      serveType = "application/octet-stream";
      inline = false;
    }

    res.setHeader("Content-Type", serveType);
    res.setHeader("Content-Disposition", contentDisposition(row.filename, inline));
    res.setHeader("Cache-Control", "private, max-age=86400");
    res.setHeader("Vary", "Sec-Fetch-Dest, Accept");
    res.setHeader("Accept-Ranges", "bytes");

    // Range support - needed for video seeking and for Safari/iOS to play at all.
    const range = req.headers.range;
    if (range && /^bytes=\d*-\d*$/.test(range)) {
      const size = body.length;
      const [startStr, endStr] = range.replace(/^bytes=/, "").split("-");
      let start = startStr ? parseInt(startStr, 10) : 0;
      let end = endStr ? parseInt(endStr, 10) : size - 1;
      if (Number.isNaN(start)) start = 0;
      if (Number.isNaN(end) || end >= size) end = size - 1;
      if (start > end || start >= size) {
        res.setHeader("Content-Range", `bytes */${size}`);
        return res.status(416).end();
      }
      res.setHeader("Content-Range", `bytes ${start}-${end}/${size}`);
      res.setHeader("Content-Length", String(end - start + 1));
      return res.status(206).end(body.subarray(start, end + 1));
    }

    return res.status(200).send(body);
  } catch (err) {
    return next(err);
  }
}

/** HEAD /asset/:owner/:slug - DB-only existence/eviction probe (no B2 fetch). */
function headAsset(req, res) {
  applyAssetSecurityHeaders(res);
  const row = assetRepository.getBySlug(req.params.owner, req.params.slug);
  if (!row) return res.status(404).end();
  if (row.evicted || !row.b2_key) return res.status(410).end();
  res.setHeader("Content-Type", row.content_type || "application/octet-stream");
  res.setHeader("Content-Length", String(row.byte_size || 0));
  return res.status(200).end();
}

/** GET /asset/:owner/:slug/meta - DB-only JSON metadata (no B2 fetch). Lets a
 *  pasted asset link render the real file inline (the bytes are already public at
 *  the sibling GET route, so this exposes nothing new). */
function assetMeta(req, res) {
  applyAssetSecurityHeaders(res);
  const row = assetRepository.getBySlug(req.params.owner, req.params.slug);
  if (!row) return res.status(404).json({ ok: false });
  if (row.evicted || !row.b2_key) return res.status(410).json({ ok: false, evicted: true });
  return res.json({
    ok: true,
    owner: req.params.owner,
    slug: req.params.slug,
    name: row.filename || "",
    ct: row.content_type || "application/octet-stream",
    size: row.byte_size || 0,
  });
}

module.exports = {
  uploadAsset,
  getStorageUsage,
  purgeStorage,
  getLibrary,
  getStarred,
  starMedia,
  unstarMedia,
  serveAsset,
  headAsset,
  assetMeta,
};
