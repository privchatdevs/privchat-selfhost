// Backblaze B2 (S3-compatible) media storage.
//
// All user-uploaded media lives here, NOT in SQLite. Objects are keyed
// "<publicUserId>/<folder>/<imageId>" - the owner segment keeps a key glanceable for
// moderation, and the folder splits a user's media into two buckets:
//   • "profile" - identity media (profile pictures, banners, server/group icons,
//     webhook avatars). Never counts toward the storage quota; never purged.
//   • "uploads" - chat attachments (the 50 MB-quota'd files shared in DMs/groups/
//     channels). These are what eviction and purges reclaim.
// Keeping them apart means uploads can be managed/purged by prefix without ever
// touching profile media. Each object also carries `uploaded-at`/`uploaded-by`
// metadata. SQLite only stores the full object key + mime type, so existing
// folderless keys keep resolving unchanged.
const { randomUUID } = require("crypto");
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectVersionsCommand,
} = require("@aws-sdk/client-s3");
const { config } = require("../config/env");

let client = null;

function getClient() {
  if (!config.b2.enabled) {
    throw new Error("Backblaze B2 storage is not configured (set B2_KEY_ID, B2_APP_KEY, B2_BUCKET, B2_ENDPOINT).");
  }
  if (!client) {
    client = new S3Client({
      region: config.b2.region,
      endpoint: config.b2.endpoint,
      credentials: {
        accessKeyId: config.b2.keyId,
        secretAccessKey: config.b2.appKey,
      },
      // Newer AWS SDKs send flexible (CRC32) checksums by default, which the
      // Backblaze B2 S3 API rejects on uploads. Only send them when required.
      requestChecksumCalculation: "WHEN_REQUIRED",
      responseChecksumValidation: "WHEN_REQUIRED",
    });
  }
  return client;
}

// Sanitises a value for S3 user-metadata (ASCII only, bounded length).
function metaValue(value) {
  return String(value == null ? "" : value).replace(/[^\x20-\x7E]/g, "").slice(0, 256);
}

/**
 * Uploads a media buffer and returns its object key ("<ownerId>/<imageId>").
 * `ownerId` should be the uploader's public user id so the key is traceable.
 * Extra `metadata` entries are merged into the object's user metadata.
 */
// Per-user media folders (see the file header). Anything not whitelisted falls back
// to "profile" - the safe, never-purged bucket - so a missed/garbled caller can never
// accidentally drop a file into the quota'd/purgeable "uploads" space.
const MEDIA_FOLDERS = new Set(["profile", "uploads"]);

async function uploadMedia({ ownerId, buffer, contentType, metadata = {}, folder = "profile" }) {
  const safeFolder = MEDIA_FOLDERS.has(folder) ? folder : "profile";
  const imageId = randomUUID();
  const key = `${ownerId}/${safeFolder}/${imageId}`;
  const meta = {
    "uploaded-at": new Date().toISOString(),
    "uploaded-by": metaValue(ownerId),
  };
  for (const [name, value] of Object.entries(metadata)) {
    meta[name] = metaValue(value);
  }
  await getClient().send(new PutObjectCommand({
    Bucket: config.b2.bucket,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    Metadata: meta,
  }));
  return key;
}

/** Fetches an object's bytes + content type. Throws if missing/unreachable. */
async function getMedia(key) {
  const response = await getClient().send(new GetObjectCommand({
    Bucket: config.b2.bucket,
    Key: key,
  }));
  const bytes = await response.Body.transformToByteArray();
  return { body: Buffer.from(bytes), contentType: response.ContentType || "" };
}

/**
 * Best-effort delete; never throws (the DB reference is already gone).
 *
 * B2 keeps EVERY version of a file. A plain S3 DeleteObject (no version id) only
 * writes a "hide" marker over the latest version - the bytes stay and keep counting
 * toward bucket storage AND the uploader's 50 MB quota (which is computed from the
 * DB rows we just removed). That mismatch is the storage-leak bug: a purge frees the
 * rows but not the bytes. So enumerate every version + hide marker for this exact
 * key and delete each by its version id, which actually reclaims the space. Falls
 * back to a plain delete when versions can't be listed (non-versioned bucket, or the
 * app key lacks listFiles). Failures are logged - this used to be a silent black
 * hole, which is how the leak hid for so long.
 */
async function deleteMedia(key) {
  if (!key) return;
  let client;
  try {
    client = getClient();
  } catch {
    return; // B2 not configured (e.g. local dev) - nothing to delete.
  }

  try {
    const listed = await client.send(new ListObjectVersionsCommand({ Bucket: config.b2.bucket, Prefix: key }));
    // Prefix is the full object key, but guard against a sibling key that merely
    // shares the prefix - only ever touch the exact key.
    const entries = [...(listed.Versions || []), ...(listed.DeleteMarkers || [])].filter((entry) => entry.Key === key);
    if (entries.length) {
      for (const entry of entries) {
        try {
          await client.send(new DeleteObjectCommand({ Bucket: config.b2.bucket, Key: key, VersionId: entry.VersionId }));
        } catch (err) {
          console.warn(`B2 version delete failed for ${key}@${entry.VersionId}:`, err?.message || err);
        }
      }
      return;
    }
  } catch (err) {
    console.warn(`B2 version listing failed for ${key}; falling back to a plain delete:`, err?.message || err);
  }

  try {
    await client.send(new DeleteObjectCommand({ Bucket: config.b2.bucket, Key: key }));
  } catch (err) {
    console.warn(`B2 delete failed for ${key}:`, err?.message || err);
  }
}

module.exports = { uploadMedia, getMedia, deleteMedia };
