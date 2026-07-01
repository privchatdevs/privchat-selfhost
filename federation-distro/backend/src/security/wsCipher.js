const crypto = require("crypto");

// Per-connection AES-256-GCM for WebSocket frames. WSS/TLS already protects the
// transport; this is a second, application-level cipher on top of it. The server
// mints a fresh 32-byte key for each connection and hands it to the client in the
// first frame (over the already-TLS-encrypted socket); from then on every frame,
// both directions, is AES-256-GCM.
//
// Frame format (base64): iv(12) || ciphertext || tag(16). This matches WebCrypto
// on the client, which appends the 16-byte GCM tag to the ciphertext.

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;

function generateKey() {
  return crypto.randomBytes(32);
}

function encryptFrame(key, plaintext) {
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]).toString("base64");
}

function decryptFrame(key, base64) {
  const buf = Buffer.from(base64, "base64");
  if (buf.length < IV_BYTES + TAG_BYTES) throw new Error("Frame too short.");
  const iv = buf.subarray(0, IV_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(IV_BYTES, buf.length - TAG_BYTES);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

module.exports = { generateKey, encryptFrame, decryptFrame };
