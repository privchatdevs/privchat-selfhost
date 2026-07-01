const crypto = require("crypto");
const wsCipher = require("./wsCipher");
const { config } = require("../config/env");

// App-layer AES-256-GCM for the server-message SEND path (POST body), mirroring
// the per-connection cipher we already run on the WebSocket receive path. This is
// defense-in-depth ON TOP of TLS - a passive traffic inspector sees ciphertext
// instead of plaintext. It is NOT independent MITM protection (the key is handed
// to the client over the TLS-protected key endpoint, same model as the WS), and
// messages are still stored PLAINTEXT once decrypted here. DMs don't need this -
// their POST body is already E2E ciphertext.
//
// The per-session key is DERIVED (HMAC-SHA256) from a stable server secret + the
// session hash, NOT random + cached in memory. That makes it deterministic and
// stateless: it survives a server restart/deploy, so a client that fetched its key
// before a restart can still have its next message decrypted (no more spurious
// "could not decrypt - refresh" right after a deploy). Frame format is identical
// to wsCipher: base64( iv(12) || ciphertext || tag(16) ).
const SECRET = crypto.createHash("sha256")
  .update(`send-cipher|${config.cookieSecret || ""}`)
  .digest();

// 32-byte AES key for a session, derived deterministically. Same inputs → same key
// across requests AND across process restarts.
function keyFor(sessionHash) {
  return crypto.createHmac("sha256", SECRET).update(String(sessionHash || "")).digest();
}

// Decrypt a base64 frame with the session's derived key. Returns the plaintext, or
// null if the frame doesn't authenticate (wrong key / tampered). Callers treat
// null as "couldn't decrypt".
function tryDecrypt(sessionHash, base64) {
  try {
    return wsCipher.decryptFrame(keyFor(sessionHash), base64);
  } catch {
    return null;
  }
}

module.exports = { keyFor, tryDecrypt };
