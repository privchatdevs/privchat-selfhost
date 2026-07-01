const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { config } = require("../config/env");

// Federation signing identity. Every PrivChat server holds one Ed25519 keypair:
// the private key never leaves this box, the public key is published at
// /api/federation/keys so other servers can verify tokens we sign (the same
// model Matrix uses server-to-server - signed requests, no shared secrets).
//
// Key source, in order:
//   1. FEDERATION_SIGNING_KEY_BASE64 (PKCS8 DER, base64) - lets an operator pin
//      the key in .env and rotate it deliberately.
//   2. data/federation-key.json - generated on first boot and reused after.
// Losing the key means other servers stop trusting this one until they re-learn
// the new key, so the data-folder file must be part of backups (documented in
// the self-hosting docs).

let keypair = null; // { keyId, privateKey, publicKey, publicKeyBase64 }

function publicKeyRawBase64(publicKey) {
  // Publish the raw 32-byte Ed25519 key (Matrix-style), not the DER wrapper.
  // The raw key is the last 32 bytes of the SPKI DER encoding.
  const spki = publicKey.export({ format: "der", type: "spki" });
  return spki.subarray(spki.length - 32).toString("base64");
}

function keyIdFor(publicKey) {
  const fingerprint = crypto
    .createHash("sha256")
    .update(publicKey.export({ format: "der", type: "spki" }))
    .digest("base64url")
    .slice(0, 8);
  return `ed25519:${fingerprint}`;
}

function fromPrivateKey(privateKey) {
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    keyId: keyIdFor(publicKey),
    privateKey,
    publicKey,
    publicKeyBase64: publicKeyRawBase64(publicKey),
  };
}

function loadOrCreateKeypair() {
  if (keypair) return keypair;

  if (config.federation.signingKeyBase64) {
    const der = Buffer.from(config.federation.signingKeyBase64, "base64");
    const privateKey = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error("FEDERATION_SIGNING_KEY_BASE64 must be an Ed25519 PKCS8 key.");
    }
    keypair = fromPrivateKey(privateKey);
    return keypair;
  }

  const keyPath = config.federation.keyPath;
  try {
    const saved = JSON.parse(fs.readFileSync(keyPath, "utf8"));
    const der = Buffer.from(saved.privateKeyBase64, "base64");
    keypair = fromPrivateKey(crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
    return keypair;
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }

  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  fs.writeFileSync(
    keyPath,
    JSON.stringify(
      {
        note: "PrivChat federation signing key. Keep secret, keep in backups.",
        algorithm: "ed25519",
        privateKeyBase64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
        createdAt: new Date().toISOString(),
      },
      null,
      2
    ),
    { mode: 0o600 }
  );
  keypair = fromPrivateKey(privateKey);
  console.log(`Federation signing key generated (${keypair.keyId}) at ${keyPath}`);
  return keypair;
}

// Sign a canonical JSON payload. Callers pass a plain object; key order is
// normalized here so both sides always sign/verify identical bytes.
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function signObject(obj) {
  const { privateKey, keyId } = loadOrCreateKeypair();
  const signature = crypto.sign(null, Buffer.from(canonicalJson(obj), "utf8"), privateKey);
  return { keyId, signatureBase64: signature.toString("base64") };
}

// Verify obj against a raw 32-byte Ed25519 public key (base64) - the format
// /api/federation/keys publishes. Used when checking another server's token.
function verifyObject(obj, signatureBase64, publicKeyRawB64) {
  try {
    const raw = Buffer.from(publicKeyRawB64, "base64");
    if (raw.length !== 32) return false;
    // Rebuild the SPKI wrapper around the raw key (fixed 12-byte Ed25519 prefix).
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([spkiPrefix, raw]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(
      null,
      Buffer.from(canonicalJson(obj), "utf8"),
      publicKey,
      Buffer.from(signatureBase64, "base64")
    );
  } catch {
    return false;
  }
}

// ── Identity self-check (does this server really own its public address?) ────
// A federation identity IS its domain/IP: other servers only ever trust keys
// they fetch from the claimed host themselves (DNS + TLS is the ownership
// proof - the same way Matrix does it). This boot check performs that exact
// fetch against our own PUBLIC_URL and compares the served key to the local
// one, so a misconfigured or unowned domain is caught at setup time instead of
// silently minting an identity nobody will ever trust. Warning-only: NAT
// hairpinning can make the URL unreachable from inside even when it works
// fine from the internet, and the server must still boot behind a
// not-yet-configured proxy.
const SELF_CHECK_DELAY_MS = 5000;

async function runIdentitySelfCheck(baseUrl) {
  const { keyId, publicKeyBase64 } = loadOrCreateKeypair();
  const url = `${baseUrl}/api/federation/keys`;
  let body;
  try {
    const res = await fetch(url, {
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      console.warn(
        `\x1b[33m[FEDERATION]\x1b[0m Self-check: ${url} answered HTTP ${res.status}. ` +
        `Other servers prove you own this address by fetching your key from it - until that URL serves ` +
        `this server, your federation identity won't be trusted. Check PUBLIC_URL and your reverse proxy.`
      );
      return false;
    }
    body = await res.json();
  } catch {
    console.warn(
      `\x1b[33m[FEDERATION]\x1b[0m Self-check: could not reach ${url} from this machine. ` +
      `If you're behind NAT this can be a false alarm (hairpinning), but make sure the address works ` +
      `from the internet - that fetch is how other servers verify you own it.`
    );
    return false;
  }
  if (body?.keys?.[keyId] === publicKeyBase64) {
    console.log(`\x1b[32m[FEDERATION]\x1b[0m Self-check passed: ${baseUrl} serves this server's key (${keyId}).`);
    return true;
  }
  console.warn(
    `\x1b[33m[FEDERATION]\x1b[0m Self-check FAILED: ${url} is serving a DIFFERENT key than this server's ` +
    `(${keyId}). Either PUBLIC_URL points at a domain/IP you don't control, or your proxy routes it to ` +
    `another instance. Fix this before federating - no other server will trust this identity.`
  );
  return false;
}

// Fire the check shortly after boot (gives the listener + proxy a moment).
function startIdentitySelfCheck(baseUrl) {
  const timer = setTimeout(() => {
    runIdentitySelfCheck(baseUrl).catch(() => {});
  }, SELF_CHECK_DELAY_MS);
  timer.unref();
}

module.exports = { loadOrCreateKeypair, canonicalJson, signObject, verifyObject, runIdentitySelfCheck, startIdentitySelfCheck };
