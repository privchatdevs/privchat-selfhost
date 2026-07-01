"use strict";

// First-boot auto-configuration: make `npm start` work with an EMPTY .env.
// Anything the operator sets in the environment always wins - this only fills
// in what's missing, and persists what it generated into
// <DATA_DIR>/auto-config.json so every later boot reuses the same values
// (regenerating AES keys would make previously encrypted data unreadable).
// That file lives with the databases on purpose: one folder to back up.
//
// Auto-configured when absent:
//   COOKIE_SECRET            random 32 bytes
//   AES_256_KEY_BASE64       random 32 bytes
//   SERVER_MSG_KEY_BASE64    random 32 bytes - FRESH INSTALLS ONLY (guarded on
//                            the messages DB not existing yet), so an existing
//                            plaintext install keeps its operator-chosen posture
//   PUBLIC_URL               detected VPS public IP -> http://<ip>:<port>
//
// Runs from src/start.js BEFORE config/env.js is first required, because env.js
// validates these at require time.

const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const path = require("path");

const dataDir = process.env.DATA_DIR || path.join(__dirname, "../data");
const savePath = path.join(dataDir, "auto-config.json");

function loadSaved() {
  try {
    return JSON.parse(fs.readFileSync(savePath, "utf8"));
  } catch {
    return {};
  }
}

function newKey() {
  return crypto.randomBytes(32).toString("base64");
}

function log(msg) {
  console.log(`\x1b[36m[AUTO-CONFIG]\x1b[0m ${msg}`);
}

// Ask a couple of well-known echo services which IP this box talks to the
// internet with. Short timeouts - a VPS answers in milliseconds, and an
// offline/air-gapped box shouldn't stall boot.
async function detectPublicIp() {
  for (const url of ["https://api.ipify.org", "https://ifconfig.me/ip"]) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) continue;
      const ip = (await res.text()).trim();
      if (net.isIP(ip)) return ip;
    } catch { /* try the next service */ }
  }
  return null;
}

async function autoconfigure() {
  const saved = loadSaved();
  let dirty = false;

  const fill = (envName, savedName, generate, note) => {
    if (process.env[envName]) return; // operator's value always wins
    if (!saved[savedName]) {
      const value = generate();
      if (value == null) return;
      saved[savedName] = value;
      dirty = true;
      if (note) log(note);
    }
    process.env[envName] = saved[savedName];
  };

  fill("COOKIE_SECRET", "cookieSecret", newKey,
    "COOKIE_SECRET not set - generated one.");
  fill("AES_256_KEY_BASE64", "aesKeyBase64", newKey,
    "AES_256_KEY_BASE64 not set - generated one.");

  // At-rest channel-message key: only on a genuinely fresh install (no messages
  // DB yet). Existing installs keep whatever the operator decided; flipping
  // encryption on for them is a deliberate act (see scripts/encrypt-server-messages.js).
  const messagesDb = process.env.MESSAGES_DB_PATH || path.join(dataDir, "data.db");
  fill("SERVER_MSG_KEY_BASE64", "serverMsgKeyBase64",
    () => (fs.existsSync(messagesDb) ? null : newKey()),
    "SERVER_MSG_KEY_BASE64 not set - generated one (fresh install), channel messages will be encrypted at rest.");

  if (!process.env.PUBLIC_URL) {
    if (!saved.publicUrl) {
      const ip = await detectPublicIp();
      if (ip) {
        const port = Number(process.env.PORT || 4000);
        saved.publicUrl = `http://${net.isIPv6(ip) ? `[${ip}]` : ip}:${port}`;
        dirty = true;
        log(`PUBLIC_URL not set - detected this machine's public IP, using ${saved.publicUrl}.`);
        log("Heads up: IP servers are desktop-app-only and plain http is unencrypted - set PUBLIC_URL in .env once you have a domain with HTTPS.");
      } else {
        log("PUBLIC_URL not set and public-IP detection failed (offline?) - falling back to http://localhost:4000. Set PUBLIC_URL in .env.");
      }
    }
    if (saved.publicUrl) process.env.PUBLIC_URL = saved.publicUrl;
  }

  if (dirty) {
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(savePath, JSON.stringify(saved, null, 2), { mode: 0o600 });
    log(`Saved auto-generated values to ${savePath} - it lives with your databases; keep the whole data folder in backups.`);
  }
}

module.exports = { autoconfigure };
