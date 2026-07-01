#!/usr/bin/env node
// One-time backfill: encrypt existing plaintext server_messages.content at rest and
// populate has_attachment. Safe to run more than once (idempotent) and resumable
// (each batch commits). Reads keep working throughout because decryptContent passes
// legacy plaintext through.
//
//   BACK UP data.db FIRST, then on the VPS:
//   cd /var/www/untitled/backend && node scripts/encrypt-server-messages.js
//
// Requires SERVER_MSG_KEY_BASE64 to be set in backend/.env (the same key the live
// server uses). Already-encrypted rows (stored as BLOBs) are skipped.
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const messageDb = require("../src/config/messageDb");
const { encryptContent, isAttachmentMarker, encryptionEnabled } = require("../src/security/serverMessageCipher");

if (!encryptionEnabled()) {
  console.error("SERVER_MSG_KEY_BASE64 is not set in backend/.env — nothing to encrypt. Set it and re-run.");
  process.exit(1);
}

const BATCH = 500;

// Only plaintext rows (typeof = 'text'); encrypted rows are BLOBs and are skipped,
// which is what makes this idempotent and resumable. Termination relies on each
// processed row leaving this candidate set, i.e. encryptContent returning a Buffer
// (a BLOB) — guaranteed here because the key is required above (encryptionEnabled).
const selectStmt = messageDb.prepare(`
  SELECT rowid AS rid, content FROM server_messages
  WHERE typeof(content) = 'text'
  ORDER BY rowid
  LIMIT ${BATCH}
`);
const updateStmt = messageDb.prepare(
  "UPDATE server_messages SET content = ?, has_attachment = ? WHERE rowid = ?"
);

let total = 0;
for (;;) {
  const rows = selectStmt.all();
  if (!rows.length) break;
  messageDb.exec("BEGIN");
  try {
    for (const row of rows) {
      updateStmt.run(encryptContent(row.content), isAttachmentMarker(row.content), row.rid);
    }
    messageDb.exec("COMMIT");
  } catch (err) {
    messageDb.exec("ROLLBACK");
    console.error("Batch failed, rolled back:", err.message);
    process.exit(1);
  }
  total += rows.length;
  console.log(`encrypted ${total} server messages...`);
}

console.log(`Done. Encrypted ${total} server message${total === 1 ? "" : "s"}.`);
