const { randomUUID } = require("crypto");
const net = require("net");
const adminDb = require("../config/adminDb");

// Federation deny-list (the m.room.server_acl idea, server-wide): hosts we
// refuse to federate with, plus IP/CIDR ranges dropped before the federation
// endpoints do any work. Checked in BOTH directions: inbound (requests from a
// blocked source) and outbound (we refuse to mint tokens toward a blocked
// host). A self-hosted server has no UI for this (moderate in-app; block
// networks at the firewall/proxy) - the table exists because home servers use
// the same code to protect their users.
adminDb.exec(`
  CREATE TABLE IF NOT EXISTS federation_blocks (
    block_id   TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    reason     TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE UNIQUE INDEX IF NOT EXISTS UX_federation_block_value ON federation_blocks (kind, value);
`);

const VALID_KINDS = new Set(["host", "cidr"]);

// ── IP / CIDR matching ────────────────────────────────────────────────────────
// Both IPv4 and IPv6 are compared as BigInts so one code path covers both. An
// IPv4-mapped IPv6 address (::ffff:1.2.3.4 - what Express reports on dual-stack
// sockets) is normalized down to its IPv4 form first.

function normalizeIp(ip) {
  const cleaned = String(ip || "").trim().replace(/^::ffff:/i, "");
  return net.isIP(cleaned) ? cleaned : null;
}

function ipToBigInt(ip) {
  if (net.isIPv4(ip)) {
    return ip.split(".").reduce((acc, part) => (acc << 8n) + BigInt(part), 0n);
  }
  // Expand :: then parse the 8 hextets. A trailing IPv4 tail (a:b::1.2.3.4) is
  // rewritten into two hextets first.
  let addr = ip;
  const v4Tail = addr.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4Tail) {
    const [, a, b, c, d] = v4Tail.map(Number);
    addr = addr.replace(v4Tail[0], ((a << 8) | b).toString(16) + ":" + ((c << 8) | d).toString(16));
  }
  const halves = addr.split("::");
  let groups;
  if (halves.length === 2) {
    const head = halves[0] ? halves[0].split(":") : [];
    const tail = halves[1] ? halves[1].split(":") : [];
    groups = [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail];
  } else {
    groups = addr.split(":");
  }
  return groups.reduce((acc, part) => (acc << 16n) + BigInt(parseInt(part || "0", 16)), 0n);
}

// "1.2.3.0/24", "10.0.0.5" (treated as /32), or "2001:db8::/32". Returns a
// normalized string or null if it isn't a valid CIDR.
function normalizeCidr(input) {
  const raw = String(input || "").trim();
  const [ipPart, bitsPart, extra] = raw.split("/");
  if (extra !== undefined) return null;
  const ip = normalizeIp(ipPart);
  if (!ip) return null;
  const maxBits = net.isIPv4(ip) ? 32 : 128;
  let bits = maxBits;
  if (bitsPart !== undefined) {
    if (!/^\d{1,3}$/.test(bitsPart)) return null;
    bits = Number(bitsPart);
    if (bits < 0 || bits > maxBits) return null;
  }
  return `${ip.toLowerCase()}/${bits}`;
}

function ipInCidr(ip, cidr) {
  const [base, bitsStr] = cidr.split("/");
  const sameFamily = net.isIPv4(ip) === net.isIPv4(base);
  if (!sameFamily) return false;
  const maxBits = net.isIPv4(base) ? 32n : 128n;
  const bits = BigInt(bitsStr);
  const shift = maxBits - bits;
  return (ipToBigInt(ip) >> shift) === (ipToBigInt(base) >> shift);
}

// ── Host normalization ────────────────────────────────────────────────────────
// Hosts are stored lowercase without scheme/port/path so "https://Evil.NET:443/x"
// and "evil.net" collide. Returns null when nothing host-shaped is left.
function normalizeHost(input) {
  let host = String(input || "").trim().toLowerCase();
  host = host.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  host = host.split("/")[0].split("?")[0].split("#")[0];
  if (host.startsWith("[")) {
    host = host.slice(1).split("]")[0]; // bracketed IPv6 literal
  } else {
    host = host.split(":")[0];
  }
  if (!host || host.length > 253 || /\s/.test(host)) return null;
  return host;
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

function listBlocks() {
  return adminDb
    .prepare("SELECT block_id, kind, value, reason, created_at FROM federation_blocks ORDER BY created_at DESC")
    .all();
}

// Returns the new block id, or null when the input doesn't validate. A
// duplicate (same kind+value) returns the string "duplicate".
function addBlock({ kind, value, reason }) {
  if (!VALID_KINDS.has(kind)) return null;
  const clean = kind === "host" ? normalizeHost(value) : normalizeCidr(value);
  if (!clean) return null;
  const id = randomUUID();
  try {
    adminDb
      .prepare("INSERT INTO federation_blocks (block_id, kind, value, reason) VALUES (?, ?, ?, ?)")
      .run(id, kind, clean, String(reason || "").trim().slice(0, 500) || null);
  } catch (err) {
    if (String(err.message || "").includes("UNIQUE")) return "duplicate";
    throw err;
  }
  return id;
}

function removeBlock(blockId) {
  return adminDb.prepare("DELETE FROM federation_blocks WHERE block_id = ?").run(blockId).changes > 0;
}

// Is this host on the deny-list? Matches the host itself and any parent domain
// block (a block on "evil.net" also covers "sub.evil.net").
function isHostBlocked(host) {
  const clean = normalizeHost(host);
  if (!clean) return false;
  const rows = adminDb.prepare("SELECT value FROM federation_blocks WHERE kind = 'host'").all();
  return rows.some(({ value }) => clean === value || clean.endsWith("." + value));
}

function isIpBlocked(ip) {
  const clean = normalizeIp(ip);
  if (!clean) return false;
  const rows = adminDb.prepare("SELECT value FROM federation_blocks WHERE kind = 'cidr'").all();
  return rows.some(({ value }) => ipInCidr(clean, value));
}

module.exports = {
  VALID_KINDS,
  listBlocks,
  addBlock,
  removeBlock,
  isHostBlocked,
  isIpBlocked,
  normalizeHost,
  normalizeCidr,
  normalizeIp,
};
