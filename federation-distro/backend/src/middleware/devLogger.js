/**
 * devLogger.js - verbose request/response logger for DEV_MODE=true
 *
 * Logs:
 *   → incoming request: method, URL, IP, sanitized body, headers
 *   ← response: status (color-coded), body, timing in ms
 */

// ANSI color helpers
const c = {
  reset:   "\x1b[0m",
  dim:     "\x1b[2m",
  bold:    "\x1b[1m",
  cyan:    "\x1b[36m",
  yellow:  "\x1b[33m",
  green:   "\x1b[32m",
  red:     "\x1b[31m",
  magenta: "\x1b[35m",
  blue:    "\x1b[34m",
  gray:    "\x1b[90m",
};

const SENSITIVE_KEYS = new Set([
  "password", "passwordHash", "password_hash",
  "token", "csrfToken", "h-captcha-response",
  "authorization", "cookie", "set-cookie",
]);

function redact(obj, depth = 0) {
  if (depth > 4 || obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map((v) => redact(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = SENSITIVE_KEYS.has(k.toLowerCase()) ? "[REDACTED]" : redact(v, depth + 1);
  }
  return out;
}

function statusColor(code) {
  if (code >= 500) return c.red + c.bold;
  if (code >= 400) return c.yellow + c.bold;
  if (code >= 300) return c.cyan;
  if (code >= 200) return c.green;
  return c.reset;
}

function methodColor(method) {
  const map = { GET: c.green, POST: c.cyan, PUT: c.blue, PATCH: c.magenta, DELETE: c.red };
  return (map[method] || c.reset) + c.bold;
}

function timestamp() {
  return c.gray + new Date().toISOString().replace("T", " ").slice(0, 23) + c.reset;
}

function prettyJson(val) {
  try {
    return JSON.stringify(val, null, 2)
      .split("\n")
      .map((line, i) => (i === 0 ? line : "      " + line))
      .join("\n");
  } catch {
    return String(val);
  }
}

function devLogger(req, res, next) {
  const start = Date.now();
  const reqId = Math.random().toString(36).slice(2, 7).toUpperCase();
  const ip = req.ip || req.socket?.remoteAddress || "?";

  // ── REQUEST ──────────────────────────────────────────────────────────────
  const methodStr = methodColor(req.method) + req.method.padEnd(7) + c.reset;
  const urlStr    = c.bold + req.originalUrl + c.reset;

  process.stdout.write(
    `\n${timestamp()} ${c.gray}[${reqId}]${c.reset} ${methodStr} ${urlStr}  ${c.gray}from ${ip}${c.reset}\n`,
  );

  if (req.body && Object.keys(req.body).length > 0) {
    process.stdout.write(
      `      ${c.dim}body:${c.reset}   ${c.yellow}${prettyJson(redact(req.body))}${c.reset}\n`,
    );
  }

  const qs = req.query && Object.keys(req.query).length > 0;
  if (qs) {
    process.stdout.write(
      `      ${c.dim}query:${c.reset}  ${c.yellow}${prettyJson(req.query)}${c.reset}\n`,
    );
  }

  // ── INTERCEPT RESPONSE ───────────────────────────────────────────────────
  const originalJson = res.json.bind(res);

  res.json = function devLogJson(body) {
    const ms      = Date.now() - start;
    const code    = res.statusCode;
    const codeStr = statusColor(code) + code + c.reset;
    const msStr   = ms > 500 ? c.red + ms + "ms" + c.reset
                  : ms > 150 ? c.yellow + ms + "ms" + c.reset
                  :            c.green + ms + "ms" + c.reset;

    process.stdout.write(
      `      ${c.gray}[${reqId}]${c.reset} ${c.dim}←${c.reset} ${codeStr}  ${msStr}\n`,
    );

    if (body !== undefined) {
      const safe = redact(typeof body === "object" ? body : { _raw: body });
      process.stdout.write(
        `      ${c.dim}resp:${c.reset}   ${c.magenta}${prettyJson(safe)}${c.reset}\n`,
      );
    }

    return originalJson(body);
  };

  next();
}

module.exports = { devLogger };
