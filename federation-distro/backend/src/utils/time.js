function parseUtcTimestamp(value) {
  if (!value) return null;
  const text = String(value);
  const normalized = text.includes("T") || /(?:Z|[+-]\d\d:?\d\d)$/.test(text)
    ? text
    : `${text.replace(" ", "T")}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function toUtcIso(value) {
  return parseUtcTimestamp(value)?.toISOString() || value;
}

function toSqliteUtc(value) {
  const date = parseUtcTimestamp(value);
  if (!date) return value;
  return date.toISOString().slice(0, 19).replace("T", " ");
}

module.exports = { parseUtcTimestamp, toUtcIso, toSqliteUtc };
