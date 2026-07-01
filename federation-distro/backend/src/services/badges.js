// Profile badges. Two sources:
//   • derived  - computed from the user row (e.g. "first 10k" by user_number).
//   • assigned - admin-granted badges stored in users.extra_badges (CSV).
// Assigned badges are listed FIRST, with "staff" always before everything else.

const db = require("../config/db");

const FIRST_USERS_BADGE_LIMIT = 10000;
const BADGE_FIRST_10K = "first_10k";
const BADGE_STAFF = "staff";
const BADGE_BUG_HUNTER = "bug_hunter";
const BADGE_CREATIVE_MIND = "creative_mind";

// The full set of badges that exist. `assignable` = an admin can grant/revoke it
// from the panel; the rest are earned/derived and shown read-only.
const BADGE_CATALOG = [
  { id: BADGE_STAFF, name: "Staff", assignable: true },
  { id: BADGE_BUG_HUNTER, name: "Bug Hunter", assignable: true },
  { id: BADGE_CREATIVE_MIND, name: "Creative Mind", assignable: true },
  { id: BADGE_FIRST_10K, name: "First 10,000 Users", assignable: false },
];

// Badges an admin can grant/revoke from the admin panel.
const ASSIGNABLE_BADGES = BADGE_CATALOG.filter((b) => b.assignable).map((b) => b.id);

// Prepared once (db is already open at require time) so per-user lookups are cheap.
// Pulls both badge CSV columns in one query for rows that didn't already select them.
const badgeColsStmt = db.prepare("SELECT extra_badges, hidden_badges FROM users WHERE user_id = ?");

function parseExtraBadges(csv) {
  return String(csv || "").split(",").map((id) => id.trim()).filter(Boolean);
}

// Read the extra_badges / hidden_badges CSVs for a row. Uses values already on the
// row when present; otherwise looks them up by id (one query), so this works no
// matter which query produced the row.
function badgeColumns(userRow) {
  let extra = userRow?.extra_badges;
  let hidden = userRow?.hidden_badges;
  if ((extra === undefined || hidden === undefined) && userRow?.user_id) {
    let row = null;
    try { row = badgeColsStmt.get(userRow.user_id); } catch { row = null; }
    if (extra === undefined) extra = row?.extra_badges;
    if (hidden === undefined) hidden = row?.hidden_badges;
  }
  return { extra: parseExtraBadges(extra), hidden: parseExtraBadges(hidden) };
}

// Every badge the user has EARNED, regardless of visibility - admin-assigned first
// (staff always before all), then derived. Used by the owner's "manage badges" UI.
function getAllUserBadges(userRow) {
  const out = [];
  const { extra: extras } = badgeColumns(userRow);
  if (extras.includes(BADGE_STAFF)) out.push(BADGE_STAFF);          // staff always first
  for (const id of extras) {
    if (id !== BADGE_STAFF && !out.includes(id)) out.push(id);
  }

  // Derived.
  const number = Number(userRow?.user_number);
  if (Number.isInteger(number) && number > 0 && number <= FIRST_USERS_BADGE_LIMIT) {
    out.push(BADGE_FIRST_10K);
  }

  return out;
}

// The PUBLIC badge list - earned badges minus the ones the user chose to hide.
// This is the chokepoint every profile/member/friend render goes through, so
// hiding a badge removes it everywhere at once.
function getUserBadges(userRow) {
  const hidden = new Set(badgeColumns(userRow).hidden);
  return getAllUserBadges(userRow).filter((id) => !hidden.has(id));
}

module.exports = {
  getUserBadges,
  getAllUserBadges,
  parseExtraBadges,
  BADGE_CATALOG,
  ASSIGNABLE_BADGES,
  FIRST_USERS_BADGE_LIMIT,
  BADGE_FIRST_10K,
  BADGE_STAFF,
  BADGE_BUG_HUNTER,
  BADGE_CREATIVE_MIND,
};
