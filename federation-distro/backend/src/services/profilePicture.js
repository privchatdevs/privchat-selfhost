const COLORS = [
  [235, 69, 158], // Pink
  [87, 192, 120], // Green
  [155, 89, 182], // Purple
  [52, 152, 219], // Blue
  [229, 57, 53],  // Red
];

// Pick a palette colour deterministically from the name, so a user/group/server
// without an uploaded icon always gets the SAME colour - it no longer changes on
// every server restart (it used to be randomInt, which re-rolled each generation).
function colorForSeed(seed) {
  const s = String(seed || "?");
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return COLORS[h % COLORS.length];
}

function generateInitialProfilePicture(username, options = {}) {
  const color = colorForSeed(username);
  const initial = (username || "?").trim().charAt(0).toUpperCase();

  // Servers render as rounded squares in the rail, so their generated fallback
  // fills the whole canvas and lets the <img> container clip the corners.
  // Users/groups stay circular. A square fill is shape-neutral: a round
  // container clips it round, the blocky server rail clips it blocky.
  const shape = options.square
    ? `<rect width="100" height="100" fill="rgb(${color[0]}, ${color[1]}, ${color[2]})" />`
    : `<circle cx="50" cy="50" r="50" fill="rgb(${color[0]}, ${color[1]}, ${color[2]})" />`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">
  ${shape}
  <text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" fill="#FFFFFF" font-family="'Plus Jakarta Sans', ui-sans-serif, system-ui, sans-serif" font-weight="bold" font-size="52">${initial}</text>
</svg>`;

  return {
    data: Buffer.from(svg),
    mimeType: "image/svg+xml",
  };
}

module.exports = {
  generateInitialProfilePicture,
};
