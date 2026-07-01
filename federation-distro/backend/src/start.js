"use strict";

// Entry point: load .env, fill in anything simple that's missing (secrets,
// public IP - see autoconfig.js), THEN load the server. The two-step dance
// exists because config/env.js validates required values at require time.
require("dotenv").config();

require("./autoconfig")
  .autoconfigure()
  .then(() => {
    require("./server");
  })
  .catch((err) => {
    console.error("Auto-configuration failed:", err);
    process.exit(1);
  });
