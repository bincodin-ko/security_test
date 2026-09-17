#!/bin/bash
# Build the React app into a single self-contained bundle.html.
# Run from design/guardrail-app/.  Output: bundle.html (served by engine/server.js
# in live mode, and publishable as a standalone claude.ai artifact in demo mode).
set -e
cd "$(dirname "$0")"

rm -rf dist bundle.html .parcel-cache
pnpm exec parcel build index.html --dist-dir dist --no-source-maps

node -e '
const fs = require("fs");
let html = fs.readFileSync("dist/index.html", "utf8");
const files = fs.readdirSync("dist");
const js = files.find(f => f.endsWith(".js"));
const css = files.find(f => f.endsWith(".css"));
html = html
  .split("<link rel=stylesheet href=/" + css + ">").join("<style>" + fs.readFileSync("dist/" + css, "utf8") + "</style>")
  .split("<script type=module src=/" + js + "></script>").join("<script type=module>" + fs.readFileSync("dist/" + js, "utf8") + "</" + "script>");
fs.writeFileSync("bundle.html", html);
console.log("bundle.html", (fs.statSync("bundle.html").size / 1024).toFixed(1), "KB");
'
