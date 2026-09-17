#!/bin/bash
# Start the 가드레일 live app: the real engine + the UI on one origin.
#
#   ./run-live.sh          then open  http://127.0.0.1:4000
#
# Clicking "진단" with the default URL scans the bundled vulnerable fixture
# (experiment/vulnapp) with the real engine and shows live results. Put a
# real URL in the box to scan your own app (needs outbound network).
#
# The committed UI bundle at design/guardrail-app/bundle.html is served as-is.
# To rebuild it after changing the React source:
#   cd design/guardrail-app && bash build-bundle.sh
set -e
cd "$(dirname "$0")"

if [ ! -f ../design/guardrail-app/bundle.html ]; then
  echo "UI bundle missing — building it…"
  ( cd ../design/guardrail-app && bash build-bundle.sh )
fi

echo "가드레일 live · http://127.0.0.1:${PORT:-4000}  (Ctrl-C to stop)"
exec node server.js
