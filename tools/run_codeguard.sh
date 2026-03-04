#!/usr/bin/env bash
# Run CodeGuard worker on all benchmark apps and generate standardized reports
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
WORKER_DIR="$REPO_ROOT/../codeguard-worker"
REPORTS_DIR="$REPO_ROOT/reports/codeguard"

APPS=(webgoat nodegoat dvwa flask-app real-app-nodejs real-app-python real-app-php)

mkdir -p "$REPORTS_DIR"

if [ ! -f "$WORKER_DIR/worker.py" ]; then
  echo "ERROR: CodeGuard worker not found at $WORKER_DIR/worker.py"
  exit 1
fi

for APP in "${APPS[@]}"; do
  APP_DIR="$REPO_ROOT/apps/$APP"
  if [ ! -d "$APP_DIR" ]; then
    echo "WARNING: $APP_DIR not found, skipping"
    continue
  fi

  echo "=== Running CodeGuard on $APP ==="
  RAW_OUT="/tmp/codeguard-$APP.ndjson"
  GL_OUT="$REPORTS_DIR/$APP.json"

  # Run the CodeGuard worker in local scan mode
  python3 "$WORKER_DIR/worker.py" \
    --scan-dir "$APP_DIR" \
    --output "$RAW_OUT" \
    2>/dev/null || true

  if [ -f "$RAW_OUT" ] && [ -s "$RAW_OUT" ]; then
    python3 "$SCRIPT_DIR/convert_codeguard_to_glsast.py" \
      "$RAW_OUT" \
      -o "$GL_OUT" \
      --app-root "$APP_DIR/"
    echo "  -> $GL_OUT"
  else
    echo "  WARNING: No output produced for $APP"
    echo '{"schema_version":"1.0.0","scanner":{"name":"CodeGuard"},"vulnerabilities":[]}' > "$GL_OUT"
  fi
done

echo "Done. Reports in $REPORTS_DIR/"
