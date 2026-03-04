#!/usr/bin/env bash
# Run Semgrep on all benchmark apps and generate standardized reports
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RULES_DIR="$REPO_ROOT/../codeguard-worker/rules"
REPORTS_DIR="$REPO_ROOT/reports/semgrep"

APPS=(webgoat nodegoat dvwa flask-app real-app-nodejs real-app-python real-app-php)
declare -A LANG_MAP=(
  [webgoat]="java"
  [nodegoat]="javascript"
  [dvwa]="php"
  [flask-app]="python"
  [real-app-nodejs]="javascript"
  [real-app-python]="python"
  [real-app-php]="php"
)

mkdir -p "$REPORTS_DIR"

for APP in "${APPS[@]}"; do
  APP_DIR="$REPO_ROOT/apps/$APP"
  if [ ! -d "$APP_DIR" ]; then
    echo "WARNING: $APP_DIR not found, skipping"
    continue
  fi

  echo "=== Running Semgrep on $APP ==="
  RAW_OUT="/tmp/semgrep-$APP.json"
  GL_OUT="$REPORTS_DIR/$APP.json"

  semgrep \
    --config "$RULES_DIR" \
    --config "p/python" \
    --config "p/javascript" \
    --config "p/typescript" \
    --config "p/php" \
    --config "p/java" \
    --config "p/ruby" \
    --json \
    --quiet \
    --timeout 120 \
    --max-memory 1500 \
    "$APP_DIR" > "$RAW_OUT" 2>/dev/null || true

  python3 "$SCRIPT_DIR/convert_semgrep_to_glsast.py" \
    "$RAW_OUT" \
    -o "$GL_OUT" \
    --app-root "$APP_DIR/"

  echo "  -> $GL_OUT"
done

echo "Done. Reports in $REPORTS_DIR/"
