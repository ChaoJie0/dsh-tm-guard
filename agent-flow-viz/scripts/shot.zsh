#!/bin/zsh
# Dev helper: headless screenshot of the local panel for a visual check.
BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
URL="${URL:-http://127.0.0.1:3100}"
OUT="${OUT:-$PWD/tmp-shot.png}"
"$BIN" --headless --disable-gpu --screenshot="$OUT" --window-size=1100,860 --hide-scrollbars "$URL"
echo "wrote $OUT"
