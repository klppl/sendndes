#!/bin/sh
# Regenerates app/Resources/AppIcon.icns from Aster (app/Sources/sendndes/Mascot.swift), no assets.
#   scripts/make-icon.sh [mint|cream|plum]
set -eu
cd "$(dirname "$0")/.."
SET=$(mktemp -d)/AppIcon.iconset
(cd scripts/icon-render && swift run -c release icon-render "$SET" "${1:-mint}")
mkdir -p app/Resources
iconutil -c icns "$SET" -o app/Resources/AppIcon.icns
echo "wrote app/Resources/AppIcon.icns"
