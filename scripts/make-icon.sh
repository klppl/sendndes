#!/bin/sh
# Regenerates app/Resources/AppIcon.icns from app/Sources/sendndes/Logo.swift (SwiftUI, no assets).
#   scripts/make-icon.sh
set -eu
cd "$(dirname "$0")/.."
SET=$(mktemp -d)/AppIcon.iconset
(cd scripts/icon-render && swift run -c release icon-render "$SET")
mkdir -p app/Resources
iconutil -c icns "$SET" -o app/Resources/AppIcon.icns
echo "wrote app/Resources/AppIcon.icns"
