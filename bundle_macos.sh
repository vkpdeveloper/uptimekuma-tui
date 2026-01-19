#!/bin/bash
set -e

APP_NAME="UptimeKuma Desktop"
BINARY_NAME="uptimekuma-desktop"
BUNDLE_DIR="target/release/MacOS"
APP_DIR="$BUNDLE_DIR/$APP_NAME.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

# Check for environment variables
if [ -z "$UPTIME_KUMA_URL" ] || [ -z "$UPTIME_KUMA_USERNAME" ] || [ -z "$UPTIME_KUMA_PASSWORD" ]; then
    echo "WARNING: UPTIME_KUMA_* environment variables are missing!"
    echo "The app bundle requires these to be set in your current shell to bake them into the app."
    echo "Usage: export UPTIME_KUMA_URL=...; ./bundle_macos.sh"
    # proceeding anyway, but warn user
fi

echo "BUILDING RELEASE BINARY..."
cargo build --release

echo "CREATING APP BUNDLE STRUCTURE..."
rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

echo "COPYING BINARY..."
cp "target/release/$BINARY_NAME" "$MACOS_DIR/"

echo "CREATING LAUNCHER SCRIPT..."
LAUNCHER_PATH="$MACOS_DIR/launcher"
cat > "$LAUNCHER_PATH" <<EOF
#!/bin/bash
export UPTIME_KUMA_URL="$UPTIME_KUMA_URL"
export UPTIME_KUMA_USERNAME="$UPTIME_KUMA_USERNAME"
export UPTIME_KUMA_PASSWORD="$UPTIME_KUMA_PASSWORD"

DIR="\$(cd "\$(dirname "\$0")"; pwd)"
"\$DIR/$BINARY_NAME"
EOF
chmod +x "$LAUNCHER_PATH"

echo "CREATING INFO.PLIST..."
cat > "$CONTENTS_DIR/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>launcher</string>
    <key>CFBundleIdentifier</key>
    <string>com.uptimekuma.desktop</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
    <key>LSUIElement</key>
    <false/>
</dict>
</plist>
EOF

echo "DONE! APP BUNDLE CREATED AT: $APP_DIR"
echo "IMPORTANT: The current UPTIME_KUMA_* variables have been baked into the app."
echo "YOU CAN RUN IT WITH: open \"$APP_DIR\""
