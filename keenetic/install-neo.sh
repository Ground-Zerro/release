#!/bin/sh

if [ "$LOGNAME" != "root" ]; then
  echo ""
  echo "    Вы вошли как "$LOGNAME""
  echo ""
  echo "    Не используйте вход через CLI для устанвоки HydraRoute,"
  echo "    подключитесь напрямую к Entware."
  echo ""
  echo "    Установка прервана..."
  echo ""
  exit 1
fi

FEED_CONF="/opt/etc/opkg/customfeeds.conf"
OLD_BASE="https://ground-zerro.github.io/release/keenetic/"
NEW_BASE="https://git.zerrolabs.org/Ground-Zerro/release/pages/keenetic/"

if [ ! -d "/opt/etc/opkg" ]; then
  mkdir -p /opt/etc/opkg
fi

if [ -f "$FEED_CONF" ] && grep -q "$OLD_BASE" "$FEED_CONF" 2>/dev/null; then
  echo "Old repository found. Replacing with new source..."
  sed -i "s|$OLD_BASE|$NEW_BASE|g" "$FEED_CONF"
  echo "Updating package list after repository replacement..."
  opkg update
fi

echo "Installing wget with HTTPS support..."
opkg update
opkg install wget-ssl

echo "Detecting system architecture (via opkg)..."
ARCH=$(opkg print-architecture | awk '
  /^arch/ && $2 !~ /_kn$/ && $2 ~ /-[0-9]+\.[0-9]+$/ {
    print $2; exit
  }'
)

if [ -z "$ARCH" ]; then
  echo "Failed to detect architecture."
  exit 1
fi

case "$ARCH" in
  aarch64-3.10)
    FEED_URL="${NEW_BASE}aarch64-k3.10"
    ;;
  mipsel-3.4)
    FEED_URL="${NEW_BASE}mipselsf-k3.4"
    ;;
  mips-3.4)
    FEED_URL="${NEW_BASE}mipssf-k3.4"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

echo "Architecture: $ARCH"
echo "Selected feed: $FEED_URL"

FEED_LINE="src/gz ground-zerro $FEED_URL"

if grep -q "src/gz ground-zerro $FEED_URL" "$FEED_CONF" 2>/dev/null; then
  echo "Repository already present in $FEED_CONF. Skipping."
else
  if [ -f "$FEED_CONF" ] && grep -q "^src/gz ground-zerro " "$FEED_CONF" 2>/dev/null; then
    echo "Replacing existing ground-zerro entry with correct architecture..."
    sed -i "/^src\/gz ground-zerro /d" "$FEED_CONF"
  fi
  echo "Adding repository to $FEED_CONF..."
  echo "$FEED_LINE" >> "$FEED_CONF"
fi

echo "Updating package list with custom feed..."
opkg update

echo "Installing HydraRoute package..."
opkg install hrneo hrweb

# Optional cleanup
SCRIPT="$0"
if [ -f "$SCRIPT" ]; then
  echo "- Cleaning up installer script..."
  rm "$SCRIPT"
fi

echo "Setup complete."
