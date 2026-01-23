#!/bin/bash

set -e

BINARY_PATH="$1"
USER=$(whoami)

if [ -z "$BINARY_PATH" ]; then
    echo "Usage: $0 <path-to-localproxyd-binary>"
    echo "Example: $0 /usr/local/bin/localproxyd"
    exit 1
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found at $BINARY_PATH"
    exit 1
fi

SUDOERS_FILE="/etc/sudoers.d/localproxy-dtrace"

echo "Creating sudoers rule to allow dtrace without password..."
echo "This will allow user '$USER' to run dtrace via localproxyd"

SUDOERS_CONTENT="$USER ALL=(root) NOPASSWD: /usr/sbin/dtrace"

echo "$SUDOERS_CONTENT" | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 0440 "$SUDOERS_FILE"

echo "✓ Sudoers configuration created at $SUDOERS_FILE"
echo ""
echo "You can now run localproxyd normally without sudo:"
echo "  $BINARY_PATH"
echo ""
echo "The dtrace calls within the application will use sudo automatically."
