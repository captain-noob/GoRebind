#!/usr/bin/env bash

# Fail if any command fails
set -e

# Output directory
OUT_DIR="build"
mkdir -p "$OUT_DIR"

# List of OS/Arch combinations
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "windows/amd64"
  "windows/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

echo "🔨 Building Go binaries..."

for PLATFORM in "${PLATFORMS[@]}"; do
    OS="${PLATFORM%%/*}"
    ARCH="${PLATFORM##*/}"

    BINARY_NAME="goRebind"
    OUTPUT_NAME="$BINARY_NAME"

    # Add .exe for Windows
    FINAL_NAME="$OUT_DIR/${OUTPUT_NAME}-${OS}-${ARCH}"

    if [ "$OS" = "windows" ]; then
        FINAL_NAME="${FINAL_NAME}.exe"
    fi

    echo "➡️  Building for $OS/$ARCH ..."

    env GOOS="$OS" GOARCH="$ARCH" go build -o "$FINAL_NAME" .

done

echo "✅ Build completed. Files in $OUT_DIR/"
