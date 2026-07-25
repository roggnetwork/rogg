#!/usr/bin/env bash
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version> [target]"
    echo "Example: $0 v0.1.0"
    echo "Example: $0 v0.1.0 linux/amd64"
    exit 1
fi

# Install cross if not present
if ! command -v cross &> /dev/null; then
    echo "Installing cross..."
    cargo install cross --git https://github.com/cross-rs/cross
fi

VERSION=$1
RELEASE_DIR="release/$VERSION"
mkdir -p "$RELEASE_DIR"

build_and_package() {
    local TARGET=$1
    local PLATFORM=$2
    # Per-target build dir: cross containers have different host glibc versions,
    # so cached build-script binaries must not be shared between targets.
    local TARGET_DIR="target/cross/$TARGET"

    echo "Building bgpgg $VERSION for $PLATFORM..."
    CARGO_TARGET_DIR="$TARGET_DIR" cross build --release --target "$TARGET" --bin bgpggd --bin ggsh

    # Strip binaries (skip for FreeBSD)
    if [[ "$TARGET" != *"freebsd"* ]]; then
        strip "$TARGET_DIR/$TARGET/release/bgpggd" 2>/dev/null || true
        strip "$TARGET_DIR/$TARGET/release/ggsh" 2>/dev/null || true
    fi

    # Package
    ARCHIVE_NAME="rogg-$VERSION-$PLATFORM"
    ARCHIVE_FILE="$RELEASE_DIR/$ARCHIVE_NAME.tar.gz"

    mkdir -p "$ARCHIVE_NAME"
    cp "$TARGET_DIR/$TARGET/release/bgpggd" "$ARCHIVE_NAME/"
    cp "$TARGET_DIR/$TARGET/release/ggsh" "$ARCHIVE_NAME/"
    cp LICENSE "$ARCHIVE_NAME/" 2>/dev/null || true

    tar czf "$ARCHIVE_FILE" "$ARCHIVE_NAME"
    rm -rf "$ARCHIVE_NAME"

    echo "Created: $ARCHIVE_FILE"
}

# Build based on target parameter
TARGET_PLATFORM=$2

if [ -n "$TARGET_PLATFORM" ]; then
    # Build single platform
    case "$TARGET_PLATFORM" in
        "linux/amd64")
            build_and_package "x86_64-unknown-linux-musl" "x86_64-linux"
            ;;
        "linux/arm64")
            build_and_package "aarch64-unknown-linux-musl" "aarch64-linux"
            ;;
        "linux/arm/v7")
            build_and_package "armv7-unknown-linux-musleabihf" "armv7-linux"
            ;;
        "linux/386")
            build_and_package "i686-unknown-linux-musl" "i686-linux"
            ;;
        *)
            echo "Error: Unsupported target: $TARGET_PLATFORM"
            echo "Supported targets: linux/amd64, linux/arm64, linux/arm/v7, linux/386"
            exit 1
            ;;
    esac
    echo ""
    echo "Build complete! Archive in release/$VERSION/"
else
    # Build all platforms
    build_and_package "x86_64-unknown-linux-musl" "x86_64-linux"
    build_and_package "aarch64-unknown-linux-musl" "aarch64-linux"
    build_and_package "armv7-unknown-linux-musleabihf" "armv7-linux"
    build_and_package "i686-unknown-linux-musl" "i686-linux"
    build_and_package "x86_64-unknown-freebsd" "x86_64-freebsd"
    echo ""
    echo "All builds complete! Archives in release/$VERSION/"
fi
