#!/usr/bin/env bash
# Build Docker image for bgpgg
#
# Usage:
# # builds for host platform (auto-detected)
# ./build.sh v0.1.0
#
# # builds arm64
# ./build.sh v0.1.0 linux/arm64
#
# # builds multiple platforms
# ./build.sh v0.1.0 "linux/amd64,linux/arm64"
set -eux

VERSION=$1

# Detect host platform if not specified
if [ -z "${2:-}" ]; then
  HOST_ARCH=$(uname -m)
  case "$HOST_ARCH" in
    x86_64)        PLATFORM="linux/amd64" ;;
    aarch64|arm64) PLATFORM="linux/arm64" ;;
    *)
      echo "Warning: Unsupported architecture: $HOST_ARCH, defaulting to linux/amd64"
      PLATFORM="linux/amd64"
      ;;
  esac
  echo "Auto-detected platform: $PLATFORM"
else
  PLATFORM=$2
fi

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
PROJECT_DIR="$SCRIPT_DIR/../.."
RELEASE_DIR="$PROJECT_DIR/release/$VERSION"

# Determine which tarballs are needed based on platforms
TARBALLS_NEEDED=()
if [[ "$PLATFORM" == *"amd64"* ]]; then
  TARBALLS_NEEDED+=("x86_64-linux")
fi
if [[ "$PLATFORM" == *"386"* ]]; then
  TARBALLS_NEEDED+=("i686-linux")
fi
if [[ "$PLATFORM" == *"arm64"* ]]; then
  TARBALLS_NEEDED+=("aarch64-linux")
fi
if [[ "$PLATFORM" == *"arm/v7"* ]]; then
  TARBALLS_NEEDED+=("armv7-linux")
fi

# Verify required tarballs exist
MISSING=()
for arch in "${TARBALLS_NEEDED[@]}"; do
  if [ ! -f "$RELEASE_DIR/rogg-$VERSION-$arch.tar.gz" ]; then
    MISSING+=("$arch")
  fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "Error: Missing release tarballs in $RELEASE_DIR:"
  for arch in "${MISSING[@]}"; do
    echo "  - rogg-$VERSION-$arch.tar.gz"
  done
  echo "Run ./script/build.sh $VERSION [target] first"
  exit 1
fi

# Create temporary build context
BUILD_CONTEXT=$(mktemp -d)
trap "rm -rf $BUILD_CONTEXT" EXIT

# Copy Dockerfile and required tarballs to build context
cp "$SCRIPT_DIR/Dockerfile" "$BUILD_CONTEXT/"
for arch in "${TARBALLS_NEEDED[@]}"; do
  cp "$RELEASE_DIR/rogg-$VERSION-$arch.tar.gz" "$BUILD_CONTEXT/"
done

# Count platforms (check for comma)
if [[ "$PLATFORM" == *","* ]]; then
  echo "Building for multiple platforms: $PLATFORM"

  # Check if multiarch builder exists, create if not
  if ! docker buildx ls | grep -q "multiarch"; then
    echo "Creating multiarch builder for multi-platform builds..."
    docker buildx create --name multiarch --use
    docker buildx inspect --bootstrap
  else
    echo "Using existing multiarch builder"
    docker buildx use multiarch
  fi
  echo ""

  docker buildx build \
    --platform "$PLATFORM" \
    -t roggnetwork/bgpgg:"$VERSION" \
    -t roggnetwork/bgpgg:latest \
    --build-arg VERSION="$VERSION" \
    "$BUILD_CONTEXT"

  # Switch back to default builder
  docker buildx use default
else
  echo "Building for single platform: $PLATFORM"
  echo "Image will be loaded to local Docker daemon"

  docker buildx build \
    --platform "$PLATFORM" \
    -t roggnetwork/bgpgg:"$VERSION" \
    -t roggnetwork/bgpgg:latest \
    --build-arg VERSION="$VERSION" \
    --load \
    "$BUILD_CONTEXT"
fi

echo ""
echo "Build complete!"
if [[ "$PLATFORM" != *","* ]]; then
  echo "Test with: docker run --rm roggnetwork/bgpgg:$VERSION ./bgpggd --version"
fi
