#!/usr/bin/env bash
# Sync local repo to/from a remote FreeBSD host for development.
#
# Usage:
#   ./script/sync-remote.sh root@freebsd-virt        # local -> remote
#   ./script/sync-remote.sh --from root@freebsd-virt # remote -> local

set -e

usage() {
    echo "Usage: $0 [--from] <user@host>"
    echo "  Default: sync host -> remote"
    echo "  --from:  sync remote -> host"
    exit 1
}

FROM=false
if [ "$1" = "--from" ]; then
    FROM=true
    shift
fi

[ -z "$1" ] && usage

REMOTE="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$FROM" = true ]; then
    rsync -av --exclude target/ --exclude .git/ \
        "${REMOTE}:~/rogg/" \
        "$REPO_ROOT/"
else
    rsync -av --exclude target/ --exclude .git/ \
        "$REPO_ROOT/" \
        "${REMOTE}:~/rogg/"
fi
