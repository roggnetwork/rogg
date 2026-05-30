#!/usr/bin/env bash
# ggsh system tests. No root required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BGPGGD="${BGPGGD:-$PROJECT_DIR/target/release/bgpggd}"
GGSH="${GGSH:-$PROJECT_DIR/target/release/ggsh}"

ggsh_configure() {
    local grpc=$1 conf=$2
    shift 2
    {
        echo configure
        echo service bgp
        for line in "$@"; do echo "$line"; done
        echo commit
        echo exit
        echo exit
    } | "$GGSH" --bgpgg-addr "$grpc" --config "$conf" >/dev/null
}

PEER1_PID=
PEER2_PID=
TMPDIR=$(mktemp -d)

cleanup() {
    [ -n "$PEER1_PID" ] && kill "$PEER1_PID" 2>/dev/null || true
    [ -n "$PEER2_PID" ] && kill "$PEER2_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    PEER1_PID=
    PEER2_PID=
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

poll_until() {
    local desc=$1 timeout=$2
    shift 2
    for _ in $(seq 1 "$timeout"); do
        if eval "$*" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "Timed out: $desc"
    return 1
}

P1_GRPC=http://127.0.0.1:50081
P2_GRPC=http://127.0.0.2:50082

# Short connect-retry: loser of TCP collision otherwise waits 30s
# (BGP default), racing the script's 30s poll below.
cat > "$TMPDIR/peer1.conf" <<'EOF'
service bgp {
  asn 65001
  router-id 1.1.1.1
  listen-addr 127.0.0.1:14179
  grpc-listen-addr 127.0.0.1:50081
  connect-retry 1
}
EOF

cat > "$TMPDIR/peer2.conf" <<'EOF'
service bgp {
  asn 65001
  router-id 2.2.2.2
  listen-addr 127.0.0.2:14179
  grpc-listen-addr 127.0.0.2:50082
  connect-retry 1
}
EOF

echo "Starting peer1 (ASN 65001, 127.0.0.1:14179, router-id 1.1.1.1)..."
"$BGPGGD" --config "$TMPDIR/peer1.conf" --runtime-dir "$TMPDIR/peer1-run" &
PEER1_PID=$!

echo "Starting peer2 (ASN 65001, 127.0.0.2:14179, router-id 2.2.2.2)..."
"$BGPGGD" --config "$TMPDIR/peer2.conf" --runtime-dir "$TMPDIR/peer2-run" &
PEER2_PID=$!

echo "Waiting for gRPC..."
poll_until "peer1 gRPC not ready" 10 "$GGSH --bgpgg-addr $P1_GRPC show bgp summary"
poll_until "peer2 gRPC not ready" 10 "$GGSH --bgpgg-addr $P2_GRPC show bgp summary"

echo "Adding peers..."
ggsh_configure "$P1_GRPC" "$TMPDIR/peer1.conf" \
    "peer 127.0.0.2 remote-as 65001" \
    "peer 127.0.0.2 port 14179"
ggsh_configure "$P2_GRPC" "$TMPDIR/peer2.conf" \
    "peer 127.0.0.1 remote-as 65001" \
    "peer 127.0.0.1 port 14179"

echo "Waiting for session to establish..."
poll_until "Peering failed to establish" 30 \
    "$GGSH --bgpgg-addr $P1_GRPC show bgp summary | grep -q Established"

echo "Announcing 10.99.0.0/24 from peer2..."
ggsh_configure "$P2_GRPC" "$TMPDIR/peer2.conf" \
    "originate 10.99.0.0/24 nexthop 192.168.1.1"

echo "Waiting for route to propagate..."
poll_until "Route did not propagate" 10 \
    "$GGSH --bgpgg-addr $P1_GRPC show bgp routes | grep -q 10.99.0.0/24"

# --- ggsh tests ---

echo ""
echo "=== ggsh one-shot: show bgp summary ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp summary)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in summary"; exit 1; }
echo "$OUTPUT" | grep -q "127.0.0.2" || { echo "FAIL: expected peer address in summary"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show bgp routes ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp routes)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "10.99.0.0/24" || { echo "FAIL: expected route in routes"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show bgp peers ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp peers)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "127.0.0.2" || { echo "FAIL: expected peer in peers list"; exit 1; }
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in peers list"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show bgp peers <addr> ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp peers 127.0.0.2)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "127.0.0.2" || { echo "FAIL: expected peer address in detail"; exit 1; }
echo "$OUTPUT" | grep -q "65001" || { echo "FAIL: expected ASN in peer detail"; exit 1; }
echo "  ok"

echo "=== ggsh one-shot: show version ==="
OUTPUT=$("$GGSH" --runtime-dir "$TMPDIR/peer1-run" show version)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "ggsh" || { echo "FAIL: expected ggsh in version"; exit 1; }
echo "  ok"

echo "=== ggsh piped mode ==="
OUTPUT=$(echo "show bgp summary" | "$GGSH" --bgpgg-addr "$P1_GRPC")
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in piped output"; exit 1; }
echo "  ok"

echo "=== ggsh stdin with multiple commands ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" <<'EOF'
show bgp summary
show bgp routes
exit
EOF
)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established in stdin output"; exit 1; }
echo "$OUTPUT" | grep -q "10.99.0.0/24" || { echo "FAIL: expected route in stdin output"; exit 1; }
echo "  ok"

echo "=== ggsh incomplete command: show bgp ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" show bgp 2>&1 || true)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "summary" || { echo "FAIL: expected summary in subcommands"; exit 1; }
echo "$OUTPUT" | grep -q "peers" || { echo "FAIL: expected peers in subcommands"; exit 1; }
echo "$OUTPUT" | grep -q "routes" || { echo "FAIL: expected routes in subcommands"; exit 1; }
echo "  ok"

echo "=== ggsh interactive: error does not exit ==="
OUTPUT=$("$GGSH" --bgpgg-addr "$P1_GRPC" <<'EOF'
show bogus
show bgp summary
exit
EOF
)
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "Established" || { echo "FAIL: expected Established after error"; exit 1; }
echo "  ok"

echo "=== ggsh error: unknown command ==="
if "$GGSH" --bgpgg-addr "$P1_GRPC" show bogus 2>/dev/null; then
    echo "FAIL: expected non-zero exit for unknown command"
    exit 1
fi
echo "  ok"

echo "=== ggsh error: trailing tokens after prefix ==="
if "$GGSH" --bgpgg-addr "$P1_GRPC" show bgp routes 10.99.0.0/24 random string 2>/dev/null; then
    echo "FAIL: expected non-zero exit for trailing tokens"
    exit 1
fi
echo "  ok"

echo "=== ggsh error: trailing tokens after version ==="
if "$GGSH" --bgpgg-addr "$P1_GRPC" show version extra 2>/dev/null; then
    echo "FAIL: expected non-zero exit for trailing tokens"
    exit 1
fi
echo "  ok"

echo "=== ggsh error: trailing tokens after safi ==="
if "$GGSH" --bgpgg-addr "$P1_GRPC" show bgp routes ipv4 unicast extra 2>/dev/null; then
    echo "FAIL: expected non-zero exit for trailing tokens"
    exit 1
fi
echo "  ok"

cleanup
echo ""
echo "All ggsh system tests passed"
