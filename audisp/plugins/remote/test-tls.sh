#!/bin/bash
# test-tls.sh -- Integration test for TLS transport
#
# Tests:
#   1. Verify audisp-remote binary has TLS support (linked with libssl)
#   2. Generate a valid PSK file
#   3. Create a representative PSK-only configuration
#   4. Test a TLS handshake with PSK using openssl s_server/s_client
#   5. Verify that a client without the PSK is rejected
#   6. Check PQC key exchange group availability
#   7. Test a PQC hybrid key exchange with PSK
#
# Requires: openssl >= 3.5, built with --enable-tls

set -e -u -o pipefail

SERVER_PID=""
TESTDIR=$(mktemp -d)
PASSED=0
FAILED=0

get_free_port() {
    local port=$1
    while ss -tln | grep -q ":${port} "; do
        port=$((port + 1))
    done
    echo "$port"
}

cleanup() {
    # Kill any background processes
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$TESTDIR"
}
trap cleanup EXIT

pass() {
    echo "  PASS: $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo "  FAIL: $1"
    FAILED=$((FAILED + 1))
}

echo "=== TLS Transport Integration Tests ==="

# Test 1: Check binary has TLS support
echo
echo "Test 1: Binary linked with OpenSSL"
# Handle libtool wrapper: real binary is in .libs/
BINARY=./audisp-remote
if [ -f .libs/audisp-remote ]; then
    BINARY=.libs/audisp-remote
fi
if ldd "$BINARY" 2>/dev/null | grep -q libssl; then
    pass "audisp-remote linked with libssl"
else
    fail "audisp-remote not linked with libssl (was --enable-tls used?)"
    echo "Skipping remaining tests - TLS support not compiled in"
    exit 1
fi

# Test 2: Generate test PSK file
echo
echo "Test 2: PSK file generation and format"
# Generate a 256-bit hex PSK
openssl rand -hex 32 > "$TESTDIR/audit.psk"
chmod 0400 "$TESTDIR/audit.psk"
PSK_HEX=$(cat "$TESTDIR/audit.psk")
if [ ${#PSK_HEX} -eq 64 ]; then
    pass "PSK file generated (256-bit hex)"
else
    fail "PSK file wrong length: ${#PSK_HEX}"
fi

# Test 3: Write a valid TLS config
echo
echo "Test 3: TLS config file creation"
cat > "$TESTDIR/audisp-remote.conf" << EOF
remote_server = 127.0.0.1
port = 60
transport = tls
queue_file = $TESTDIR/remote.log
mode = immediate
queue_depth = 200
format = managed
network_retry_time = 1
max_tries_per_record = 3
max_time_per_record = 5
heartbeat_timeout = 0
network_failure_action = stop
disk_low_action = ignore
disk_full_action = warn_once
disk_error_action = warn_once
remote_ending_action = reconnect
generic_error_action = syslog
generic_warning_action = syslog
queue_error_action = stop
overflow_action = syslog
startup_failure_action = warn_once_continue
tls_psk_file = $TESTDIR/audit.psk
tls_psk_identity = audit-test
tls_cipher_suites = TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
tls_key_exchange = X25519MLKEM768:X25519
EOF
chmod 0644 "$TESTDIR/audisp-remote.conf"

if [ -f "$TESTDIR/audisp-remote.conf" ]; then
    pass "TLS config file created"
else
    fail "TLS config file creation failed"
fi

# Test 4: TLS 1.3 PSK handshake via openssl s_server/s_client
echo
echo "Test 4: TLS 1.3 PSK handshake"
PORT=$(get_free_port 14720)

# openssl s_server with PSK
openssl s_server -tls1_3 -psk "$PSK_HEX" -psk_identity audit-test \
    -accept "$PORT" -naccept 1 -quiet \
    -nocert > "$TESTDIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.5

# openssl s_client connecting with PSK
set +e
openssl s_client -tls1_3 -psk "$PSK_HEX" -psk_identity audit-test \
    -no-interactive < /dev/null \
    -connect "127.0.0.1:$PORT" \
    > "$TESTDIR/client.log" 2>&1
CLIENT_STATUS=$?
set -e

wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

if [ "$CLIENT_STATUS" -eq 0 ] && \
   grep -Eq '^(New|Reused), TLSv1.3, Cipher is TLS_' \
        "$TESTDIR/client.log" 2>/dev/null; then
    pass "TLS 1.3 PSK handshake succeeded"
else
    fail "TLS 1.3 PSK handshake failed"
    cat "$TESTDIR/client.log" 2>/dev/null || true
fi

# Test 5: Client without the PSK must not negotiate TLS
echo
echo "Test 5: No-PSK client rejection"
PORT=$(get_free_port 14721)

openssl s_server -tls1_3 -psk "$PSK_HEX" -psk_identity audit-test \
    -accept "$PORT" -naccept 1 -quiet -nocert \
    > "$TESTDIR/no-psk-server.log" 2>&1 &
SERVER_PID=$!
sleep 0.5

set +e
openssl s_client -tls1_3 -connect "127.0.0.1:$PORT" \
    < /dev/null > "$TESTDIR/no-psk-client.log" 2>&1
CLIENT_STATUS=$?
set -e

wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

if [ "$CLIENT_STATUS" -ne 0 ] && \
   ! grep -Eq '^(New|Reused), TLSv1.3, Cipher is ' \
        "$TESTDIR/no-psk-client.log" 2>/dev/null; then
    pass "client without PSK was rejected"
else
    fail "client without PSK negotiated TLS"
    cat "$TESTDIR/no-psk-client.log" 2>/dev/null || true
fi

# Test 6: PQC key exchange availability
echo
echo "Test 6: PQC key exchange group availability"
if openssl list -kem-algorithms 2>/dev/null | grep -qi 'mlkem\|ML-KEM'; then
    pass "ML-KEM key exchange available in OpenSSL"
else
    echo "  SKIP: ML-KEM not available in this OpenSSL build" \
        "(PQC will use classical fallback)"
fi

# Test 7: PQC hybrid key exchange handshake
echo
echo "Test 7: PQC hybrid key exchange handshake"
PORT=$(get_free_port 14722)
if openssl list -kem-algorithms 2>/dev/null | grep -qi mlkem; then
    openssl s_server -tls1_3 -groups X25519MLKEM768:X25519 \
        -psk "$PSK_HEX" -psk_identity audit-test -nocert \
        -accept "$PORT" -naccept 1 -quiet \
        > "$TESTDIR/pqc-server.log" 2>&1 &
    SERVER_PID=$!
    sleep 0.5
    set +e
    openssl s_client -tls1_3 -no-interactive < /dev/null \
        -groups X25519MLKEM768 -psk "$PSK_HEX" \
        -psk_identity audit-test \
        -connect "127.0.0.1:$PORT" \
        > "$TESTDIR/pqc-client.log" 2>&1
    CLIENT_STATUS=$?
    set -e
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    # With -groups X25519MLKEM768 (no fallback), connection only
    # succeeds if both sides support ML-KEM hybrid kex
    if [ "$CLIENT_STATUS" -eq 0 ] && \
       grep -Eq '^(New|Reused), TLSv1.3, Cipher is ' \
            "$TESTDIR/pqc-client.log" 2>/dev/null; then
        pass "PQC hybrid key exchange negotiated"
    else
        fail "PQC hybrid key exchange not negotiated"
    fi
else
    echo "  SKIP: ML-KEM not available"
fi

# Summary
echo
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
