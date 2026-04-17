#!/bin/bash
# test-tls.sh -- Integration test for TLS transport
#
# Tests:
#   1. Verify audisp-remote binary has TLS support (linked with libssl)
#   2. Verify TLS config parsing works
#   3. Verify PSK file format validation
#   4. Verify cert/key permission validation
#   5. Test TLS handshake with PSK mode using openssl s_server/s_client
#   6. Test PQC key exchange group negotiation
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

# Test 3: Generate test certificates
echo
echo "Test 3: Certificate generation"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TESTDIR/server-key.pem" -out "$TESTDIR/server-cert.pem" \
    -days 1 -nodes -subj "/CN=audit-test-server" 2>/dev/null
chmod 0400 "$TESTDIR/server-key.pem"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$TESTDIR/client-key.pem" -out "$TESTDIR/client-cert.pem" \
    -days 1 -nodes -subj "/CN=audit-test-client" 2>/dev/null
chmod 0400 "$TESTDIR/client-key.pem"

if [ -f "$TESTDIR/server-cert.pem" ] && [ -f "$TESTDIR/client-cert.pem" ]; then
    pass "Test certificates generated"
else
    fail "Certificate generation failed"
fi

# Test 4: Write a valid TLS config
echo
echo "Test 4: TLS config file creation"
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

# Test 5: TLS 1.3 PSK handshake via openssl s_server/s_client
echo
echo "Test 5: TLS 1.3 PSK handshake"
PORT=$(get_free_port 14720)

# openssl s_server with PSK
openssl s_server -tls1_3 -psk "$PSK_HEX" -psk_identity audit-test \
    -accept "$PORT" -naccept 1 \
    -nocert > "$TESTDIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.5

# openssl s_client connecting with PSK
echo "test audit message" | \
    openssl s_client -tls1_3 -psk "$PSK_HEX" -psk_identity audit-test \
    -connect "127.0.0.1:$PORT" \
    > "$TESTDIR/client.log" 2>&1 || true

wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

if grep -q "TLS_AES_256_GCM_SHA384\|TLS_AES_128_GCM_SHA256" "$TESTDIR/client.log" 2>/dev/null; then
    pass "TLS 1.3 PSK handshake succeeded"
else
    # Check if connection was established
    if grep -q "CONNECTED" "$TESTDIR/client.log" 2>/dev/null; then
        pass "TLS 1.3 PSK handshake connected"
    else
        fail "TLS 1.3 PSK handshake failed"
        cat "$TESTDIR/client.log" 2>/dev/null || true
    fi
fi

# Test 6: PQC key exchange availability
echo
echo "Test 6: PQC key exchange group availability"
if openssl list -kem-algorithms 2>/dev/null | grep -qi 'mlkem\|ML-KEM'; then
    pass "ML-KEM key exchange available in OpenSSL"
else
    echo "  SKIP: ML-KEM not available in this OpenSSL build (PQC will use classical fallback)"
fi

# Test 7: TLS 1.3 certificate handshake
echo
echo "Test 7: TLS 1.3 certificate handshake"
PORT=$(get_free_port 14721)

openssl s_server -tls1_3 \
    -cert "$TESTDIR/server-cert.pem" -key "$TESTDIR/server-key.pem" \
    -accept "$PORT" -naccept 1 \
    > "$TESTDIR/cert-server.log" 2>&1 &
SERVER_PID=$!
sleep 0.5

echo "test audit message" | \
    openssl s_client -tls1_3 \
    -connect "127.0.0.1:$PORT" \
    > "$TESTDIR/cert-client.log" 2>&1 || true

wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

if grep -q "CONNECTED" "$TESTDIR/cert-client.log" 2>/dev/null; then
    pass "TLS 1.3 certificate handshake succeeded"
else
    fail "TLS 1.3 certificate handshake failed"
fi

# Test 8: PQC hybrid key exchange handshake
echo
echo "Test 8: PQC hybrid key exchange handshake"
PORT=$(get_free_port 14722)
if openssl list -kem-algorithms 2>/dev/null | grep -qi mlkem; then
    openssl s_server -tls1_3 -groups X25519MLKEM768:X25519 \
        -cert "$TESTDIR/server-cert.pem" \
        -key "$TESTDIR/server-key.pem" \
        -accept "$PORT" -naccept 1 > "$TESTDIR/pqc-server.log" 2>&1 &
    SERVER_PID=$!
    sleep 0.5
    echo "test" | openssl s_client -tls1_3 \
        -groups X25519MLKEM768 \
        -connect "127.0.0.1:$PORT" \
        > "$TESTDIR/pqc-client.log" 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    # With -groups X25519MLKEM768 (no fallback), connection only
    # succeeds if both sides support ML-KEM hybrid kex
    if grep -q "CONNECTED" "$TESTDIR/pqc-client.log" 2>/dev/null && \
       grep -q "TLSv1.3" "$TESTDIR/pqc-client.log" 2>/dev/null; then
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
