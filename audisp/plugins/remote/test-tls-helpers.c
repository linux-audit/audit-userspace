/* test-tls-helpers.c -- unit tests for TLS helper functions in autls/
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * Authors:
 *   Sergio Correia <scorreia@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include "autls.h"

#ifdef HAVE_TLS
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static char tmpdir[256];

static void test_log(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

static void write_file(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");
	assert(f != NULL);
	if (content)
		fputs(content, f);
	fclose(f);
}

static void cleanup(void)
{
	char cmd[768];

	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
	system(cmd);
}

static void test_autls_is_pqc_group(void)
{
	printf("  autls_is_pqc_group...\n");

	/* Classical groups -- all return 0 */
	assert(autls_is_pqc_group(NULL) == 0);
	assert(autls_is_pqc_group("") == 0);
	assert(autls_is_pqc_group("X25519") == 0);
	assert(autls_is_pqc_group("P-256") == 0);
	assert(autls_is_pqc_group("P-384") == 0);
	assert(autls_is_pqc_group("P-521") == 0);
	assert(autls_is_pqc_group("X448") == 0);
	assert(autls_is_pqc_group("ffdhe2048") == 0);
	assert(autls_is_pqc_group("brainpoolP256r1tls13") == 0);

	/* Case sensitivity and near-misses -- return 0 */
	assert(autls_is_pqc_group("x25519mlkem768") == 0);
	assert(autls_is_pqc_group("MLKE") == 0);

	/* PQC groups -- all return 1 */
	assert(autls_is_pqc_group("X25519MLKEM768") == 1);
	assert(autls_is_pqc_group("SecP256r1MLKEM768") == 1);
	assert(autls_is_pqc_group("SecP384r1MLKEM1024") == 1);
	assert(autls_is_pqc_group("MLKEM768") == 1);
	assert(autls_is_pqc_group("MLKEM1024") == 1);
	assert(autls_is_pqc_group("X448MLKEM1024") == 1);
}

static void test_autls_remaining_ms(void)
{
	struct timespec deadline;
	int r;

	printf("  autls_remaining_ms...\n");

	/* 1 second in the future */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += 1;
	r = autls_remaining_ms(&deadline);
	assert(r > 900 && r <= 1000);

	/* 10 seconds in the past */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec -= 10;
	r = autls_remaining_ms(&deadline);
	assert(r == 0);

	/* Epoch-like value (always in the past) */
	deadline.tv_sec = 0;
	deadline.tv_nsec = 0;
	r = autls_remaining_ms(&deadline);
	assert(r == 0);

	/* Large deadline -- tests INT_MAX clamp (~25 days) */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += 2200000;
	r = autls_remaining_ms(&deadline);
	assert(r == INT_MAX);

	/* Nanosecond boundary */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += 1;
	deadline.tv_nsec = 999999999;
	r = autls_remaining_ms(&deadline);
	assert(r > 900 && r <= 2000);
}

/* Verify a silent peer cannot extend the TLS handshake deadline. */
static void test_autls_ssl_connect_deadline(void)
{
	struct timespec start, end;
	SSL_CTX *ctx;
	SSL *ssl;
	long long elapsed;
	int pair[2], flags;

	printf("  autls_ssl_connect deadline...\n");
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);

	ctx = SSL_CTX_new(TLS_client_method());
	assert(ctx != NULL);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	ssl = SSL_new(ctx);
	assert(ssl != NULL);
	assert(SSL_set_fd(ssl, pair[0]) == 1);

	flags = fcntl(pair[0], F_GETFL);
	assert(flags >= 0);
	clock_gettime(CLOCK_MONOTONIC, &start);
	assert(autls_ssl_connect(ssl, 100) == -1);
	clock_gettime(CLOCK_MONOTONIC, &end);
	assert(fcntl(pair[0], F_GETFL) == flags);

	elapsed = (long long)(end.tv_sec - start.tv_sec) * 1000 +
		(end.tv_nsec - start.tv_nsec) / 1000000;
	assert(elapsed >= 50);
	assert(elapsed < 1000);

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(pair[0]);
	close(pair[1]);
}

/*
 * Helper to create a PSK test file with correct permissions.
 * Sets mode 0400 so autls_load_psk's built-in validation can
 * pass on root-owned files (when running as root).
 */
static void write_psk_file(const char *path, const char *content)
{
	write_file(path, content);
	chmod(path, 0400);
}

static void test_autls_load_psk(void)
{
	char path[512];
	unsigned char *key = NULL;
	size_t key_len = 0;
	unsigned char expected[32];
	int i;

	printf("  autls_load_psk...\n");

	/* Nonexistent file -- open() fails */
	snprintf(path, sizeof(path), "%s/nonexistent-psk", tmpdir);
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);

	/*
	 * Hex-parsing tests: autls_load_psk now validates permissions
	 * internally (must be mode 0400, root-owned).  These tests
	 * exercise the parsing path and only succeed fully when run
	 * as root.  When run as non-root, we still verify that all
	 * of them are rejected (either by uid check or parse error).
	 */

	/* Empty file */
	snprintf(path, sizeof(path), "%s/empty-psk", tmpdir);
	write_psk_file(path, "");
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Whitespace-only file */
	snprintf(path, sizeof(path), "%s/ws-psk", tmpdir);
	write_psk_file(path, "\n");
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Odd-length hex */
	snprintf(path, sizeof(path), "%s/odd-psk", tmpdir);
	write_psk_file(path, "abc\n");
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Short key (8 bytes, below 32-byte minimum) */
	snprintf(path, sizeof(path), "%s/short-psk", tmpdir);
	write_psk_file(path, "0011223344556677\n");
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Invalid hex characters */
	snprintf(path, sizeof(path), "%s/badhex-psk", tmpdir);
	write_psk_file(path,
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n");
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Colon-separated hex with trailing incomplete byte --
	 * even length (94 chars), passes len%2 but fails in
	 * OPENSSL_hexstr2buf due to malformed input */
	snprintf(path, sizeof(path), "%s/colon-psk", tmpdir);
	write_psk_file(path,
		"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
		":AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:9\n");
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Valid 64-char hex key (32 bytes) -- requires root */
	snprintf(path, sizeof(path), "%s/valid-psk", tmpdir);
	write_psk_file(path,
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f\n");
	if (getuid() == 0) {
		assert(autls_load_psk(path, &key, &key_len,
			test_log) == 0);
		assert(key != NULL);
		assert(key_len == 32);
		for (i = 0; i < 32; i++)
			expected[i] = (unsigned char)i;
		assert(memcmp(key, expected, 32) == 0);
		OPENSSL_cleanse(key, key_len);
		OPENSSL_free(key);
		key = NULL;
	} else {
		/* Non-root: uid check rejects before parsing */
		assert(autls_load_psk(path, &key, &key_len,
			test_log) == -1);
	}
	unlink(path);

	/* Valid uppercase hex key -- requires root */
	snprintf(path, sizeof(path), "%s/upper-psk", tmpdir);
	write_psk_file(path,
		"AABBCCDDAABBCCDDAABBCCDDAABBCCDD"
		"AABBCCDDAABBCCDDAABBCCDDAABBCCDD\n");
	if (getuid() == 0) {
		assert(autls_load_psk(path, &key, &key_len,
			test_log) == 0);
		assert(key != NULL);
		assert(key_len == 32);
		OPENSSL_cleanse(key, key_len);
		OPENSSL_free(key);
		key = NULL;
	} else {
		assert(autls_load_psk(path, &key, &key_len,
			test_log) == -1);
	}
	unlink(path);
}

static void test_autls_load_psk_validation(void)
{
	char path[512];
	unsigned char *key = NULL;
	size_t key_len = 0;
	const char *valid_hex =
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f\n";

	printf("  autls_load_psk (built-in validation)...\n");

	/* Mode 0644 -- rejected by fstat check */
	snprintf(path, sizeof(path), "%s/psk-mode-644", tmpdir);
	write_file(path, valid_hex);
	chmod(path, 0644);
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Mode 0600 -- only exactly 0400 passes */
	snprintf(path, sizeof(path), "%s/psk-mode-600", tmpdir);
	write_file(path, valid_hex);
	chmod(path, 0600);
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Symlink -- rejected by O_NOFOLLOW */
	if (getuid() == 0) {
		char target[512], link_path[512];

		snprintf(target, sizeof(target),
			"%s/psk-sym-target", tmpdir);
		snprintf(link_path, sizeof(link_path),
			"%s/psk-sym-link", tmpdir);
		write_file(target, valid_hex);
		chmod(target, 0400);
		symlink(target, link_path);
		assert(autls_load_psk(link_path, &key, &key_len,
			test_log) == -1);
		unlink(link_path);
		unlink(target);
	}

	/* Valid file, mode 0400, root-owned -- passes when run as root */
	snprintf(path, sizeof(path), "%s/psk-valid", tmpdir);
	write_file(path, valid_hex);
	chmod(path, 0400);
	if (getuid() == 0) {
		assert(autls_load_psk(path, &key, &key_len,
			test_log) == 0);
		assert(key != NULL);
		assert(key_len == 32);
		OPENSSL_cleanse(key, key_len);
		OPENSSL_free(key);
		key = NULL;
	} else {
		/* Not root -- uid check fails */
		assert(autls_load_psk(path, &key, &key_len,
			test_log) == -1);
	}
	unlink(path);
}

/*
 * test_autls_load_secret_fifo - check FIFO rejection in secret loaders
 *
 * Creates a PSK FIFO with no writer. The loader must reject the path
 * promptly instead of blocking before validation.
 */
static void test_autls_load_secret_fifo(void)
{
	char path[512];
	unsigned char *key = NULL;
	size_t key_len = 0;

	printf("  autls secret loaders reject FIFOs...\n");

	snprintf(path, sizeof(path), "%s/psk-fifo", tmpdir);
	assert(mkfifo(path, 0400) == 0);
	alarm(5);
	assert(autls_load_psk(path, &key, &key_len, test_log) == -1);
	alarm(0);
	assert(key == NULL);
	assert(key_len == 0);
	unlink(path);
}

/*
 * test_autls_acl_fifo - check ACL FIFO rejection before a blocking open
 *
 * Returns: None.
 */
static void test_autls_acl_fifo(void)
{
	struct autls_acl_table *table = NULL;
	char path[512];

	printf("  autls ACL loader rejects FIFOs...\n");
	snprintf(path, sizeof(path), "%s/acl-fifo", tmpdir);
	assert(mkfifo(path, 0400) == 0);

	/* An unfixed blocking open would hang here with no FIFO writer. */
	alarm(5);
	assert(autls_acl_load(path, &table, test_log) == -1);
	alarm(0);
	assert(table == NULL);
	unlink(path);
}

static void test_autls_validate_psk_identity(void)
{
	printf("  autls_validate_psk_identity...\n");

	/* Empty and NULL */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"", 0, test_log) == -1);

	/* Valid identities */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"host-1", 6, test_log) == 0);
	assert(autls_validate_psk_identity(
		(const unsigned char *)"a", 1, test_log) == 0);
	assert(autls_validate_psk_identity(
		(const unsigned char *)"host.example-01_test", 20,
		test_log) == 0);

	/* Printable ASCII boundary: 0x21 (!) and 0x7E (~) */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"!", 1, test_log) == 0);
	assert(autls_validate_psk_identity(
		(const unsigned char *)"~", 1, test_log) == 0);

	/* Space (0x20) rejected */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"a b", 3, test_log) == -1);

	/* Control chars rejected */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"\t", 1, test_log) == -1);
	assert(autls_validate_psk_identity(
		(const unsigned char *)"\n", 1, test_log) == -1);
	assert(autls_validate_psk_identity(
		(const unsigned char *)"\x01", 1, test_log) == -1);

	/* NUL byte rejected */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"a\x00" "b", 3, test_log) == -1);

	/* DEL (0x7F) rejected */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"\x7F", 1, test_log) == -1);

	/* High bytes (0x80-0xFF) rejected */
	assert(autls_validate_psk_identity(
		(const unsigned char *)"\x80", 1, test_log) == -1);
	assert(autls_validate_psk_identity(
		(const unsigned char *)"\xC0\xAF", 2, test_log) == -1);
	assert(autls_validate_psk_identity(
		(const unsigned char *)"\xFF", 1, test_log) == -1);

	/* Max length (255) accepted */
	{
		unsigned char buf[256];
		memset(buf, 'A', 255);
		assert(autls_validate_psk_identity(
			buf, 255, test_log) == 0);
	}

	/* Overlength (256) rejected */
	{
		unsigned char buf[257];
		memset(buf, 'A', 256);
		assert(autls_validate_psk_identity(
			buf, 256, test_log) == -1);
	}
}

static void test_autls_profile_ciphers(void)
{
	printf("  autls_profile_ciphers...\n");

	/* COMPATIBLE returns non-NULL default */
	assert(autls_profile_ciphers(AUTLS_PROFILE_COMPATIBLE) != NULL);
	assert(strstr(autls_profile_ciphers(AUTLS_PROFILE_COMPATIBLE),
		"TLS_AES_256_GCM_SHA384") != NULL);

	/* PQC returns same as COMPATIBLE */
	assert(autls_profile_ciphers(AUTLS_PROFILE_PQC) != NULL);
	assert(strcmp(autls_profile_ciphers(AUTLS_PROFILE_PQC),
		autls_profile_ciphers(AUTLS_PROFILE_COMPATIBLE)) == 0);

	/* SYSTEM returns NULL (defer to system policy) */
	assert(autls_profile_ciphers(AUTLS_PROFILE_SYSTEM) == NULL);
}

static void test_autls_profile_groups(void)
{
	printf("  autls_profile_groups...\n");

	/* COMPATIBLE returns hybrid + classical */
	assert(autls_profile_groups(AUTLS_PROFILE_COMPATIBLE) != NULL);
	assert(strstr(autls_profile_groups(AUTLS_PROFILE_COMPATIBLE),
		"X25519") != NULL);

	/* PQC returns hybrid-only (no plain X25519) */
	assert(autls_profile_groups(AUTLS_PROFILE_PQC) != NULL);
	assert(strstr(autls_profile_groups(AUTLS_PROFILE_PQC),
		"MLKEM") != NULL);

	/* SYSTEM returns NULL */
	assert(autls_profile_groups(AUTLS_PROFILE_SYSTEM) == NULL);
}

static void test_autls_crypto_audit_format(void)
{
	struct autls_audit_session session;
	char buf[256];
	char tiny[16];

	printf("  autls crypto audit format...\n");

	session.direction = "from-client";
	session.cipher = "TLS_AES_256_GCM_SHA384";
	session.ksize = 256;
	session.pfs = "X25519MLKEM768";
	session.spid = 123;
	session.suid = "?";
	session.rport = 40918;
	session.laddr = "::1";
	session.lport = 60;

	assert(autls_format_crypto_session(buf, sizeof(buf), &session) == 0);
	assert(strcmp(buf,
		"op=start direction=from-client "
		"cipher=TLS_AES_256_GCM_SHA384 ksize=256 "
		"mac=<implicit> pfs=X25519MLKEM768 spid=123 suid=? "
		"rport=40918 laddr=::1 lport=60 ") == 0);
	assert(autls_format_crypto_session(tiny, sizeof(tiny),
		&session) == -1);

	session.direction = "both";
	assert(autls_format_crypto_key_destroy(buf, sizeof(buf),
		&session) == 0);
	assert(strcmp(buf,
		"op=destroy kind=session fp=? direction=both spid=123 "
		"suid=? rport=40918 laddr=::1 lport=60 ") == 0);
	assert(autls_format_crypto_key_destroy(tiny, sizeof(tiny),
		&session) == -1);
}

static void test_autls_acl_load(void)
{
	struct autls_acl_table *t = NULL;
	char path[512];

	printf("  autls_acl_load...\n");

	/* Valid file with one enabled, one disabled */
	snprintf(path, sizeof(path), "%s/acl-valid", tmpdir);
	write_file(path, "host-1 enabled prod\nhost-2 disabled retired\n");
	chmod(path, 0600);
	if (getuid() == 0) {
		assert(autls_acl_load(path, &t, test_log) == 0);
		assert(t != NULL);
		assert(t->count == 2);
		assert(t->enabled_count == 1);
		autls_acl_free(t);
		t = NULL;
	}
	unlink(path);

	/* Empty file (no entries) */
	snprintf(path, sizeof(path), "%s/acl-empty", tmpdir);
	write_file(path, "# only comments\n\n");
	chmod(path, 0600);
	if (getuid() == 0) {
		assert(autls_acl_load(path, &t, test_log) == 0);
		assert(t != NULL);
		assert(t->count == 0);
		assert(t->enabled_count == 0);
		autls_acl_free(t);
		t = NULL;
	}
	unlink(path);

	/* Duplicate identity rejected */
	snprintf(path, sizeof(path), "%s/acl-dup", tmpdir);
	write_file(path, "host-1 enabled\nhost-1 disabled\n");
	chmod(path, 0600);
	if (getuid() == 0) {
		assert(autls_acl_load(path, &t, test_log) == -1);
		assert(t == NULL);
	}
	unlink(path);

	/* Invalid status rejected */
	snprintf(path, sizeof(path), "%s/acl-badstatus", tmpdir);
	write_file(path, "host-1 active\n");
	chmod(path, 0600);
	if (getuid() == 0) {
		assert(autls_acl_load(path, &t, test_log) == -1);
	}
	unlink(path);

	/* Missing status field rejected */
	snprintf(path, sizeof(path), "%s/acl-nostatus", tmpdir);
	write_file(path, "host-1\n");
	chmod(path, 0600);
	if (getuid() == 0) {
		assert(autls_acl_load(path, &t, test_log) == -1);
	}
	unlink(path);

	/* Case-insensitive status */
	snprintf(path, sizeof(path), "%s/acl-case", tmpdir);
	write_file(path, "host-1 Enabled\nhost-2 DISABLED\n");
	chmod(path, 0600);
	if (getuid() == 0) {
		assert(autls_acl_load(path, &t, test_log) == 0);
		assert(t->count == 2);
		assert(t->enabled_count == 1);
		autls_acl_free(t);
		t = NULL;
	}
	unlink(path);

	/* Group-writable file rejected */
	snprintf(path, sizeof(path), "%s/acl-gw", tmpdir);
	write_file(path, "host-1 enabled\n");
	chmod(path, 0660);
	if (getuid() == 0) {
		assert(autls_acl_load(path, &t, test_log) == -1);
	}
	unlink(path);
}

static void test_autls_acl_check(void)
{
	struct autls_acl_table *t = NULL;
	char path[512];

	printf("  autls_acl_check...\n");

	snprintf(path, sizeof(path), "%s/acl-check", tmpdir);
	write_file(path, "host-1 enabled\nhost-2 disabled\n");
	chmod(path, 0600);
	if (getuid() != 0) {
		printf("    (skipped, not root)\n");
		unlink(path);
		return;
	}
	assert(autls_acl_load(path, &t, test_log) == 0);
	unlink(path);

	/* Enabled returns 1 */
	assert(autls_acl_check(t,
		(const unsigned char *)"host-1", 6) == 1);

	/* Disabled returns 0 */
	assert(autls_acl_check(t,
		(const unsigned char *)"host-2", 6) == 0);

	/* Unknown returns -1 */
	assert(autls_acl_check(t,
		(const unsigned char *)"host-3", 6) == -1);

	/* Empty identity returns -1 */
	assert(autls_acl_check(t,
		(const unsigned char *)"", 0) == -1);

	/* Prefix match does NOT succeed (length-bounded) */
	assert(autls_acl_check(t,
		(const unsigned char *)"host-1x", 7) == -1);
	assert(autls_acl_check(t,
		(const unsigned char *)"host-", 5) == -1);

	autls_acl_free(t);
}

static void test_autls_authorize_psk_identity(void)
{
	struct autls_acl_table *t = NULL;
	char path[512];
	int rc;

	printf("  autls_authorize_psk_identity (composed)...\n");

	snprintf(path, sizeof(path), "%s/acl-auth", tmpdir);
	write_file(path, "good-host enabled\nbad-host disabled\n");
	chmod(path, 0600);
	if (getuid() != 0) {
		printf("    (skipped, not root)\n");
		unlink(path);
		return;
	}
	assert(autls_acl_load(path, &t, test_log) == 0);
	unlink(path);

	/* Valid + enabled: validate passes, ACL returns 1 */
	rc = autls_validate_psk_identity(
		(const unsigned char *)"good-host", 9, test_log);
	assert(rc == 0);
	assert(autls_acl_check(t,
		(const unsigned char *)"good-host", 9) == 1);

	/* Valid + disabled: validate passes, ACL returns 0 */
	rc = autls_validate_psk_identity(
		(const unsigned char *)"bad-host", 8, test_log);
	assert(rc == 0);
	assert(autls_acl_check(t,
		(const unsigned char *)"bad-host", 8) == 0);

	/* Invalid identity: validate fails before ACL check */
	rc = autls_validate_psk_identity(
		(const unsigned char *)"bad\x00host", 8, test_log);
	assert(rc == -1);

	/* Unknown identity: validate passes, ACL returns -1 */
	rc = autls_validate_psk_identity(
		(const unsigned char *)"unknown", 7, test_log);
	assert(rc == 0);
	assert(autls_acl_check(t,
		(const unsigned char *)"unknown", 7) == -1);

	/* Catches if(rc) vs if(rc==1) bug: -1 is truthy in C */
	rc = autls_acl_check(t,
		(const unsigned char *)"unknown", 7);
	assert(rc == -1);
	assert(rc != 1);  /* Must not treat -1 as "enabled" */

	autls_acl_free(t);
}

/* Two distinct 32-byte hex keys for per-identity tests */
#define KEY_A_HEX \
	"000102030405060708090a0b0c0d0e0f" \
	"101112131415161718191a1b1c1d1e1f\n"
#define KEY_B_HEX \
	"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff" \
	"e0e1e2e3e4e5e6e7e8e9eaebecedeeef\n"
/* A third key used as a fake global PSK for fallback tests */
#define KEY_GLOBAL_HEX \
	"aabbccddeeff00112233445566778899" \
	"aabbccddeeff00112233445566778899\n"

/*
 * write_key_file - write a PSK key file with mode 0400
 *
 * Returns the full path via @path.
 */
static void write_key_file(char *path, size_t pathlen,
			   const char *name, const char *hex)
{
	snprintf(path, pathlen, "%s/%s", tmpdir, name);
	write_file(path, hex);
	chmod(path, 0400);
}

static void test_autls_acl_per_identity_keys(void)
{
	struct autls_acl_table *t = NULL;
	const struct autls_acl_entry *e;
	char path[512], kpath_a[512], kpath_b[512];
	char acl_line[1024];

	printf("  autls_acl_load (per-identity keys)...\n");

	if (getuid() != 0) {
		printf("    (skipped, not root)\n");
		return;
	}

	write_key_file(kpath_a, sizeof(kpath_a), "key-a.psk", KEY_A_HEX);
	write_key_file(kpath_b, sizeof(kpath_b), "key-b.psk", KEY_B_HEX);

	/* 1. Per-identity key loading succeeds */
	snprintf(path, sizeof(path), "%s/acl-pikey", tmpdir);
	snprintf(acl_line, sizeof(acl_line),
		"host-a enabled key=%s\nhost-b disabled key=%s\n",
		kpath_a, kpath_b);
	write_file(path, acl_line);
	chmod(path, 0600);

	assert(autls_acl_load(path, &t, test_log) == 0);
	assert(t != NULL);
	assert(t->count == 2);
	assert(t->enabled_count == 1);
	assert(t->has_per_identity_keys == 1);

	e = autls_acl_lookup(t, (const unsigned char *)"host-a", 6);
	assert(e != NULL);
	assert(e->enabled == 1);
	assert(e->psk_key != NULL);
	assert(e->psk_key_len == 32);
	assert(e->key_file != NULL);

	e = autls_acl_lookup(t, (const unsigned char *)"host-b", 6);
	assert(e != NULL);
	assert(e->enabled == 0);
	assert(e->psk_key != NULL);
	assert(e->psk_key_len == 32);

	/* Keys are distinct */
	e = autls_acl_lookup(t, (const unsigned char *)"host-a", 6);
	{
		const struct autls_acl_entry *e2 =
			autls_acl_lookup(t,
				(const unsigned char *)"host-b", 6);
		assert(memcmp(e->psk_key, e2->psk_key, 32) != 0);
	}

	/* Unknown identity returns NULL */
	assert(autls_acl_lookup(t,
		(const unsigned char *)"host-c", 6) == NULL);

	autls_acl_free(t);
	t = NULL;
	unlink(path);

	/* 2. Mixed format rejected: one with key=, one without */
	snprintf(path, sizeof(path), "%s/acl-mixed", tmpdir);
	snprintf(acl_line, sizeof(acl_line),
		"host-a enabled key=%s\nhost-b disabled\n", kpath_a);
	write_file(path, acl_line);
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == -1);
	assert(t == NULL);
	unlink(path);

	/* 3. Duplicate key paths rejected */
	snprintf(path, sizeof(path), "%s/acl-dupkey", tmpdir);
	snprintf(acl_line, sizeof(acl_line),
		"host-a enabled key=%s\nhost-b disabled key=%s\n",
		kpath_a, kpath_a);
	write_file(path, acl_line);
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == -1);
	assert(t == NULL);
	unlink(path);

	/* 4. Missing key file rejected */
	snprintf(path, sizeof(path), "%s/acl-nokey", tmpdir);
	write_file(path, "host-a enabled key=/nonexistent/key.psk\n");
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == -1);
	assert(t == NULL);
	unlink(path);

	/* 5. Partial-load cleanup: 2nd entry has bad key */
	snprintf(path, sizeof(path), "%s/acl-partial", tmpdir);
	snprintf(acl_line, sizeof(acl_line),
		"host-a enabled key=%s\n"
		"host-b disabled key=/nonexistent/key.psk\n",
		kpath_a);
	write_file(path, acl_line);
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == -1);
	assert(t == NULL);
	unlink(path);

	/* 6. Multiple enabled with per-identity keys accepted */
	snprintf(path, sizeof(path), "%s/acl-multi", tmpdir);
	snprintf(acl_line, sizeof(acl_line),
		"host-a enabled key=%s\nhost-b enabled key=%s\n",
		kpath_a, kpath_b);
	write_file(path, acl_line);
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == 0);
	assert(t->enabled_count == 2);
	assert(t->has_per_identity_keys == 1);
	autls_acl_free(t);
	t = NULL;
	unlink(path);

	/* 7. Backward compat: no key= columns */
	snprintf(path, sizeof(path), "%s/acl-compat", tmpdir);
	write_file(path, "host-a enabled notes here\n"
			 "host-b disabled retired\n");
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == 0);
	assert(t->has_per_identity_keys == 0);
	e = autls_acl_lookup(t, (const unsigned char *)"host-a", 6);
	assert(e != NULL);
	assert(e->psk_key == NULL);
	assert(e->key_file == NULL);
	autls_acl_free(t);
	t = NULL;
	unlink(path);

	/* 8. Notes starting with key= but no / are treated as notes */
	snprintf(path, sizeof(path), "%s/acl-notes", tmpdir);
	write_file(path, "host-a enabled key=rotation-needed\n"
			 "host-b disabled key=decommissioned\n");
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == 0);
	assert(t->has_per_identity_keys == 0);
	e = autls_acl_lookup(t, (const unsigned char *)"host-a", 6);
	assert(e != NULL);
	assert(e->psk_key == NULL);
	autls_acl_free(t);
	t = NULL;
	unlink(path);

	/* 9. Trailing tokens after key= rejected */
	snprintf(path, sizeof(path), "%s/acl-trailing", tmpdir);
	snprintf(acl_line, sizeof(acl_line),
		"host-a enabled key=%s extra-notes\n", kpath_a);
	write_file(path, acl_line);
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == -1);
	assert(t == NULL);
	unlink(path);

	unlink(kpath_a);
	unlink(kpath_b);
}

/*
 * TLS binder cross-identity regression test.
 *
 * Uses in-memory BIO pairs to exercise actual TLS 1.3 PSK handshakes
 * with per-identity keys, verifying that cross-pairing an identity
 * with the wrong key fails at the cryptographic (binder) level.
 *
 * This is the essential regression test from SPECS/fr-028-001:
 * "the disabled identity's old key paired with the active label fails
 * binder verification -- a label-only unit test will continue to pass
 * while the vulnerability remains."
 */

/* State for the BIO pair PSK test */
static struct autls_acl_table *bio_test_acl = NULL;
static const unsigned char *bio_test_client_key = NULL;
static size_t bio_test_client_key_len = 0;
static const char *bio_test_client_identity = NULL;
static SSL_SESSION *bio_test_shared_session = NULL;

/*
 * build_psk_session - create an SSL_SESSION for external PSK
 * @ssl: SSL connection (for cipher lookup)
 * @key: PSK key bytes
 * @key_len: PSK key length
 *
 * Returns a new SSL_SESSION, or NULL on error.
 */
/*
 * find_first_tls13_cipher - return the first TLS 1.3 cipher
 * @ssl: SSL connection for cipher list
 *
 * Returns the first configured TLS 1.3 cipher.  Unlike
 * autls_find_tls13_cipher which selects by hash, this returns
 * whatever OpenSSL defaults to, ensuring client and server agree.
 */
static const SSL_CIPHER *find_first_tls13_cipher(SSL *ssl)
{
	STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
	int i;

	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, i);
		const char *ver = SSL_CIPHER_get_version(c);

		if (ver && strcmp(ver, "TLSv1.3") == 0)
			return c;
	}
	return NULL;
}

static SSL_SESSION *build_psk_session(SSL *ssl, const unsigned char *key,
				      size_t key_len)
{
	const SSL_CIPHER *cipher;
	SSL_SESSION *s;

	cipher = find_first_tls13_cipher(ssl);
	if (cipher == NULL)
		return NULL;

	s = SSL_SESSION_new();
	if (s == NULL)
		return NULL;

	if (!SSL_SESSION_set1_master_key(s, key, key_len) ||
	    !SSL_SESSION_set_cipher(s, cipher) ||
	    !SSL_SESSION_set_protocol_version(s, TLS1_3_VERSION)) {
		SSL_SESSION_free(s);
		return NULL;
	}
	return s;
}

/*
 * test_server_psk_cb - server PSK callback using per-identity keys
 *
 * Mirrors the production tls_psk_find_session_cb key selection logic:
 * look up the identity in the ACL, select the per-identity key.
 */
static int test_server_psk_cb(SSL *ssl, const unsigned char *identity,
			      size_t identity_len, SSL_SESSION **sess)
{
	const struct autls_acl_entry *entry;

	if (bio_test_acl == NULL)
		return 0;

	entry = autls_acl_lookup(bio_test_acl, identity, identity_len);
	if (entry == NULL || !entry->enabled)
		return 0;
	if (entry->psk_key == NULL || entry->psk_key_len == 0)
		return 0;

	{
		const SSL_CIPHER *cipher = find_first_tls13_cipher(ssl);
		SSL_SESSION *s;

		if (cipher == NULL)
			return 0;
		s = SSL_SESSION_new();
		if (s == NULL)
			return 0;
		if (!SSL_SESSION_set1_master_key(s, entry->psk_key,
						 entry->psk_key_len) ||
		    !SSL_SESSION_set_cipher(s, cipher) ||
		    !SSL_SESSION_set_protocol_version(s,
						     TLS1_3_VERSION)) {
			SSL_SESSION_free(s);
			return 0;
		}
		*sess = s;
	}
	return 1;
}

/*
 * test_client_psk_cb - client PSK callback presenting a specific
 * identity and key pair.  Uses a shared pre-built session.
 */
static int test_client_psk_cb(SSL *ssl, const EVP_MD *md,
			      const unsigned char **id, size_t *idlen,
			      SSL_SESSION **sess)
{
	(void)ssl;
	(void)md;

	if (bio_test_client_key == NULL || bio_test_client_identity == NULL)
		return 0;

	if (bio_test_shared_session == NULL)
		return 0;

	*id = (const unsigned char *)bio_test_client_identity;
	*idlen = strlen(bio_test_client_identity);
	SSL_SESSION_up_ref(bio_test_shared_session);
	*sess = bio_test_shared_session;
	return 1;
}

/*
 * try_bio_pair_handshake - attempt a TLS 1.3 PSK handshake using shared
 * memory BIOs (the same pattern OpenSSL's own test suite uses)
 *
 * Returns 1 if PSK handshake succeeds, 0 if it fails.
 */
static int try_bio_pair_handshake(void)
{
	SSL_CTX *server_ctx = NULL, *client_ctx = NULL;
	SSL *server_ssl = NULL, *client_ssl = NULL;
	BIO *s_to_c = NULL, *c_to_s = NULL;
	int result = 0;
	int i;

	server_ctx = SSL_CTX_new(TLS_server_method());
	client_ctx = SSL_CTX_new(TLS_client_method());
	if (!server_ctx || !client_ctx)
		goto out;

	SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION);
	SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_early_data(server_ctx, 0);
	SSL_CTX_set_max_early_data(client_ctx, 0);
	SSL_CTX_set_num_tickets(server_ctx, 0);

	/*
	 * No certificate.  Use SSL_OP_ALLOW_NO_DHE_KEX for psk_ke mode
	 * (PSK without DHE key exchange).  Without a certificate, the
	 * handshake can only succeed via PSK -- there is no cert fallback.
	 */
	SSL_CTX_set_options(server_ctx, SSL_OP_ALLOW_NO_DHE_KEX);
	SSL_CTX_set_options(client_ctx, SSL_OP_ALLOW_NO_DHE_KEX);

	SSL_CTX_set_psk_find_session_callback(server_ctx,
					      test_server_psk_cb);
	SSL_CTX_set_psk_use_session_callback(client_ctx,
					     test_client_psk_cb);

	server_ssl = SSL_new(server_ctx);
	client_ssl = SSL_new(client_ctx);
	if (!server_ssl || !client_ssl)
		goto out;

	/* Shared memory BIOs (same pattern as OpenSSL test suite).
	 * s_to_c: server writes, client reads
	 * c_to_s: client writes, server reads */
	s_to_c = BIO_new(BIO_s_mem());
	c_to_s = BIO_new(BIO_s_mem());
	if (!s_to_c || !c_to_s)
		goto out;

	/* Both SSL objects share these BIOs; bump refcounts */
	BIO_up_ref(s_to_c);
	BIO_up_ref(c_to_s);

	SSL_set_bio(server_ssl, c_to_s, s_to_c);
	SSL_set_bio(client_ssl, s_to_c, c_to_s);
	s_to_c = c_to_s = NULL; /* owned by SSL now */

	SSL_set_accept_state(server_ssl);
	SSL_set_connect_state(client_ssl);

	/* Build the shared PSK session using the client's SSL for
	 * cipher lookup.  The client callback will return this session
	 * directly; the server callback builds its own from the ACL. */
	if (bio_test_client_key && bio_test_client_key_len > 0) {
		bio_test_shared_session = build_psk_session(
			client_ssl, bio_test_client_key,
			bio_test_client_key_len);
		if (bio_test_shared_session == NULL)
			goto out;
	}

	/* Drive the handshake: alternate client and server */
	for (i = 0; i < 100; i++) {
		int client_ret, server_ret;
		int client_err, server_err;

		client_ret = SSL_do_handshake(client_ssl);
		client_err = SSL_get_error(client_ssl, client_ret);

		server_ret = SSL_do_handshake(server_ssl);
		server_err = SSL_get_error(server_ssl, server_ret);

		if (client_ret == 1 && server_ret == 1) {
			result = 1;
			break;
		}

		if (client_err != SSL_ERROR_WANT_READ &&
		    client_err != SSL_ERROR_WANT_WRITE &&
		    client_ret != 1)
			break;
		if (server_err != SSL_ERROR_WANT_READ &&
		    server_err != SSL_ERROR_WANT_WRITE &&
		    server_ret != 1)
			break;
	}

out:
	SSL_SESSION_free(bio_test_shared_session);
	bio_test_shared_session = NULL;
	SSL_free(server_ssl);
	SSL_free(client_ssl);
	SSL_CTX_free(server_ctx);
	SSL_CTX_free(client_ctx);
	BIO_free(s_to_c);
	BIO_free(c_to_s);
	return result;
}

static void test_tls_binder_cross_identity(void)
{
	struct autls_acl_table *t = NULL;
	const struct autls_acl_entry *entry_a, *entry_b;
	char path[512], kpath_a[512], kpath_b[512], kpath_g[512];
	char acl_line[1024];
	int ok;

	printf("  TLS binder cross-identity regression...\n");

	if (getuid() != 0) {
		printf("    (skipped, not root)\n");
		return;
	}

	write_key_file(kpath_a, sizeof(kpath_a), "bio-key-a.psk",
		       KEY_A_HEX);
	write_key_file(kpath_b, sizeof(kpath_b), "bio-key-b.psk",
		       KEY_B_HEX);
	write_key_file(kpath_g, sizeof(kpath_g), "bio-key-g.psk",
		       KEY_GLOBAL_HEX);

	/* Load ACL with per-identity keys */
	snprintf(path, sizeof(path), "%s/acl-bio", tmpdir);
	snprintf(acl_line, sizeof(acl_line),
		"host-a enabled key=%s\nhost-b disabled key=%s\n",
		kpath_a, kpath_b);
	write_file(path, acl_line);
	chmod(path, 0600);
	assert(autls_acl_load(path, &t, test_log) == 0);
	assert(t->has_per_identity_keys == 1);

	entry_a = autls_acl_lookup(t,
				   (const unsigned char *)"host-a", 6);
	entry_b = autls_acl_lookup(t,
				   (const unsigned char *)"host-b", 6);
	assert(entry_a && entry_b);

	bio_test_acl = t;

	/* Test 1: Correct pairing succeeds --
	 * identity host-a with key-A should authenticate */
	bio_test_client_identity = "host-a";
	bio_test_client_key = entry_a->psk_key;
	bio_test_client_key_len = entry_a->psk_key_len;
	ok = try_bio_pair_handshake();
	assert(ok == 1);
	printf("    1. correct identity+key: PASS (authenticated)\n");

	/* Test 2: Cross-identity pairing fails --
	 * identity host-a with key-B should fail binder.
	 * THIS IS THE ESSENTIAL REGRESSION TEST. */
	bio_test_client_identity = "host-a";
	bio_test_client_key = entry_b->psk_key;
	bio_test_client_key_len = entry_b->psk_key_len;
	ok = try_bio_pair_handshake();
	assert(ok == 0);
	printf("    2. cross-identity key: PASS (rejected)\n");

	/* Test 3: Disabled identity with own key rejected --
	 * identity host-b (disabled) with key-B should be
	 * rejected by ACL before binder verification */
	bio_test_client_identity = "host-b";
	bio_test_client_key = entry_b->psk_key;
	bio_test_client_key_len = entry_b->psk_key_len;
	ok = try_bio_pair_handshake();
	assert(ok == 0);
	printf("    3. disabled identity+own key: PASS (rejected)\n");

	/* Test 4: Unknown identity rejected */
	bio_test_client_identity = "host-unknown";
	bio_test_client_key = entry_a->psk_key;
	bio_test_client_key_len = entry_a->psk_key_len;
	ok = try_bio_pair_handshake();
	assert(ok == 0);
	printf("    4. unknown identity: PASS (rejected)\n");

	/* Test 5: Global key does not match per-identity entry --
	 * Load a "global" key different from both per-identity keys.
	 * identity host-a with global key should fail binder. */
	{
		unsigned char *gkey = NULL;
		size_t gkey_len = 0;

		assert(autls_load_psk(kpath_g, &gkey, &gkey_len,
				      test_log) == 0);
		bio_test_client_identity = "host-a";
		bio_test_client_key = gkey;
		bio_test_client_key_len = gkey_len;
		ok = try_bio_pair_handshake();
		assert(ok == 0);
		printf("    5. global key vs per-identity: "
		       "PASS (rejected)\n");
		OPENSSL_cleanse(gkey, gkey_len);
		OPENSSL_free(gkey);
	}

	bio_test_acl = NULL;
	bio_test_client_key = NULL;
	bio_test_client_identity = NULL;
	autls_acl_free(t);
	unlink(path);
	unlink(kpath_a);
	unlink(kpath_b);
	unlink(kpath_g);
}

int main(void)
{
	char template[] = "/tmp/test-tls-XXXXXX";

	if (mkdtemp(template) == NULL) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(tmpdir, sizeof(tmpdir), "%s", template);
	atexit(cleanup);

	printf("TLS helper tests:\n");
	test_autls_is_pqc_group();
	test_autls_remaining_ms();
	test_autls_ssl_connect_deadline();
	test_autls_load_psk();
	test_autls_load_psk_validation();
	test_autls_load_secret_fifo();
	test_autls_acl_fifo();
	test_autls_validate_psk_identity();
	test_autls_profile_ciphers();
	test_autls_profile_groups();
	test_autls_crypto_audit_format();
	test_autls_acl_load();
	test_autls_acl_check();
	test_autls_authorize_psk_identity();
	test_autls_acl_per_identity_keys();
	test_tls_binder_cross_identity();
	printf("All TLS helper tests passed.\n");
	return 0;
}

#else /* !HAVE_TLS */

int main(void)
{
	printf("TLS not enabled, skipping tests.\n");
	return 0;
}

#endif
