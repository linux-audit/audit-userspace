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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include "autls.h"

#ifdef HAVE_TLS

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

static void test_autls_validate_key_file(void)
{
	char path[512];

	printf("  autls_validate_key_file...\n");

	/* Nonexistent file */
	snprintf(path, sizeof(path), "%s/nonexistent", tmpdir);
	assert(autls_validate_key_file(path, test_log) == -1);

	/* Directory */
	assert(autls_validate_key_file(tmpdir, test_log) == -1);

	/* Regular file, mode 0644 */
	snprintf(path, sizeof(path), "%s/bad-mode", tmpdir);
	write_file(path, "data");
	chmod(path, 0644);
	assert(autls_validate_key_file(path, test_log) == -1);
	unlink(path);

	/* Regular file, mode 0600 -- only exactly 0400 passes */
	snprintf(path, sizeof(path), "%s/mode-0600", tmpdir);
	write_file(path, "data");
	chmod(path, 0600);
	assert(autls_validate_key_file(path, test_log) == -1);
	unlink(path);

	/* Regular file, mode 0400, owned by current user */
	snprintf(path, sizeof(path), "%s/good-mode", tmpdir);
	write_file(path, "data");
	chmod(path, 0400);
	if (getuid() == 0) {
		/* Running as root -- file is root-owned, should pass */
		assert(autls_validate_key_file(path, test_log) == 0);
	} else {
		/* Not root -- uid check fails */
		assert(autls_validate_key_file(path, test_log) == -1);
	}
	unlink(path);

	/* Symlink to a valid file -- lstat sees the symlink itself */
	if (getuid() == 0) {
		char target[512], link_path[512];

		snprintf(target, sizeof(target),
			"%s/symlink-target", tmpdir);
		snprintf(link_path, sizeof(link_path),
			"%s/symlink-link", tmpdir);
		write_file(target, "data");
		chmod(target, 0400);
		symlink(target, link_path);
		/* lstat does not follow symlinks -- rejected */
		assert(autls_validate_key_file(link_path,
			test_log) == -1);
		unlink(link_path);
		unlink(target);
	}
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
	test_autls_validate_key_file();
	test_autls_load_psk();
	test_autls_load_psk_validation();
	test_autls_validate_psk_identity();
	test_autls_profile_ciphers();
	test_autls_profile_groups();
	test_autls_acl_load();
	test_autls_acl_check();
	test_autls_authorize_psk_identity();
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
