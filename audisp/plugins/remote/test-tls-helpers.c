/* test-tls-helpers.c -- unit tests for TLS helper functions in common.h
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
#include "common.h"

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

static void test_is_pqc_group(void)
{
	printf("  is_pqc_group...\n");

	/* Classical groups -- all return 0 */
	assert(is_pqc_group(NULL) == 0);
	assert(is_pqc_group("") == 0);
	assert(is_pqc_group("X25519") == 0);
	assert(is_pqc_group("P-256") == 0);
	assert(is_pqc_group("P-384") == 0);
	assert(is_pqc_group("P-521") == 0);
	assert(is_pqc_group("X448") == 0);
	assert(is_pqc_group("ffdhe2048") == 0);
	assert(is_pqc_group("brainpoolP256r1tls13") == 0);

	/* Case sensitivity and near-misses -- return 0 */
	assert(is_pqc_group("x25519mlkem768") == 0);
	assert(is_pqc_group("MLKE") == 0);

	/* PQC groups -- all return 1 */
	assert(is_pqc_group("X25519MLKEM768") == 1);
	assert(is_pqc_group("SecP256r1MLKEM768") == 1);
	assert(is_pqc_group("SecP384r1MLKEM1024") == 1);
	assert(is_pqc_group("MLKEM768") == 1);
	assert(is_pqc_group("MLKEM1024") == 1);
	assert(is_pqc_group("X448MLKEM1024") == 1);
}

static void test_tls_remaining_ms(void)
{
	struct timespec deadline;
	int r;

	printf("  tls_remaining_ms...\n");

	/* 1 second in the future */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += 1;
	r = tls_remaining_ms(&deadline);
	assert(r > 900 && r <= 1000);

	/* 10 seconds in the past */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec -= 10;
	r = tls_remaining_ms(&deadline);
	assert(r == 0);

	/* Epoch-like value (always in the past) */
	deadline.tv_sec = 0;
	deadline.tv_nsec = 0;
	r = tls_remaining_ms(&deadline);
	assert(r == 0);

	/* Large deadline -- tests INT_MAX clamp (~25 days) */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += 2200000;
	r = tls_remaining_ms(&deadline);
	assert(r == INT_MAX);

	/* Nanosecond boundary */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += 1;
	deadline.tv_nsec = 999999999;
	r = tls_remaining_ms(&deadline);
	assert(r > 900 && r <= 2000);
}

static void test_tls_validate_key_file(void)
{
	char path[512];

	printf("  tls_validate_key_file...\n");

	/* Nonexistent file */
	snprintf(path, sizeof(path), "%s/nonexistent", tmpdir);
	assert(tls_validate_key_file(path, test_log) == -1);

	/* Directory */
	assert(tls_validate_key_file(tmpdir, test_log) == -1);

	/* Regular file, mode 0644 */
	snprintf(path, sizeof(path), "%s/bad-mode", tmpdir);
	write_file(path, "data");
	chmod(path, 0644);
	assert(tls_validate_key_file(path, test_log) == -1);
	unlink(path);

	/* Regular file, mode 0600 -- only exactly 0400 passes */
	snprintf(path, sizeof(path), "%s/mode-0600", tmpdir);
	write_file(path, "data");
	chmod(path, 0600);
	assert(tls_validate_key_file(path, test_log) == -1);
	unlink(path);

	/* Regular file, mode 0400, owned by current user */
	snprintf(path, sizeof(path), "%s/good-mode", tmpdir);
	write_file(path, "data");
	chmod(path, 0400);
	if (getuid() == 0) {
		/* Running as root -- file is root-owned, should pass */
		assert(tls_validate_key_file(path, test_log) == 0);
	} else {
		/* Not root -- uid check fails */
		assert(tls_validate_key_file(path, test_log) == -1);
	}
	unlink(path);

	/* Symlink to a valid file -- stat follows symlinks */
	if (getuid() == 0) {
		char target[512], link[512];

		snprintf(target, sizeof(target), "%s/symlink-target", tmpdir);
		snprintf(link, sizeof(link), "%s/symlink-link", tmpdir);
		write_file(target, "data");
		chmod(target, 0400);
		symlink(target, link);
		/* stat follows the symlink -- target is root-owned, 0400 */
		assert(tls_validate_key_file(link, test_log) == 0);
		unlink(link);
		unlink(target);
	}
}

static void test_tls_load_psk(void)
{
	char path[512];
	unsigned char *key = NULL;
	size_t key_len = 0;
	unsigned char expected[32];
	int i;

	printf("  tls_load_psk...\n");

	/* Nonexistent file */
	snprintf(path, sizeof(path), "%s/nonexistent-psk", tmpdir);
	assert(tls_load_psk(path, &key, &key_len, test_log) == -1);

	/* Empty file */
	snprintf(path, sizeof(path), "%s/empty-psk", tmpdir);
	write_file(path, "");
	assert(tls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Whitespace-only file */
	snprintf(path, sizeof(path), "%s/ws-psk", tmpdir);
	write_file(path, "\n");
	assert(tls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Odd-length hex */
	snprintf(path, sizeof(path), "%s/odd-psk", tmpdir);
	write_file(path, "abc\n");
	assert(tls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Short key (8 bytes, below 32-byte minimum) */
	snprintf(path, sizeof(path), "%s/short-psk", tmpdir);
	write_file(path, "0011223344556677\n");
	assert(tls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Invalid hex characters */
	snprintf(path, sizeof(path), "%s/badhex-psk", tmpdir);
	write_file(path,
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
		"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n");
	assert(tls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Colon-separated hex with trailing incomplete byte --
	 * even length (94 chars), passes len%2 but fails in
	 * OPENSSL_hexstr2buf due to malformed input */
	snprintf(path, sizeof(path), "%s/colon-psk", tmpdir);
	write_file(path,
		"AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
		":AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:9\n");
	assert(tls_load_psk(path, &key, &key_len, test_log) == -1);
	unlink(path);

	/* Valid 64-char hex key (32 bytes) */
	snprintf(path, sizeof(path), "%s/valid-psk", tmpdir);
	write_file(path,
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f\n");
	assert(tls_load_psk(path, &key, &key_len, test_log) == 0);
	assert(key != NULL);
	assert(key_len == 32);
	for (i = 0; i < 32; i++)
		expected[i] = (unsigned char)i;
	assert(memcmp(key, expected, 32) == 0);
	OPENSSL_cleanse(key, key_len);
	OPENSSL_free(key);
	key = NULL;
	unlink(path);

	/* Valid uppercase hex key */
	snprintf(path, sizeof(path), "%s/upper-psk", tmpdir);
	write_file(path,
		"AABBCCDDAABBCCDDAABBCCDDAABBCCDD"
		"AABBCCDDAABBCCDDAABBCCDDAABBCCDD\n");
	assert(tls_load_psk(path, &key, &key_len, test_log) == 0);
	assert(key != NULL);
	assert(key_len == 32);
	OPENSSL_cleanse(key, key_len);
	OPENSSL_free(key);
	key = NULL;
	unlink(path);
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
	test_is_pqc_group();
	test_tls_remaining_ms();
	test_tls_validate_key_file();
	test_tls_load_psk();
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
