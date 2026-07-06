/*
 * auditd_config_alloc_test.c - allocation failure tests for auditd parser
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_audit_msg(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

char *test_audit_strsplit(char *s)
{
	(void)s;
	return NULL;
}

long test_time_string_to_seconds(const char *time_string,
				 const char *subsystem, int line)
{
	(void)time_string;
	(void)subsystem;
	(void)line;
	return 0;
}

static long alloc_count;
static long fail_at;

static void reset_allocs(long fail)
{
	alloc_count = 0;
	fail_at = fail;
}

static int should_fail(void)
{
	alloc_count++;
	return fail_at == alloc_count;
}

static void *test_malloc(size_t size)
{
	if (should_fail())
		return NULL;
	return malloc(size);
}

static char *test_strdup(const char *s)
{
	char *copy;
	size_t len;

	if (should_fail())
		return NULL;
	len = strlen(s) + 1;
	copy = malloc(len);
	if (copy)
		memcpy(copy, s, len);
	return copy;
}

static int test_asprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	if (should_fail()) {
		*strp = NULL;
		return -1;
	}

	va_start(ap, fmt);
	rc = vasprintf(strp, fmt, ap);
	va_end(ap);
	return rc;
}

#define audit_msg test_audit_msg
#define audit_strsplit test_audit_strsplit
#define time_string_to_seconds test_time_string_to_seconds
#define malloc test_malloc
#define strdup test_strdup
#define asprintf test_asprintf
#include "../auditd-config.c"
#undef asprintf
#undef strdup
#undef malloc
#undef time_string_to_seconds
#undef audit_strsplit
#undef audit_msg

static void test_name_preserves_old_value(void)
{
	struct daemon_conf config;
	struct nv_pair nv = { "name", "new-node", NULL };

	memset(&config, 0, sizeof(config));
	config.node_name = strdup("old-node");
	assert(config.node_name != NULL);

	reset_allocs(1);
	assert(name_parser(&nv, 1, &config) == 1);
	assert(strcmp(config.node_name, "old-node") == 0);

	free((void *)config.node_name);
}

static void test_log_file_preserves_old_value(void)
{
	struct daemon_conf config;
	struct nv_pair nv = { "log_file", "/tmp/audit-test.log", NULL };

	memset(&config, 0, sizeof(config));
	config.log_file = strdup("/tmp/old-audit.log");
	assert(config.log_file != NULL);
	log_test = TEST_SEARCH;

	reset_allocs(2);
	assert(log_file_parser(&nv, 1, &config) == 1);
	assert(strcmp(config.log_file, "/tmp/old-audit.log") == 0);

	free((void *)config.log_file);
}

static void test_set_config_dir_preserves_old_value(void)
{
	reset_allocs(-1);
	assert(set_config_dir("/tmp/audit-old") == 0);
	assert(strcmp(config_dir, "/tmp/audit-old") == 0);
	assert(strcmp(config_file, "/tmp/audit-old/auditd.conf") == 0);

	reset_allocs(1);
	assert(set_config_dir("/tmp/audit-new") == 1);
	assert(strcmp(config_dir, "/tmp/audit-old") == 0);
	assert(strcmp(config_file, "/tmp/audit-old/auditd.conf") == 0);

	reset_allocs(-1);
	free((void *)config_dir);
	free(config_file);
	config_dir = NULL;
	config_file = NULL;
}

#ifdef HAVE_TLS
/*
 * clear_sane_config - reset config and satisfy non-TLS sanity defaults
 * @config: daemon configuration to initialize
 *
 * Returns: None.
 */
static void clear_sane_config(struct daemon_conf *config)
{
	clear_config(config);
	config->space_left = 1;
	config->admin_space_left = 0;
}

static void test_tls_auth_parser(void)
{
	struct daemon_conf config;
	struct nv_pair nv;

	memset(&config, 0, sizeof(config));
	reset_allocs(-1);

	/* Valid value: psk */
	nv = (struct nv_pair){ "tls_auth", "psk", NULL };
	assert(tls_auth_parser(&nv, 1, &config) == 0);
	assert(config.tls_auth == TLS_AUTH_PSK);

	/* Invalid value rejected */
	nv = (struct nv_pair){ "tls_auth", "certificate", NULL };
	assert(tls_auth_parser(&nv, 1, &config) == 1);
}

static void test_tls_crypto_profile_parser(void)
{
	struct daemon_conf config;
	struct nv_pair nv;

	memset(&config, 0, sizeof(config));
	reset_allocs(-1);

	nv = (struct nv_pair){ "tls_crypto_profile", "compatible", NULL };
	assert(tls_crypto_profile_parser(&nv, 1, &config) == 0);
	assert(config.tls_crypto_profile == TLS_PROFILE_COMPATIBLE);

	nv = (struct nv_pair){ "tls_crypto_profile", "system", NULL };
	assert(tls_crypto_profile_parser(&nv, 1, &config) == 0);
	assert(config.tls_crypto_profile == TLS_PROFILE_SYSTEM);

	nv = (struct nv_pair){ "tls_crypto_profile", "pqc", NULL };
	assert(tls_crypto_profile_parser(&nv, 1, &config) == 0);
	assert(config.tls_crypto_profile == TLS_PROFILE_PQC);

	/* Invalid value rejected */
	nv = (struct nv_pair){ "tls_crypto_profile", "quantum", NULL };
	assert(tls_crypto_profile_parser(&nv, 1, &config) == 1);
}

static void test_tls_require_pqc_compat_alias(void)
{
	struct daemon_conf config;
	struct nv_pair nv;

	memset(&config, 0, sizeof(config));
	reset_allocs(-1);

	/* yes sets both tls_require_pqc and tls_crypto_profile */
	config.tls_crypto_profile = TLS_PROFILE_COMPATIBLE;
	nv = (struct nv_pair){ "tls_require_pqc", "yes", NULL };
	assert(tls_require_pqc_parser(&nv, 1, &config) == 0);
	assert(config.tls_require_pqc == 1);
	assert(config.tls_crypto_profile == TLS_PROFILE_PQC);

	/* no is a no-op for tls_crypto_profile */
	config.tls_crypto_profile = TLS_PROFILE_PQC;
	nv = (struct nv_pair){ "tls_require_pqc", "no", NULL };
	assert(tls_require_pqc_parser(&nv, 1, &config) == 0);
	assert(config.tls_require_pqc == 0);
	assert(config.tls_crypto_profile == TLS_PROFILE_PQC);

	/* Explicit profile after yes wins (last writer) */
	config.tls_crypto_profile = TLS_PROFILE_COMPATIBLE;
	config.tls_require_pqc = 0;
	nv = (struct nv_pair){ "tls_require_pqc", "yes", NULL };
	assert(tls_require_pqc_parser(&nv, 1, &config) == 0);
	assert(config.tls_crypto_profile == TLS_PROFILE_PQC);
	nv = (struct nv_pair){ "tls_crypto_profile", "compatible", NULL };
	assert(tls_crypto_profile_parser(&nv, 1, &config) == 0);
	assert(config.tls_crypto_profile == TLS_PROFILE_COMPATIBLE);
}
static void test_sanity_check_tls(void)
{
	struct daemon_conf config;

	printf("  sanity_check TLS constraints...\n");

	/* cert/key pairing: cert without key must fail */
	clear_sane_config(&config);
	config.transport = T_TLS;
	config.tls_cert_file = "/cert";
	config.tls_key_file = NULL;
	assert(sanity_check(&config) == 1);

	/* PSK + cert mutual exclusion */
	clear_sane_config(&config);
	config.transport = T_TLS;
	config.tls_psk_file = "/psk";
	config.tls_cert_file = "/cert";
	config.tls_key_file = "/key";
	config.tls_psk_identity = "id";
	config.tls_auth = TLS_AUTH_PSK;
	assert(sanity_check(&config) == 1);

	/* tls_auth=psk requires tls_psk_file */
	clear_sane_config(&config);
	config.transport = T_TLS;
	config.tls_auth = TLS_AUTH_PSK;
	config.tls_psk_file = NULL;
	config.tls_cert_file = "/cert";
	config.tls_key_file = "/key";
	assert(sanity_check(&config) == 1);

	/* No credentials at all */
	clear_sane_config(&config);
	config.transport = T_TLS;
	assert(sanity_check(&config) == 1);

	/* PSK requires identity or ACL */
	clear_sane_config(&config);
	config.transport = T_TLS;
	config.tls_psk_file = "/psk";
	config.tls_auth = TLS_AUTH_PSK;
	config.tls_psk_identity = NULL;
	config.tls_allowed_clients = NULL;
	assert(sanity_check(&config) == 1);

	/* tls_require_pqc conflicts with non-PQC profile */
	clear_sane_config(&config);
	config.transport = T_TLS;
	config.tls_psk_file = "/psk";
	config.tls_psk_identity = "id";
	config.tls_auth = TLS_AUTH_PSK;
	config.tls_require_pqc = 1;
	config.tls_crypto_profile = TLS_PROFILE_COMPATIBLE;
	assert(sanity_check(&config) == 1);

	/* Valid minimal PSK config should pass */
	clear_sane_config(&config);
	config.transport = T_TLS;
	config.tls_psk_file = "/psk";
	config.tls_psk_identity = "id";
	config.tls_auth = TLS_AUTH_PSK;
	assert(sanity_check(&config) == 0);
}
#endif /* HAVE_TLS */

int main(void)
{
	reset_allocs(-1);
	test_name_preserves_old_value();
	test_log_file_preserves_old_value();
	test_set_config_dir_preserves_old_value();
#ifdef HAVE_TLS
	test_tls_auth_parser();
	test_tls_crypto_profile_parser();
	test_tls_require_pqc_compat_alias();
	test_sanity_check_tls();
#endif
	return 0;
}
