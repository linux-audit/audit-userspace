/*
 * auditctl_key_test.c - auditctl rule-key parsing tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libaudit.h"

int list_requested;
int interpret;
char key[AUDIT_MAX_KEY_LEN+1];

#include "../auditctl-listing.c"

/*
 * make_rule - make a rule with one string field followed by key bytes
 * @keys: separator-delimited keys without a trailing NUL
 * @keylen: number of bytes in @keys
 *
 * Returns: An allocated rule, or NULL if allocation fails.
 */
static struct audit_rule_data *make_rule(const char *keys, size_t keylen)
{
	static const char exe[] = "/usr/bin/test";
	struct audit_rule_data *rule;
	size_t exe_len = sizeof(exe) - 1;

	rule = calloc(1, sizeof(*rule) + exe_len + keylen);
	if (rule == NULL)
		return NULL;

	rule->field_count = 2;
	rule->fields[0] = AUDIT_EXE;
	rule->values[0] = exe_len;
	rule->fields[1] = AUDIT_FILTERKEY;
	rule->values[1] = keylen;
	rule->buflen = exe_len + keylen;
	memcpy(rule->buf, exe, exe_len);
	memcpy(rule->buf + exe_len, keys, keylen);
	return rule;
}

/*
 * capture_keys - run key printing with stdout directed to a pipe
 * @keys: separator-delimited keys without a trailing NUL
 * @keylen: number of bytes in @keys
 * @watch: non-zero for watch-rule output
 * @output: caller-provided output buffer
 * @output_len: size of @output
 *
 * Returns: None.
 */
static void capture_keys(const char *keys, size_t keylen, int watch,
			 char *output, size_t output_len)
{
	int pipefd[2];
	int stdout_fd;
	ssize_t len;

	assert(pipe(pipefd) == 0);
	stdout_fd = dup(STDOUT_FILENO);
	assert(stdout_fd >= 0);
	fflush(stdout);
	assert(dup2(pipefd[1], STDOUT_FILENO) >= 0);
	close(pipefd[1]);

	print_rule_keys(keys, keylen, watch);
	fflush(stdout);
	assert(dup2(stdout_fd, STDOUT_FILENO) >= 0);
	close(stdout_fd);

	len = read(pipefd[0], output, output_len - 1);
	assert(len >= 0);
	output[len] = 0;
	close(pipefd[0]);
}

/*
 * test_key_match - retain matching across a preceding string field
 *
 * Returns: None.
 */
static void test_key_match(void)
{
	const char keys[] = {
		AUDIT_KEY_SEPARATOR, 'f', 'i', 'r', 's', 't',
		AUDIT_KEY_SEPARATOR, AUDIT_KEY_SEPARATOR,
		's', 'e', 'c', 'o', 'n', 'd', AUDIT_KEY_SEPARATOR
	};
	struct audit_rule_data *rule = make_rule(keys, sizeof(keys));

	assert(rule != NULL);
	strcpy(key, "second");
	assert(key_match(rule) == 1);
	strcpy(key, "eco");
	assert(key_match(rule) == 1);
	strcpy(key, "missing");
	assert(key_match(rule) == 0);
	free(rule);
}

/*
 * test_key_output - preserve delimiter handling without a temporary string
 *
 * Returns: None.
 */
static void test_key_output(void)
{
	const char keys[] = {
		AUDIT_KEY_SEPARATOR, 'f', 'i', 'r', 's', 't',
		AUDIT_KEY_SEPARATOR, AUDIT_KEY_SEPARATOR,
		's', 'e', 'c', 'o', 'n', 'd', AUDIT_KEY_SEPARATOR
	};
	char output[64];

	capture_keys(keys, sizeof(keys), 0, output, sizeof(output));
	assert(strcmp(output, " -F key=first -F key=second") == 0);
	capture_keys(keys, sizeof(keys), 1, output, sizeof(output));
	assert(strcmp(output, " -k first -k second") == 0);
}

/*
 * main - run auditctl key parsing regression tests
 *
 * Returns: 0 when all tests pass.
 */
int main(void)
{
	test_key_match();
	test_key_output();
	return 0;
}
