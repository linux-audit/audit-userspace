/*
 * auditctl_rule_file_test.c - auditctl rules file parsing tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#define main auditctl_program_main
#define audit_add_rule_data test_audit_add_rule_data
#define audit_close test_audit_close
#include "../auditctl.c"
#undef audit_close
#undef audit_add_rule_data
#undef main

static int saw_syscall_0;
static int saw_syscall_1;

/*
 * test_audit_add_rule_data - capture the rule instead of sending it
 * @audit_fd: unused audit netlink descriptor
 * @rule: rule produced from the test file
 * @flags: unused audit rule filter
 * @action: unused audit rule action
 *
 * Returns: One to report a successful rule request.
 */
int test_audit_add_rule_data(int audit_fd, struct audit_rule_data *rule,
			     int flags, int action)
{
	(void)audit_fd;
	(void)flags;
	(void)action;
	saw_syscall_0 = !!(rule->mask[AUDIT_WORD(0)] & AUDIT_BIT(0));
	saw_syscall_1 = !!(rule->mask[AUDIT_WORD(1)] & AUDIT_BIT(1));
	return 1;
}

/*
 * test_audit_close - leave the synthetic audit descriptor untouched
 * @audit_fd: unused audit netlink descriptor
 *
 * Returns: None.
 */
void test_audit_close(int audit_fd)
{
	(void)audit_fd;
}

/*
 * test_dense_rule - retain every option from a densely tokenized rule
 *
 * Returns: None.
 */
static void test_dense_rule(void)
{
	static const char rule[] =
		"-a always,exit"
		" -S 0 -S 0 -S 0 -S 0 -S 0 -S 0 -S 0"
		" -S 0 -S 0 -S 0 -S 0 -S 0 -S 0 -S 0"
		" -S 1\n";
	char path[] = "/tmp/auditctl-rule-file-test-XXXXXX";
	int rule_fd;

	rule_fd = mkstemp(path);
	assert(rule_fd >= 0);
	assert(write(rule_fd, rule, sizeof(rule) - 1) == sizeof(rule) - 1);
	assert(close(rule_fd) == 0);

	fd = 42;
	assert(fileopt(path) == 0);
	assert(unlink(path) == 0);
	assert(saw_syscall_0 == 1);
	assert(saw_syscall_1 == 1);
	audit_rule_free_data(rule_new);
	rule_new = NULL;
}

/*
 * main - run auditctl rules file parsing regression tests
 *
 * Returns: Zero when all tests pass.
 */
int main(void)
{
	test_dense_rule();
	return 0;
}
