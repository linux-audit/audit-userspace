/*
 * auditctl_list_alloc_test.c - auditctl listing allocation failure tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <stdlib.h>

#include "auditctl-llist.h"

int list_requested;
int interpret;
char key[AUDIT_MAX_KEY_LEN+1];
static int fail_list_append;

/*
 * test_list_append - fail rule-list storage when directed by a test
 * @list: destination rule list
 * @rule: rule to copy
 * @size: size of @rule in bytes
 *
 * Returns: Non-zero when failure injection is enabled, otherwise list_append's
 * return value.
 */
static int test_list_append(llist *list, const struct audit_rule_data *rule,
			    size_t size)
{
	if (fail_list_append)
		return 1;
	return list_append(list, rule, size);
}

#define list_append test_list_append
#include "../auditctl-listing.c"
#undef list_append

/*
 * make_rule - allocate a minimal rule suitable for a list reply
 *
 * Returns: An allocated rule, or NULL if allocation fails.
 */
static struct audit_rule_data *make_rule(void)
{
	return calloc(1, sizeof(struct audit_rule_data));
}

/*
 * test_failed_list_append - reject a listing that cannot retain every rule
 *
 * Returns: None.
 */
static void test_failed_list_append(void)
{
	struct audit_reply reply = { 0 };
	struct audit_rule_data *rule = make_rule();

	assert(rule != NULL);
	assert(key[0] == 0);
	audit_print_init();
	list_requested = 1;
	fail_list_append = 1;
	reply.type = AUDIT_LIST_RULES;
	reply.ruledata = rule;
	assert(audit_print_reply(&reply, -1) == -1);
	assert(list_requested == 0);
	assert(l.cnt == 0);
	fail_list_append = 0;
	free(rule);
}

/*
 * main - run auditctl list allocation regression tests
 *
 * Returns: 0 when all tests pass.
 */
int main(void)
{
	test_failed_list_append();
	return 0;
}
