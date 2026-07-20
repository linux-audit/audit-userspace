/*
 * delete_all_alloc_test.c - delete-all allocation failure tests
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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "libaudit.h"

#include "../delete_all.c"

static int append_calls;
static int clear_calls;
static int reply_calls;
static int send_calls;

/*
 * audit_request_rules_list_data - provide a known request sequence
 * @fd: audit netlink descriptor
 *
 * Returns: The test's request sequence.
 */
int audit_request_rules_list_data(int fd)
{
	(void)fd;
	return 1;
}

/*
 * audit_get_reply - provide one matching rule-list reply
 * @fd: audit netlink descriptor
 * @rep: reply to populate
 * @block: requested receive mode
 * @peek: requested receive peek mode
 *
 * Returns: One for the synthetic reply, then zero.
 */
int audit_get_reply(int fd, struct audit_reply *rep, reply_t block, int peek)
{
	static struct nlmsghdr header;
	static struct audit_rule_data rule;

	(void)fd;
	(void)block;
	(void)peek;
	if (reply_calls++)
		return 0;

	memset(rep, 0, sizeof(*rep));
	header.nlmsg_seq = 1;
	rep->nlh = &header;
	rep->type = AUDIT_LIST_RULES;
	rep->ruledata = &rule;
	return 1;
}

/*
 * audit_send - record attempted rule deletions
 * @fd: audit netlink descriptor
 * @type: requested audit message type
 * @data: message payload
 * @size: payload size
 *
 * Returns: Success.
 */
int audit_send(int fd, int type, const void *data, unsigned int size)
{
	(void)fd;
	(void)type;
	(void)data;
	(void)size;
	send_calls++;
	return 1;
}

/*
 * audit_msg - discard diagnostic output from the unit under test
 * @priority: audit log priority
 * @fmt: diagnostic format string
 *
 * Returns: None.
 */
void audit_msg(int priority, const char *fmt, ...)
{
	va_list args;

	(void)priority;
	(void)fmt;
	va_start(args, fmt);
	va_end(args);
}

/*
 * key_match - select the synthetic rule for deletion
 * @rule: candidate rule
 *
 * Returns: One.
 */
int key_match(const struct audit_rule_data *rule)
{
	(void)rule;
	return 1;
}

/*
 * list_create - initialize the list passed to the test stubs
 * @list: list to initialize
 *
 * Returns: None.
 */
void list_create(llist *list)
{
	memset(list, 0, sizeof(*list));
}

/*
 * list_first - reset the test list iterator
 * @list: list to reset
 *
 * Returns: None.
 */
void list_first(llist *list)
{
	list->cur = list->head;
}

/*
 * list_next - advance the test list iterator
 * @list: list to advance
 *
 * Returns: No node.
 */
lnode *list_next(llist *list)
{
	list->cur = NULL;
	return NULL;
}

/*
 * list_append - simulate a failed rule copy
 * @list: destination list
 * @rule: rule to copy
 * @size: size of @rule in bytes
 *
 * Returns: Non-zero to report allocation failure.
 */
int list_append(llist *list, const struct audit_rule_data *rule, size_t size)
{
	(void)list;
	(void)rule;
	(void)size;
	append_calls++;
	return 1;
}

/*
 * list_clear - record cleanup of a partially collected rule list
 * @list: list to clear
 *
 * Returns: None.
 */
void list_clear(llist *list)
{
	memset(list, 0, sizeof(*list));
	clear_calls++;
}

/*
 * test_failed_list_append - make sure failure occurs before any deletion
 *
 * Returns: None.
 */
static void test_failed_list_append(void)
{
	int pipefd[2];

	assert(pipe(pipefd) == 0);
	assert(write(pipefd[1], "x", 1) == 1);
	assert(delete_all_rules(pipefd[0]) == -1);
	assert(append_calls == 1);
	assert(clear_calls == 1);
	assert(send_calls == 0);
	close(pipefd[0]);
	close(pipefd[1]);
}

/*
 * main - run delete-all allocation regression tests
 *
 * Returns: 0 when all tests pass.
 */
int main(void)
{
	test_failed_list_append();
	return 0;
}
