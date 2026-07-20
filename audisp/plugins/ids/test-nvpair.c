/*
 * test-nvpair.c - Test timer job list handling
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "nvpair.h"

/* Append a timer job, transferring ownership of its argument to the list. */
static void append_job(nvlist *list, const char *arg, time_t expiration)
{
	nvnode node;

	node.job = UNLOCK_ACCOUNT;
	node.arg = strdup(arg);
	assert(node.arg != NULL);
	node.expiration = expiration;
	node.next = NULL;
	assert(nvpair_list_append(list, &node) == 0);
}

/* Verify append does not depend on cursor state left by timer processing. */
int main(void)
{
	nvlist list;
	time_t now = 100;

	nvpair_list_create(&list);
	append_job(&list, "expired", now);
	append_job(&list, "pending", now + 10);

	assert(nvpair_list_find_job(&list, now) == 1);
	assert(nvpair_list_get_cur(&list) == list.head);
	nvpair_list_delete_cur(&list);
	assert(list.cnt == 1);
	assert(nvpair_list_get_cur(&list) == NULL);
	assert(list.prev == NULL);

	assert(nvpair_list_find_job(&list, now) == 0);
	assert(nvpair_list_get_cur(&list) == NULL);
	append_job(&list, "new", now + 20);

	assert(list.cnt == 2);
	assert(strcmp(list.head->arg, "pending") == 0);
	assert(list.head->next != NULL);
	assert(strcmp(list.head->next->arg, "new") == 0);
	assert(list.head->next->next == NULL);
	assert(nvpair_list_get_cur(&list) == list.head->next);
	assert(list.prev == list.head);

	nvpair_list_clear(&list);
	assert(list.head == NULL);
	assert(list.cur == NULL);
	assert(list.prev == NULL);
	assert(list.cnt == 0);
	return 0;
}
