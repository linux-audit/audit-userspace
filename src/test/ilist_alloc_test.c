/*
 * ilist_alloc_test.c - integer-list allocation failure tests
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
#include <stddef.h>
#include <stdlib.h>

static int fail_alloc;

/*
 * test_malloc - fail a requested list-node allocation when directed by a test
 * @size: requested allocation size
 *
 * Returns: Allocated memory, or NULL when failure injection is enabled.
 */
static void *test_malloc(size_t size)
{
	if (fail_alloc)
		return NULL;
	return malloc(size);
}

#define malloc test_malloc
#include "../ausearch-int.c"
#undef malloc

/*
 * assert_list - verify a list's order, count, and terminating link
 * @list: list to inspect
 * @numbers: expected ordered contents
 * @count: expected number of nodes
 *
 * Returns: None.
 */
static void assert_list(const ilist *list, const int *numbers, size_t count)
{
	const int_node *node = list->head;
	size_t i;

	assert(list->cnt == count);
	for (i = 0; i < count; i++) {
		assert(node != NULL);
		assert(node->num == numbers[i]);
		node = node->next;
	}
	assert(node == NULL);
}

/*
 * test_failed_insertions - preserve all links when node allocation fails
 *
 * Returns: None.
 */
static void test_failed_insertions(void)
{
	const int expected[] = { 3, 5, 7 };
	ilist list;

	ilist_create(&list);
	assert(ilist_add_if_uniq(&list, 3, 0) == 1);
	assert(ilist_add_if_uniq(&list, 5, 0) == 1);
	assert(ilist_add_if_uniq(&list, 7, 0) == 1);
	assert_list(&list, expected, 3);

	fail_alloc = 1;
	assert(ilist_add_if_uniq(&list, 1, 0) == -1);
	assert_list(&list, expected, 3);
	assert(ilist_add_if_uniq(&list, 4, 0) == -1);
	assert_list(&list, expected, 3);
	assert(ilist_add_if_uniq(&list, 9, 0) == -1);
	assert_list(&list, expected, 3);

	fail_alloc = 0;
	ilist_clear(&list);
}

int main(void)
{
	test_failed_insertions();
	return 0;
}
