/*
 * lol_alloc_test.c - linked-list-of-lists allocation failure tests
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
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "common.h"
#include "libaudit.h"

time_t start_time;
time_t end_time;
static unsigned int malloc_calls;
static unsigned int fail_malloc_at;
static int fail_realloc;

/*
 * test_malloc - optionally fail allocations made by the list implementations
 * @size: requested allocation size
 *
 * Returns: Allocated memory, or NULL when failure injection is enabled.
 */
static void *test_malloc(size_t size)
{
	malloc_calls++;
	if (fail_malloc_at && malloc_calls == fail_malloc_at)
		return NULL;
	return malloc(size);
}

/*
 * test_realloc - optionally fail table growth in the list-of-lists code
 * @ptr: allocation to resize
 * @size: requested allocation size
 *
 * Returns: Resized memory, or NULL when failure injection is enabled.
 */
static void *test_realloc(void *ptr, size_t size)
{
	if (fail_realloc)
		return NULL;
	return realloc(ptr, size);
}

/*
 * audit_strsplit - split audit fields at spaces for the parser test fixture
 * @s: string to begin splitting, or NULL to continue
 *
 * Returns: The next field, or NULL at the end of the string.
 */
char *audit_strsplit(char *s)
{
	static char *next;
	char *field;

	if (s)
		next = s;
	if (next == NULL)
		return NULL;
	while (*next == ' ')
		next++;
	if (*next == '\0') {
		next = NULL;
		return NULL;
	}
	field = next;
	next = strchr(next, ' ');
	if (next)
		*next++ = '\0';
	return field;
}

/*
 * audit_name_to_msg_type - provide a stable record type for this fixture
 * @name: audit record type name
 *
 * Returns: A non-terminal audit record type.
 */
int audit_name_to_msg_type(const char *name)
{
	(void)name;
	return 1;
}

/*
 * audit_is_last_record - keep fixture records in the building state
 * @type: audit record type
 *
 * Returns: Always zero for this allocation-failure fixture.
 */
int audit_is_last_record(int type)
{
	(void)type;
	return 0;
}

#define malloc test_malloc
#define realloc test_realloc
#include "../ausearch-string.c"
#include "../ausearch-avc.c"
#include "../ausearch-llist.c"
#include "../ausearch-lol.c"
#undef realloc
#undef malloc

/*
 * add_record - add one unique record to an in-progress event list
 * @lo: list-of-lists to populate
 * @serial: unique event serial number
 *
 * Returns: Result from lol_add_record().
 */
static int add_record(lol *lo, int serial)
{
	char record[80];

	assert(snprintf(record, sizeof(record),
		"type=TEST msg=audit(1000000000.001:%d): test", serial) > 0);
	return lol_add_record(lo, record);
}

/*
 * test_timestamp_range - reject seconds that do not fit the signed event time
 * @void: no input
 *
 * Returns: None. Failures abort through assert().
 */
static void test_timestamp_range(void)
{
	const unsigned long max_sec = (unsigned long)LONG_MAX -
		(unsigned long)eoe_timeout - 1;
	char timestamp[64];
	event e;

	assert(snprintf(timestamp, sizeof(timestamp), "%lu.999:1",
		max_sec) > 0);
	assert(str2event(timestamp, &e) == 0);
	assert(e.sec == (time_t)max_sec);

	assert(snprintf(timestamp, sizeof(timestamp), "%lu.000:1",
		(unsigned long)LONG_MAX + 1) > 0);
	assert(str2event(timestamp, &e) == -1);
}

/*
 * test_failed_record_append - discard a record whose list node cannot allocate
 *
 * Returns: None.
 */
static void test_failed_record_append(void)
{
	lol lo;

	lol_create(&lo);
	assert(lo.array != NULL);
	malloc_calls = 0;
	/* llist allocation succeeds; its record-node allocation fails. */
	fail_malloc_at = 2;
	assert(add_record(&lo, 1) == 0);
	assert(lo.maxi == -1);
	assert(lo.array[0].status == L_EMPTY);
	assert(malloc_calls == 2);
	fail_malloc_at = 0;
	lol_clear(&lo);
}

/*
 * test_failed_table_growth - discard a completed event when table growth fails
 *
 * Returns: None.
 */
static void test_failed_table_growth(void)
{
	lol lo;
	int i;

	lol_create(&lo);
	assert(lo.array != NULL);
	for (i = 1; i <= ARRAY_LIMIT; i++)
		assert(add_record(&lo, i) == 1);
	assert(lo.maxi == ARRAY_LIMIT - 1);

	fail_realloc = 1;
	assert(add_record(&lo, ARRAY_LIMIT + 1) == 0);
	assert(lo.maxi == ARRAY_LIMIT - 1);
	fail_realloc = 0;
	lol_clear(&lo);
}

int main(void)
{
	test_timestamp_range();
	test_failed_record_append();
	test_failed_table_growth();
	return 0;
}
