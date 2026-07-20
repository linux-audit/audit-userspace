/*
 * ausearch_time_test.c - ausearch time parsing regression tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include "ausearch-time.h"

/*
 * test_eoe_timeout_range - reject timeouts that narrow to negative time_t
 * @void: no input
 *
 * Returns: None. Failures abort through assert().
 */
static void test_eoe_timeout_range(void)
{
	char value[64];
	time_t timeout = 17;

	assert(ausearch_parse_eoe_timeout("2", &timeout) == 0);
	assert(timeout == 2);
	assert(ausearch_parse_eoe_timeout("0", &timeout) == -1);
	assert(timeout == 2);

	assert(snprintf(value, sizeof(value), "%lu",
		(unsigned long)LONG_MAX - 1) > 0);
	assert(ausearch_parse_eoe_timeout(value, &timeout) == 0);
	assert(timeout == (time_t)LONG_MAX - 1);

	assert(snprintf(value, sizeof(value), "%lu",
		(unsigned long)LONG_MAX) > 0);
	assert(ausearch_parse_eoe_timeout(value, &timeout) == -1);
	assert(timeout == (time_t)LONG_MAX - 1);

	assert(snprintf(value, sizeof(value), "%lu",
		(unsigned long)LONG_MAX + 1) > 0);
	assert(ausearch_parse_eoe_timeout(value, &timeout) == -1);
	assert(timeout == (time_t)LONG_MAX - 1);
}

/*
 * main - run ausearch time parsing regression tests
 * @void: no input
 *
 * Returns: 0 when all tests pass.
 */
int main(void)
{
	test_eoe_timeout_range();
	return 0;
}
