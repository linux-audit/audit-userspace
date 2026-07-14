/*
 * test-remote-config.c - tests for audisp-remote configuration parsing
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <assert.h>
#include "remote-config.c"

static void test_parse_uint_rejects_narrowed_value(void)
{
	const struct nv_pair nv = {
		.name = "port",
		.value = "4294967297",
	};
	unsigned int value = 0;

	assert(parse_uint(&nv, 1, &value, 0, 65535) == 1);
}

static void test_parse_uint_accepts_range_limit(void)
{
	const struct nv_pair nv = {
		.name = "port",
		.value = "65535",
	};
	unsigned int value = 0;

	assert(parse_uint(&nv, 1, &value, 0, 65535) == 0);
	assert(value == 65535);
}

int main(void)
{
	test_parse_uint_rejects_narrowed_value();
	test_parse_uint_accepts_range_limit();
	return 0;
}
