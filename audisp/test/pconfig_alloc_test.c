/*
 * pconfig_alloc_test.c - allocation failure tests for audispd plugin parser
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_audit_msg(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
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

static void *test_calloc(size_t nmemb, size_t size)
{
	if (should_fail())
		return NULL;
	return calloc(nmemb, size);
}

static void *test_realloc(void *ptr, size_t size)
{
	if (should_fail())
		return NULL;
	return realloc(ptr, size);
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

#define audit_msg test_audit_msg
#define calloc test_calloc
#define realloc test_realloc
#define strdup test_strdup
#include "../audispd-pconfig.c"
#undef strdup
#undef realloc
#undef calloc
#undef audit_msg

static void test_path_preserves_old_value(void)
{
	plugin_conf_t config;
	struct nv_pair nv;
	char *values[] = { "/tmp/new-plugin" };

	clear_pconfig(&config);
	config.path = strdup("/tmp/old-plugin");
	assert(config.path != NULL);
	nv.name = "path";
	nv.values = values;
	nv.nvalues = 1;

	reset_allocs(2);
	assert(path_parser(&nv, 1, &config) == 1);
	assert(strcmp(config.path, "/tmp/old-plugin") == 0);

	free_pconfig(&config);
}

static void test_args_preserves_old_value(void)
{
	plugin_conf_t config;
	struct nv_pair nv;
	char *values[] = { "one", "two" };

	clear_pconfig(&config);
	config.nargs = 1;
	config.args = calloc(1, sizeof(char *));
	assert(config.args != NULL);
	config.args[0] = strdup("old");
	assert(config.args[0] != NULL);
	nv.name = "args";
	nv.values = values;
	nv.nvalues = 2;

	reset_allocs(2);
	assert(args_parser(&nv, 1, &config) == 1);
	assert(config.nargs == 1);
	assert(strcmp(config.args[0], "old") == 0);

	free_pconfig(&config);
}

static void test_nv_split_realloc_failure(void)
{
	struct nv_pair nv;
	char line[] = "args = one two";

	reset_allocs(2);
	assert(nv_split(line, &nv) == 1);
	assert(nv.values == NULL);
	assert(nv.nvalues == 0);
}

int main(void)
{
	test_path_preserves_old_value();
	test_args_preserves_old_value();
	test_nv_split_realloc_failure();
	return 0;
}
