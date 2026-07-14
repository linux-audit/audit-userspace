/*
 * test-syslog.c - bounds tests for audisp-syslog formatting helpers
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
#include <string.h>

#define main audisp_syslog_main
#include "audisp-syslog.c"
#undef main

static void test_append_text_preserves_termination(void)
{
	char buffer[8];
	char *cursor = buffer;
	size_t remaining = sizeof(buffer);

	buffer[0] = '\0';
	assert(append_text(&cursor, &remaining, "1234567") == 0);
	assert(cursor == &buffer[7]);
	assert(remaining == 1);
	assert(buffer[7] == '\0');
	assert(append_text(&cursor, &remaining, "8") == 1);
	assert(strcmp(buffer, "1234567") == 0);
}

int main(void)
{
	test_append_text_preserves_termination();
	return 0;
}
