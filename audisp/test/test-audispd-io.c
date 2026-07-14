/* test-audispd-io.c - dispatcher write completion tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static unsigned char captured[256];
static size_t captured_len;
static unsigned int write_calls;
static int zero_progress;

static ssize_t test_write(int fd, const void *buf, size_t len)
{
	size_t chunk;

	assert(fd == 42);
	if (write_calls++ == 0) {
		errno = EINTR;
		return -1;
	}
	if (zero_progress)
		return 0;
	chunk = len > 3 ? 3 : len;
	assert(captured_len + chunk <= sizeof(captured));
	memcpy(captured + captured_len, buf, chunk);
	captured_len += chunk;
	return (ssize_t)chunk;
}

#define write test_write
#include "../audispd.c"
#undef write

static void reset_output(void)
{
	captured_len = 0;
	write_calls = 0;
	zero_progress = 0;
}

static void test_string_write_completes(void)
{
	plugin_conf_t plugin = {
		.format = F_STRING,
		.plug_pipe = { -1, 42 },
	};
	lnode node = { .p = &plugin };
	const char record[] = "complete string record";

	reset_output();
	assert(write_to_plugin(NULL, record, sizeof(record) - 1, &node) == 0);
	assert(write_calls > 2);
	assert(captured_len == sizeof(record) - 1);
	assert(memcmp(captured, record, captured_len) == 0);
}

static void test_binary_write_keeps_frame_order(void)
{
	plugin_conf_t plugin = {
		.format = F_BINARY,
		.plug_pipe = { -1, 42 },
	};
	lnode node = { .p = &plugin };
	event_t event = { 0 };
	size_t header_len = sizeof(event.hdr);

	event.hdr.ver = AUDISP_PROTOCOL_VER2;
	event.hdr.size = 5;
	memcpy(event.data, "event", event.hdr.size);
	reset_output();
	assert(write_to_plugin(&event, NULL, 0, &node) == 0);
	assert(captured_len == header_len + event.hdr.size);
	assert(memcmp(captured, &event.hdr, header_len) == 0);
	assert(memcmp(captured + header_len, event.data,
		       event.hdr.size) == 0);
}

static void test_zero_length_write_fails(void)
{
	plugin_conf_t plugin = {
		.format = F_STRING,
		.plug_pipe = { -1, 42 },
	};
	lnode node = { .p = &plugin };

	reset_output();
	zero_progress = 1;
	errno = 0;
	assert(write_to_plugin(NULL, "x", 1, &node) == -1);
	assert(errno == EIO);
}

int main(void)
{
	test_string_write_completes();
	test_binary_write_keeps_frame_order();
	test_zero_length_write_fails();
	return 0;
}
