/* test-audispd-io.c - dispatcher write completion tests
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
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned char captured[256];
static size_t captured_len;
static unsigned int write_calls;
static unsigned int calloc_calls;
static int zero_progress;
static int write_epipe;
static int fork_should_fail;
static pid_t child_pid;
static int child_state;
static int last_signal;

enum {
	CHILD_RUNNING,
	CHILD_MISSING,
	CHILD_EXITS_ON_SIGNAL,
};

/* Model exact-PID child state checks made by the dispatcher. */
static pid_t test_waitpid(pid_t pid, int *status, int options)
{
	(void)status;
	assert(options == WNOHANG || options == 0);
	assert(pid == child_pid);
	if (child_state == CHILD_MISSING) {
		errno = ECHILD;
		return -1;
	}
	if (child_state == CHILD_EXITS_ON_SIGNAL && last_signal)
		return pid;
	return 0;
}

/* Record signals without affecting a real process. */
static int test_kill(pid_t pid, int sig)
{
	assert(pid == child_pid);
	last_signal = sig;
	return 0;
}

/* Avoid real grace-period delays in child lifecycle tests. */
static int test_usleep(useconds_t usec)
{
	assert(usec == 50000);
	return 0;
}

static void *test_calloc(size_t count, size_t size)
{
	calloc_calls++;
	return calloc(count, size);
}

static pid_t test_fork(void)
{
	assert(fork_should_fail);
	assert(calloc_calls == 1);
	errno = EAGAIN;
	return -1;
}

static ssize_t test_write(int fd, const void *buf, size_t len)
{
	size_t chunk;

	assert(fd == 42);
	if (write_epipe) {
		write_calls++;
		errno = EPIPE;
		return -1;
	}
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

#define calloc test_calloc
#define fork test_fork
#define kill test_kill
#define usleep test_usleep
#define waitpid test_waitpid
#define write test_write
#include "../audispd.c"
#undef write
#undef waitpid
#undef usleep
#undef kill
#undef fork
#undef calloc

static void reset_output(void)
{
	captured_len = 0;
	write_calls = 0;
	zero_progress = 0;
	write_epipe = 0;
}

/* Reset dispatcher-child syscall mocks and their global test state. */
static void reset_child_mocks(void)
{
	child_pid = -1;
	child_state = CHILD_RUNNING;
	last_signal = 0;
	plugin_conf.head = NULL;
	plugin_conf.cur = NULL;
	plugin_conf.cnt = 0;
	AUDIT_ATOMIC_STORE(plugin_child_pending, 0);
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

static void test_safe_exec_preserves_fork_failure(void)
{
	plugin_conf_t plugin = {
		.path = "/bin/true",
		.plug_pipe = { 7, 8 },
		.pid = 123,
	};

	calloc_calls = 0;
	fork_should_fail = 1;
	errno = 0;
	assert(safe_exec(&plugin) == -1);
	assert(errno == EAGAIN);
	assert(calloc_calls == 1);
	assert(plugin.pid == 0);
	assert(plugin.plug_pipe[0] == -1);
	assert(plugin.plug_pipe[1] == -1);
	fork_should_fail = 0;
}

/* Verify dispatcher reaping clears a stale PID without moving the cursor. */
static void test_stale_plugin_pid_is_cleared(void)
{
	plugin_conf_t plugin = { .pid = 101, .type = S_ALWAYS };
	lnode cursor = { 0 };
	lnode node = { .p = &plugin };

	reset_child_mocks();
	plugin_conf.head = &node;
	plugin_conf.cur = &cursor;
	plugin_conf.cnt = 1;
	child_pid = plugin.pid;
	child_state = CHILD_MISSING;
	libdisp_child_changed();
	reap_plugin_children();
	assert(plugin.pid == 0);
	assert(plugin_conf.cur == &cursor);
	assert(last_signal == 0);
}

/* Verify stop_plugin reaps the old generation before allowing replacement. */
static void test_plugin_stop_is_serialized(void)
{
	plugin_conf_t plugin = {
		.pid = 303,
		.type = S_ALWAYS,
		.plug_pipe = { -1, -1 },
	};

	reset_child_mocks();
	child_pid = plugin.pid;
	child_state = CHILD_EXITS_ON_SIGNAL;
	assert(stop_plugin(&plugin) == 0);
	assert(plugin.pid == 0);
	assert(last_signal == SIGTERM);
}

/* Verify a complete retry makes the restarted plugin active again. */
static void test_restart_retry_activates_plugin(void)
{
	plugin_conf_t plugin = {
		.active = A_NO,
		.format = F_STRING,
		.path = "/bin/true",
		.plug_pipe = { -1, 42 },
		.restart_cnt = 2,
	};
	lnode node = { .p = &plugin };

	reset_output();
	finish_plugin_restart(NULL, "event", 5, &node);
	assert(plugin.active == A_YES);
	assert(captured_len == 5);
}

/* Verify a failed retry leaves the plugin inactive and stops its child. */
static void test_restart_retry_failure_stops_plugin(void)
{
	plugin_conf_t plugin = {
		.active = A_NO,
		.format = F_STRING,
		.path = "/bin/true",
		.pid = 404,
		.plug_pipe = { -1, 42 },
		.restart_cnt = 2,
		.type = S_ALWAYS,
	};
	lnode node = { .p = &plugin };

	reset_child_mocks();
	reset_output();
	write_epipe = 1;
	child_pid = plugin.pid;
	child_state = CHILD_EXITS_ON_SIGNAL;
	finish_plugin_restart(NULL, "event", 5, &node);
	assert(plugin.active == A_NO);
	assert(plugin.pid == 0);
	assert(last_signal == SIGTERM);
}

int main(void)
{
	test_string_write_completes();
	test_binary_write_keeps_frame_order();
	test_zero_length_write_fails();
	test_safe_exec_preserves_fork_failure();
	test_stale_plugin_pid_is_cleared();
	test_plugin_stop_is_serialized();
	test_restart_retry_activates_plugin();
	test_restart_retry_failure_stops_plugin();
	return 0;
}
