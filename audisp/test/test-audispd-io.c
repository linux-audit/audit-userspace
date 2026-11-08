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
static unsigned int dropped;
static void (*write_hook)(void);

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
	assert(calloc_calls == 1);
	if (fork_should_fail) {
		errno = EAGAIN;
		return -1;
	}
	assert(child_pid > 0);
	return child_pid;
}

static int test_socketpair(int domain, int type, int protocol, int sv[2])
{
	(void)domain;
	(void)type;
	(void)protocol;
	sv[0] = -1;
	sv[1] = 42;
	return 0;
}

static void test_increment_plugin_dropped(void)
{
	dropped++;
}

static struct event *test_dequeue(void);

static ssize_t test_write(int fd, const void *buf, size_t len)
{
	size_t chunk;

	assert(fd == 42);
	if (write_hook)
		write_hook();
	if (write_epipe) {
		write_epipe--;
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
#define dequeue test_dequeue
#define fork test_fork
#define increment_plugin_dropped test_increment_plugin_dropped
#define kill test_kill
#define socketpair test_socketpair
#define usleep test_usleep
#define waitpid test_waitpid
#define write test_write
#include "../audispd.c"
#undef write
#undef waitpid
#undef usleep
#undef socketpair
#undef kill
#undef increment_plugin_dropped
#undef fork
#undef dequeue
#undef calloc

static event_t *pending[4];
static unsigned int pending_cnt, pending_next;

/* Hand queued records to event_loop(), then make it return as on SIGHUP. */
static event_t *test_dequeue(void)
{
	if (pending_next == pending_cnt) {
		AUDIT_ATOMIC_STORE(disp_hup, 1);
		return NULL;
	}
	return pending[pending_next++];
}

static int run_event_loop(unsigned int cnt, unsigned int ver)
{
	unsigned int i;
	int rc;

	assert(cnt <= sizeof(pending) / sizeof(pending[0]));
	for (i = 0; i < cnt; i++) {
		pending[i] = calloc(1, sizeof(event_t));
		assert(pending[i]);
		pending[i]->hdr.ver = ver;
		pending[i]->hdr.size = 1;
		pending[i]->data[0] = 'x';
	}
	pending_cnt = cnt;
	pending_next = 0;
	dropped = 0;
	rc = event_loop();
	AUDIT_ATOMIC_STORE(disp_hup, 0);
	return rc;
}

static void request_stop(void)
{
	AUDIT_ATOMIC_STORE(stop, 1);
}

static void reset_output(void)
{
	captured_len = 0;
	write_calls = 0;
	zero_progress = 0;
	write_epipe = 0;
	write_hook = NULL;
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

static const plugin_conf_t running_plugin = {
	.active = A_YES,
	.format = F_STRING,
	.path = "/bin/true",
	.plug_pipe = { -1, 42 },
	.type = S_ALWAYS,
};

static void use_plugins(lnode *head, unsigned int cnt)
{
	reset_child_mocks();
	reset_output();
	plugin_conf.head = head;
	plugin_conf.cnt = cnt;
}

/* Verify each record a failed plugin misses is counted once. */
static void test_inactive_plugin_drops_counted(void)
{
	plugin_conf_t live = running_plugin;
	plugin_conf_t failed = { .active = A_NO, .type = S_ALWAYS };
	plugin_conf_t failed2 = failed;
	lnode third = { .p = &failed2 };
	lnode second = { .p = &failed, .next = &third };
	lnode first = { .p = &live, .next = &second };

	use_plugins(&first, 3);
	assert(run_event_loop(3, AUDISP_PROTOCOL_VER2) == 1);
	assert(dropped == 3);
	assert(captured_len == 6);
}

/* Verify the record that exposes a dead, unrestarted plugin is counted. */
static void test_dead_plugin_drop_counted(void)
{
	plugin_conf_t plugin = running_plugin;
	lnode node = { .p = &plugin };

	use_plugins(&node, 1);
	write_epipe = 1;
	assert(run_event_loop(1, AUDISP_PROTOCOL_VER2) == 1);
	assert(plugin.active == A_NO);
	assert(dropped == 1);
}

/* Verify a record the restarted plugin receives is not counted. */
static void test_restarted_plugin_not_counted(void)
{
	plugin_conf_t plugin = running_plugin;
	lnode node = { .p = &plugin };

	use_plugins(&node, 1);
	daemon_config.max_restarts = 1;
	calloc_calls = 0;
	child_pid = 505;
	write_epipe = 1;
	assert(run_event_loop(1, AUDISP_PROTOCOL_VER2) == 1);
	daemon_config.max_restarts = 0;
	assert(plugin.active == A_YES);
	assert(captured_len == 2);
	assert(dropped == 0);
}

/* Verify a failed write to a plugin that keeps running is counted. */
static void test_failed_write_drop_counted(void)
{
	plugin_conf_t plugin = running_plugin;
	lnode node = { .p = &plugin };

	use_plugins(&node, 1);
	zero_progress = 1;
	assert(run_event_loop(1, AUDISP_PROTOCOL_VER2) == 1);
	assert(plugin.active == A_YES);
	assert(dropped == 1);
}

/* Verify a record the dispatcher cannot format is counted. */
static void test_unformatted_drop_counted(void)
{
	plugin_conf_t plugin = running_plugin;
	lnode node = { .p = &plugin };

	use_plugins(&node, 1);
	assert(run_event_loop(1, AUDISP_PROTOCOL_VER2 + 1) == 1);
	assert(write_calls == 0);
	assert(dropped == 1);
}

/* Verify a plugin lost during shutdown is not counted. */
static void test_shutdown_drop_not_counted(void)
{
	plugin_conf_t plugin = running_plugin;
	lnode node = { .p = &plugin };

	use_plugins(&node, 1);
	daemon_config.max_restarts = 1;
	write_hook = request_stop;
	write_epipe = 1;
	assert(run_event_loop(1, AUDISP_PROTOCOL_VER2) == 0);
	daemon_config.max_restarts = 0;
	AUDIT_ATOMIC_STORE(stop, 0);
	assert(plugin.active == A_NO);
	assert(dropped == 0);
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
	test_inactive_plugin_drops_counted();
	test_dead_plugin_drop_counted();
	test_restarted_plugin_not_counted();
	test_failed_write_drop_counted();
	test_unformatted_drop_counted();
	test_shutdown_drop_not_counted();
	return 0;
}
