/*
 * test-reactions.c - Test IDS reaction session handling
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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include "ids.h"
#include "ids_config.h"
#include "origin.h"
#include "reactions.h"
#include "session.h"
#include "timer-services.h"

int debug;
struct ids_conf config;

static unsigned int fork_calls;
static session_data_t *current;
static int capture_commands;
static unsigned int timer_calls;
static char timer_arg[INET6_ADDRSTRLEN];

#define CAPTURE_ARGS 12
#define CAPTURE_ARG_SIZE 64

struct exec_capture {
	char path[CAPTURE_ARG_SIZE];
	char argv[CAPTURE_ARGS][CAPTURE_ARG_SIZE];
	unsigned int argc;
};

static struct exec_capture *capture;

pid_t __real_fork(void);

/* Record a fork attempt and return failure without starting a child. */
pid_t __wrap_fork(void)
{
	fork_calls++;
	if (capture_commands)
		return __real_fork();
	errno = EAGAIN;
	return -1;
}

/* Capture an exec request in shared memory instead of running the command. */
int __wrap_execve(const char *path, char *const argv[],
	char *const envp[] __attribute__((unused)))
{
	unsigned int i;

	snprintf(capture->path, sizeof(capture->path), "%s", path);
	for (i = 0; i < CAPTURE_ARGS && argv[i]; i++)
		snprintf(capture->argv[i], sizeof(capture->argv[i]), "%s",
			argv[i]);
	capture->argc = i;
	_exit(0);
}

/* Return the legacy global cursor, which reaction dispatch must not consult. */
session_data_t *current_session(void)
{
	return current;
}

/* Return no current origin because these tests exercise session reactions. */
origin_data_t *current_origin(void)
{
	return NULL;
}

/* Record timed address jobs and report success. */
int add_timer_job(jobs_t job __attribute__((unused)),
	const char *arg,
	unsigned long length __attribute__((unused)))
{
	timer_calls++;
	snprintf(timer_arg, sizeof(timer_arg), "%s", arg);
	return 0;
}

/* Ignore the unused audit event and report success. */
int log_audit_event(int type __attribute__((unused)),
	const char *text __attribute__((unused)),
	int res __attribute__((unused)))
{
	return 0;
}

/* Ignore debug messages emitted while exercising reactions. */
void my_printf(const char *fmt __attribute__((unused)), ...)
{
}

/* Clear the shared command capture before invoking another reaction. */
static void reset_capture(void)
{
	memset(capture, 0, sizeof(*capture));
}

/* Verify firewall commands select the correct IPv4 and IPv6 syntax. */
static void test_firewall_commands(void)
{
	ids_address_t ipv4;
	ids_address_t ipv6;
	ids_address_t invalid;

	capture = mmap(NULL, sizeof(*capture), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert(capture != MAP_FAILED);
	assert(ids_address_parse("192.0.2.1", &ipv4) == 1);
	assert(ids_address_parse("2001:db8::1", &ipv6) == 1);
	assert(ids_address_parse("invalid", &invalid) == 0);

	fork_calls = 0;
	assert(block_ip_address(&invalid) == 1);
	assert(fork_calls == 0);

	capture_commands = 1;
	reset_capture();
	assert(block_ip_address(&ipv4) == 0);
#ifdef USE_NFTABLES
	assert(strcmp(capture->path, "/usr/sbin/nft") == 0);
	assert(capture->argc == 10);
	assert(strcmp(capture->argv[1], "add") == 0);
	assert(strcmp(capture->argv[6], "ip") == 0);
	assert(strcmp(capture->argv[8], "192.0.2.1") == 0);
#else
	assert(strcmp(capture->path, "/usr/sbin/iptables") == 0);
	assert(capture->argc == 7);
	assert(strcmp(capture->argv[1], "-I") == 0);
	assert(strcmp(capture->argv[4], "192.0.2.1") == 0);
#endif

	reset_capture();
	timer_calls = 0;
	assert(block_ip_address_timed(&ipv6, 60) == 0);
#ifdef USE_NFTABLES
	assert(strcmp(capture->path, "/usr/sbin/nft") == 0);
	assert(capture->argc == 10);
	assert(strcmp(capture->argv[6], "ip6") == 0);
	assert(strcmp(capture->argv[8], "2001:db8::1") == 0);
#else
	assert(strcmp(capture->path, "/usr/sbin/ip6tables") == 0);
	assert(capture->argc == 7);
	assert(strcmp(capture->argv[4], "2001:db8::1") == 0);
#endif
	assert(timer_calls == 1);
	assert(strcmp(timer_arg, "2001:db8::1") == 0);

	reset_capture();
	assert(unblock_ip_address("2001:0db8:0:0:0:0:0:1") == 0);
#ifdef USE_NFTABLES
	assert(strcmp(capture->argv[1], "delete") == 0);
	assert(strcmp(capture->argv[6], "ip6") == 0);
	assert(strcmp(capture->argv[8], "2001:db8::1") == 0);
#else
	assert(strcmp(capture->path, "/usr/sbin/ip6tables") == 0);
	assert(strcmp(capture->argv[1], "-D") == 0);
	assert(strcmp(capture->argv[4], "2001:db8::1") == 0);
#endif

	capture_commands = 0;
	assert(munmap(capture, sizeof(*capture)) == 0);
	capture = NULL;
}

/* Verify reactions use only their explicit session and return success. */
int main(void)
{
	session_data_t unrelated = { .session = 41, .acct = "unrelated" };
	session_data_t triggering = { .session = 42, .acct = "triggering" };

	// An origin-only reaction has no session target.
	current = NULL;
	fork_calls = 0;
	do_reaction(REACTION_TERMINATE_SESSION, "no_session", NULL);
	assert(fork_calls == 0);

	// A stale global cursor must not become an origin reaction target.
	current = &unrelated;
	fork_calls = 0;
	do_reaction(REACTION_TERMINATE_SESSION, "stale_session", NULL);
	assert(fork_calls == 0);

	// A session reaction uses the session supplied by its caller.
	fork_calls = 0;
	do_reaction(REACTION_TERMINATE_SESSION, "session_bad", &triggering);
	assert(fork_calls == 1);

	test_firewall_commands();
	return 0;
}
