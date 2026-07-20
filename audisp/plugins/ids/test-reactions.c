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
#include <sys/types.h>
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

/* Record a fork attempt and return failure without starting a child. */
pid_t __wrap_fork(void)
{
	fork_calls++;
	errno = EAGAIN;
	return -1;
}

/* Return the test's simulated current session, which may be NULL. */
session_data_t *current_session(void)
{
	return current;
}

/* Return no current origin because these tests exercise session reactions. */
origin_data_t *current_origin(void)
{
	return NULL;
}

/* Ignore the unused address and return no printable representation. */
char *sockint_to_ipv4(unsigned int addr __attribute__((unused)))
{
	return NULL;
}

/* Ignore the unused timer job and report success. */
int add_timer_job(jobs_t job __attribute__((unused)),
	const char *arg __attribute__((unused)),
	unsigned long length __attribute__((unused)))
{
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

/* Verify session termination tolerates an empty cursor and return success. */
int main(void)
{
	current = NULL;
	fork_calls = 0;
	do_reaction(REACTION_TERMINATE_SESSION, "no_session");
	assert(fork_calls == 0);
	return 0;
}
