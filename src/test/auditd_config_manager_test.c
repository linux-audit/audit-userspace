/* auditd_config_manager_test.c - configuration worker lifecycle tests
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
#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include "auditd-event.h"
#include "private.h"

static pthread_mutex_t completion_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t completion_cond = PTHREAD_COND_INITIALIZER;
static unsigned int completion_count;
static unsigned int free_config_count;

/*
 * reconfig_ready - record a worker completion for the test thread
 *
 * Returns: None.
 */
void reconfig_ready(void)
{
	pthread_mutex_lock(&completion_lock);
	completion_count++;
	pthread_cond_signal(&completion_cond);
	pthread_mutex_unlock(&completion_lock);
}

/*
 * load_config - make each test worker take the parse-failure path
 * @config: configuration structure to initialize
 * @lt: configuration test mode, unused by this stub
 *
 * Returns: 1 to report a parse failure.
 */
int load_config(struct daemon_conf *config, log_test_t lt)
{
	(void)lt;
	memset(config, 0, sizeof(*config));
	return 1;
}

/*
 * free_config - record release of a failed configuration
 * @config: failed configuration, unused by this stub
 *
 * Returns: None.
 */
void free_config(struct daemon_conf *config)
{
	(void)config;
	free_config_count++;
}

/*
 * audit_msg - discard config manager diagnostics during the test
 * @priority: syslog priority, unused by this stub
 * @fmt: format string, unused by this stub
 *
 * Returns: None.
 */
void audit_msg(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

#include "../auditd-reconfig.c"

/*
 * wait_for_completion - wait until workers reach the main-loop handoff
 * @target: number of completions required before returning
 *
 * Returns: None.
 */
static void wait_for_completion(unsigned int target)
{
	pthread_mutex_lock(&completion_lock);
	while (completion_count < target)
		pthread_cond_wait(&completion_cond, &completion_lock);
	pthread_mutex_unlock(&completion_lock);
}

/*
 * test_busy_until_main_completion - reject reloads pending main-loop work
 *
 * Returns: None.
 */
static void test_busy_until_main_completion(void)
{
	struct auditd_event first, rejected, next;

	memset(&first, 0, sizeof(first));
	memset(&rejected, 0, sizeof(rejected));
	memset(&next, 0, sizeof(next));
	rejected.reply.type = AUDIT_SIGNAL_INFO;

	init_config_manager();
	assert(start_config_manager(&first) == 0);
	wait_for_completion(1);

	/* Parsing is done, but the main thread has not consumed the result. */
	assert(start_config_manager(&rejected) != 0);
	assert(rejected.reply.type == AUDIT_SIGNAL_INFO);
	assert(completion_count == 1);
	assert(free_config_count == 1);

	finish_config_manager();
	assert(start_config_manager(&next) == 0);
	wait_for_completion(2);
	assert(free_config_count == 2);
	finish_config_manager();
}

/*
 * main - run configuration manager lifecycle tests
 *
 * Returns: 0 after all assertions pass.
 */
int main(void)
{
	test_busy_until_main_completion();
	return 0;
}
