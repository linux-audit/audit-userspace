/* auditd_reconfigure_test.c - auditd reconfigure ownership tests
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auditd-reconfigure.h"
#include "auditd-dispatch.h"
#include "auditd-listen.h"
#include "private.h"

static const void *watched_free;
static unsigned int watched_free_count;
static unsigned int open_log_count;
static unsigned int disk_error_count;

/*
 * test_free - record whether the ownership test releases its allocation
 * @ptr: allocation being released
 *
 * Returns: None.
 */
static void test_free(void *ptr)
{
	if (ptr == watched_free)
		watched_free_count++;
	free(ptr);
}

#define free test_free
#include "../auditd-reconfigure.c"
#undef free

void update_report_timer(unsigned int interval)
{
	(void)interval;
}

void auditd_tcp_listen_reconfigure(const struct daemon_conf *nconf,
				   struct daemon_conf *oconf)
{
	(void)nconf;
	(void)oconf;
}

void reconfigure_dispatcher(const struct daemon_conf *config)
{
	(void)config;
}

void setup_percentages(struct daemon_conf *config, int fd)
{
	(void)config;
	(void)fd;
}

void audit_msg(int priority, const char *fmt, ...)
{
	(void)priority;
	(void)fmt;
}

/*
 * fail_permission_repair - emulate rejecting an unsafe audit log directory
 *
 * Returns: 1 to report a failed permission repair.
 */
static int fail_permission_repair(void)
{
	errno = EPERM;
	return 1;
}

/*
 * count_log_open - record an unexpected log-open attempt
 *
 * Returns: 0 to emulate a successful log open.
 */
static int count_log_open(void)
{
	open_log_count++;
	return 0;
}

/*
 * count_disk_error - record reconfigure error handling
 * @func: operation that reported the error
 * @err: saved operation error
 *
 * Returns: None.
 */
static void count_disk_error(const char *func, int err)
{
	assert(strcmp(func, "reconfig") == 0);
	assert(err == EPERM);
	disk_error_count++;
}

/*
 * setup_context - initialize the fields used by general reconfiguration
 * @ctx: context to initialize
 * @event: event carrying the new configuration
 * @old_conf: active configuration
 * @disk_err_warning: warning state updated by reconfiguration
 *
 * Returns: None.
 */
static void setup_context(struct auditd_reconfigure_context *ctx,
			  struct auditd_event *event,
			  struct daemon_conf *old_conf,
			  unsigned int *disk_err_warning)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->event = event;
	ctx->config = old_conf;
	ctx->state.disk_err_warning = disk_err_warning;
}

/*
 * setup_matching_action_mail_accounts - supply valid unchanged mail accounts
 * @old_conf: active configuration
 * @new_conf: reloaded configuration
 *
 * Returns: None.
 */
static void setup_matching_action_mail_accounts(struct daemon_conf *old_conf,
						struct daemon_conf *new_conf)
{
	old_conf->action_mail_acct = strdup("root");
	new_conf->action_mail_acct = strdup("root");
	assert(old_conf->action_mail_acct != NULL);
	assert(new_conf->action_mail_acct != NULL);
}

/*
 * test_matching_node_name_is_released - discard duplicate reload allocation
 *
 * Returns: None.
 */
static void test_matching_node_name_is_released(void)
{
	struct daemon_conf old_conf, new_conf;
	struct auditd_event event;
	struct auditd_reconfigure_context ctx;
	unsigned int disk_err_warning = 1;
	const char *old_name;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	memset(&event, 0, sizeof(event));
	old_conf.node_name_format = N_USER;
	new_conf.node_name_format = N_USER;
	old_conf.node_name = strdup("same-node");
	new_conf.node_name = strdup("same-node");
	assert(old_conf.node_name != NULL);
	assert(new_conf.node_name != NULL);
	setup_matching_action_mail_accounts(&old_conf, &new_conf);
	old_name = old_conf.node_name;
	event.reply.conf = &new_conf;
	setup_context(&ctx, &event, &old_conf, &disk_err_warning);

	watched_free = new_conf.node_name;
	watched_free_count = 0;
	reconfigure_general_options(&ctx);

	assert(old_conf.node_name == old_name);
	assert(watched_free_count == 1);
	assert(disk_err_warning == 0);
	new_conf.node_name = NULL;
	new_conf.action_mail_acct = NULL;
	free((void *)old_conf.node_name);
	free((void *)old_conf.action_mail_acct);
}

/*
 * test_node_name_nullness_replaces_active_value - apply a cleared node name
 *
 * Returns: None.
 */
static void test_node_name_nullness_replaces_active_value(void)
{
	struct daemon_conf old_conf, new_conf;
	struct auditd_event event;
	struct auditd_reconfigure_context ctx;
	unsigned int disk_err_warning = 1;
	const char *old_name;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	memset(&event, 0, sizeof(event));
	old_conf.node_name_format = N_USER;
	new_conf.node_name_format = N_USER;
	old_conf.node_name = strdup("old-node");
	assert(old_conf.node_name != NULL);
	setup_matching_action_mail_accounts(&old_conf, &new_conf);
	old_name = old_conf.node_name;
	event.reply.conf = &new_conf;
	setup_context(&ctx, &event, &old_conf, &disk_err_warning);

	watched_free = old_name;
	watched_free_count = 0;
	reconfigure_general_options(&ctx);

	assert(old_conf.node_name == NULL);
	assert(watched_free_count == 1);
	assert(disk_err_warning == 0);
	new_conf.action_mail_acct = NULL;
	free((void *)old_conf.action_mail_acct);
}

/*
 * test_new_node_name_replaces_null_value - apply a newly configured name
 *
 * Returns: None.
 */
static void test_new_node_name_replaces_null_value(void)
{
	struct daemon_conf old_conf, new_conf;
	struct auditd_event event;
	struct auditd_reconfigure_context ctx;
	unsigned int disk_err_warning = 1;
	const char *new_name;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	memset(&event, 0, sizeof(event));
	old_conf.node_name_format = N_USER;
	new_conf.node_name_format = N_USER;
	new_conf.node_name = strdup("new-node");
	assert(new_conf.node_name != NULL);
	setup_matching_action_mail_accounts(&old_conf, &new_conf);
	new_name = new_conf.node_name;
	event.reply.conf = &new_conf;
	setup_context(&ctx, &event, &old_conf, &disk_err_warning);

	watched_free = new_name;
	watched_free_count = 0;
	reconfigure_general_options(&ctx);

	assert(old_conf.node_name == new_name);
	assert(watched_free_count == 0);
	assert(disk_err_warning == 0);
	new_conf.action_mail_acct = NULL;
	free((void *)old_conf.node_name);
	free((void *)old_conf.action_mail_acct);
}

/*
 * test_permission_repair_failure_stops_reopen - fail closed on unsafe paths
 *
 * Returns: None.
 */
static void test_permission_repair_failure_stops_reopen(void)
{
	struct auditd_reconfigure_context ctx;
	FILE *log_file = NULL;
	int logging_suspended = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.state.log_file = &log_file;
	ctx.state.logging_suspended = &logging_suspended;
	ctx.ops.fix_disk_permissions = fail_permission_repair;
	ctx.ops.open_audit_log = count_log_open;
	ctx.ops.do_disk_error_action = count_disk_error;
	open_log_count = 0;
	disk_error_count = 0;

	reopen_log_file(&ctx);

	assert(open_log_count == 0);
	assert(disk_error_count == 1);
	assert(logging_suspended == 1);
}

int main(void)
{
	test_matching_node_name_is_released();
	test_node_name_nullness_replaces_active_value();
	test_new_node_name_replaces_null_value();
	test_permission_repair_failure_stops_reopen();
	return 0;
}
