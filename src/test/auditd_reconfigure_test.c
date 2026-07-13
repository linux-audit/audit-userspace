/* auditd_reconfigure_test.c - auditd reconfigure ownership tests
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

int main(void)
{
	test_matching_node_name_is_released();
	test_node_name_nullness_replaces_active_value();
	test_new_node_name_replaces_null_value();
	return 0;
}
