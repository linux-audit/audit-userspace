/* auditd-reconfigure.c --
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "auditd-reconfigure.h"
#include "auditd-dispatch.h"
#include "auditd-listen.h"
#include "private.h"

extern void update_report_timer(unsigned int interval);

/*
 * reconfigure_general_options - Update global daemon options.
 * @ctx: Reconfigure context containing old and new daemon configuration.
 *
 * Returns: None.
 */
static void reconfigure_general_options(struct auditd_reconfigure_context *ctx)
{
	struct daemon_conf *nconf = ctx->event->reply.conf;
	struct daemon_conf *oconf = ctx->config;

	// start with disk error action.
	oconf->disk_error_action = nconf->disk_error_action;
	free((char *)oconf->disk_error_exe);
	oconf->disk_error_exe = nconf->disk_error_exe;
	*ctx->state.disk_err_warning = 0;

	// number of logs
	oconf->num_logs = nconf->num_logs;

	// flush freq
	oconf->freq = nconf->freq;

	// priority boost
	if (oconf->priority_boost != nconf->priority_boost) {
		oconf->priority_boost = nconf->priority_boost;
		errno = 0;
		if (nice(-oconf->priority_boost))
			; /* Intentionally blank, we have to check errno */
		if (errno)
			audit_msg(LOG_WARNING, "Cannot change priority in "
					"reconfigure (%s)", strerror(errno));
	}

	// log format
	oconf->log_format = nconf->log_format;

	// action_mail_acct
	if (strcmp(oconf->action_mail_acct, nconf->action_mail_acct)) {
		free((void *)oconf->action_mail_acct);
		oconf->action_mail_acct = nconf->action_mail_acct;
	} else
		free((void *)nconf->action_mail_acct);

	// node_name
	if (oconf->node_name_format != nconf->node_name_format ||
			(oconf->node_name == NULL) != (nconf->node_name == NULL) ||
			(oconf->node_name && nconf->node_name &&
			strcmp(oconf->node_name, nconf->node_name) != 0)) {
		oconf->node_name_format = nconf->node_name_format;
		free((char *)oconf->node_name);
		oconf->node_name = nconf->node_name;
	} else {
		/* The event buffer overwrites nconf after reconfigure. */
		free((char *)nconf->node_name);
	}

	// report interval
	if (oconf->report_interval != nconf->report_interval) {
		oconf->report_interval = nconf->report_interval;
		update_report_timer(oconf->report_interval);
	}
}

/*
 * reconfigure_network_options - Update network listener options.
 * @ctx: Reconfigure context containing old and new daemon configuration.
 *
 * Returns: None.
 */
static void reconfigure_network_options(struct auditd_reconfigure_context *ctx)
{
	struct daemon_conf *nconf = ctx->event->reply.conf;
	struct daemon_conf *oconf = ctx->config;

	auditd_tcp_listen_reconfigure(nconf, oconf);
	oconf->distribute_network_events = nconf->distribute_network_events;
}

/*
 * reconfigure_dispatcher_options - Update dispatcher and plugin options.
 * @ctx: Reconfigure context containing old and new daemon configuration.
 *
 * Returns: None.
 */
static void reconfigure_dispatcher_options(
		struct auditd_reconfigure_context *ctx)
{
	struct daemon_conf *nconf = ctx->event->reply.conf;
	struct daemon_conf *oconf = ctx->config;

	oconf->q_depth = nconf->q_depth;
	oconf->overflow_action = nconf->overflow_action;
	oconf->max_restarts = nconf->max_restarts;
	if (nconf->plugin_dir) {
		if (!oconf->plugin_dir ||
				strcmp(oconf->plugin_dir,
					nconf->plugin_dir) != 0) {
			char *tmp = strdup(nconf->plugin_dir);

			if (tmp == NULL)
				audit_msg(LOG_ERR,
				"Cannot duplicate plugin_dir in reconfigure");
			else {
				free(oconf->plugin_dir);
				oconf->plugin_dir = tmp;
			}
		}
	} else if (oconf->plugin_dir) {
		free(oconf->plugin_dir);
		oconf->plugin_dir = NULL;
	}
	if (nconf->plugin_dir == oconf->plugin_dir)
		nconf->plugin_dir = NULL;
	else {
		free(nconf->plugin_dir);
		nconf->plugin_dir = NULL;
	}
}

/*
 * reopen_log_file - Reopen the active audit log file.
 * @ctx: Reconfigure context containing log file state and event callbacks.
 *
 * Returns: None.
 */
static void reopen_log_file(struct auditd_reconfigure_context *ctx)
{
	if (*ctx->state.log_file)
		fclose(*ctx->state.log_file);
	*ctx->state.log_file = NULL;
	ctx->ops.fix_disk_permissions();
	if (ctx->ops.open_audit_log()) {
		int saved_errno = errno;

		audit_msg(LOG_ERR,
			"Could not reopen a log after reconfigure");
		*ctx->state.logging_suspended = 1;
		// Likely errors: ENOMEM, ENOSPC
		ctx->ops.do_disk_error_action("reconfig", saved_errno);
	} else {
		*ctx->state.logging_suspended = 0;
		ctx->ops.check_log_file_size();
	}
}

/*
 * reconfigure_log_file_options - Update log file and rotation options.
 * @ctx: Reconfigure context containing old and new daemon configuration.
 *
 * Returns: None.
 */
static void reconfigure_log_file_options(
		struct auditd_reconfigure_context *ctx)
{
	struct daemon_conf *nconf = ctx->event->reply.conf;
	struct daemon_conf *oconf = ctx->config;

	// Only update this if we are in background mode since
	// foreground mode writes to stderr.
	if ((oconf->write_logs != nconf->write_logs) &&
				(oconf->daemonize == D_BACKGROUND)) {
		oconf->write_logs = nconf->write_logs;
		ctx->need_reopen = 1;
	}

	// log_group
	if (oconf->log_group != nconf->log_group) {
		oconf->log_group = nconf->log_group;
		ctx->need_reopen = 1;
	}

	// max logfile action
	if (oconf->max_log_size_action != nconf->max_log_size_action) {
		oconf->max_log_size_action = nconf->max_log_size_action;
		ctx->need_size_check = 1;
	}

	// max log size
	if (oconf->max_log_size != nconf->max_log_size) {
		oconf->max_log_size = nconf->max_log_size;
		ctx->need_size_check = 1;
	}

	// max log exe
	if (oconf->max_log_file_exe || nconf->max_log_file_exe) {
		if (nconf->max_log_file_exe == NULL)
			;
		else if (oconf->max_log_file_exe == NULL &&
				nconf->max_log_file_exe)
			ctx->need_size_check = 1;
		else if (strcmp(oconf->max_log_file_exe,
				nconf->max_log_file_exe))
			ctx->need_size_check = 1;
		free((char *)oconf->max_log_file_exe);
		oconf->max_log_file_exe = nconf->max_log_file_exe;
	}

	if (ctx->need_size_check) {
		*ctx->state.logging_suspended = 0;
		ctx->ops.check_log_file_size();
	}

	// flush technique
	if (oconf->flush != nconf->flush) {
		oconf->flush = nconf->flush;
		ctx->need_reopen = 1;
	}

	// logfile
	if (strcmp(oconf->log_file, nconf->log_file)) {
		free((void *)oconf->log_file);
		oconf->log_file = nconf->log_file;
		ctx->need_reopen = 1;
		ctx->need_space_check = 1; // might be on new partition
	} else
		free((void *)nconf->log_file);

	if (ctx->need_reopen)
		reopen_log_file(ctx);
}

/*
 * reconfigure_disk_space_options - Update disk space thresholds and actions.
 * @ctx: Reconfigure context containing old and new daemon configuration.
 *
 * Returns: None.
 */
static void reconfigure_disk_space_options(
		struct auditd_reconfigure_context *ctx)
{
	struct daemon_conf *nconf = ctx->event->reply.conf;
	struct daemon_conf *oconf = ctx->config;

	// space left
	if (oconf->space_left != nconf->space_left) {
		oconf->space_left = nconf->space_left;
		ctx->need_space_check = 1;
	}

	// space left percent
	if (oconf->space_left_percent != nconf->space_left_percent) {
		oconf->space_left_percent = nconf->space_left_percent;
		ctx->need_space_check = 1;
	}

	// space left action
	if (oconf->space_left_action != nconf->space_left_action) {
		oconf->space_left_action = nconf->space_left_action;
		ctx->need_space_check = 1;
	}

	// space left exe
	if (oconf->space_left_exe || nconf->space_left_exe) {
		if (nconf->space_left_exe == NULL)
			; /* do nothing if new one is blank */
		else if (oconf->space_left_exe == NULL && nconf->space_left_exe)
			ctx->need_space_check = 1;
		else if (strcmp(oconf->space_left_exe, nconf->space_left_exe))
			ctx->need_space_check = 1;
		free((char *)oconf->space_left_exe);
		oconf->space_left_exe = nconf->space_left_exe;
	}

	// admin space left
	if (oconf->admin_space_left != nconf->admin_space_left) {
		oconf->admin_space_left = nconf->admin_space_left;
		ctx->need_space_check = 1;
	}

	// admin space left percent
	if (oconf->admin_space_left_percent != nconf->admin_space_left_percent){
		oconf->admin_space_left_percent =
					nconf->admin_space_left_percent;
		ctx->need_space_check = 1;
	}

	// admin space action
	if (oconf->admin_space_left_action != nconf->admin_space_left_action) {
		oconf->admin_space_left_action = nconf->admin_space_left_action;
		ctx->need_space_check = 1;
	}

	// admin space left exe
	if (oconf->admin_space_left_exe || nconf->admin_space_left_exe) {
		if (nconf->admin_space_left_exe == NULL)
			; /* do nothing if new one is blank */
		else if (oconf->admin_space_left_exe == NULL &&
					 nconf->admin_space_left_exe)
			ctx->need_space_check = 1;
		else if (strcmp(oconf->admin_space_left_exe,
					nconf->admin_space_left_exe))
			ctx->need_space_check = 1;
		free((char *)oconf->admin_space_left_exe);
		oconf->admin_space_left_exe = nconf->admin_space_left_exe;
	}
	// disk full action
	if (oconf->disk_full_action != nconf->disk_full_action) {
		oconf->disk_full_action = nconf->disk_full_action;
		ctx->need_space_check = 1;
	}

	// disk full exe
	if (oconf->disk_full_exe || nconf->disk_full_exe) {
		if (nconf->disk_full_exe == NULL)
			; /* do nothing if new one is blank */
		else if (oconf->disk_full_exe == NULL && nconf->disk_full_exe)
			ctx->need_space_check = 1;
		else if (strcmp(oconf->disk_full_exe, nconf->disk_full_exe))
			ctx->need_space_check = 1;
		free((char *)oconf->disk_full_exe);
		oconf->disk_full_exe = nconf->disk_full_exe;
	}

	if (ctx->need_space_check) {
		/* note save suspended flag, then do space_left. If suspended
		 * is still 0, then copy saved suspended back. This avoids
		 * having to call check_log_file_size to restore it. */
		int saved_suspend = *ctx->state.logging_suspended;

		setup_percentages(oconf, ctx->ops.get_log_fd());
		*ctx->state.fs_space_warning = 0;
		*ctx->state.fs_admin_space_warning = 0;
		*ctx->state.fs_space_left = 1;
		*ctx->state.logging_suspended = 0;
		ctx->ops.check_excess_logs();
		ctx->ops.check_space_left();
		if (*ctx->state.logging_suspended == 0)
			*ctx->state.logging_suspended = saved_suspend;
	}
}

/*
 * emit_reconfigure_event - Fill the event with the final DAEMON_CONFIG record.
 * @ctx: Reconfigure context containing sender and event information.
 *
 * Returns: None.
 */
static void emit_reconfigure_event(struct auditd_reconfigure_context *ctx)
{
	struct auditd_event *e = ctx->event;
	struct daemon_conf *nconf = e->reply.conf;
	uid_t uid = nconf->sender_uid;
	pid_t pid = nconf->sender_pid;
	const char *sender_ctx = nconf->sender_ctx;
	struct timeval tv;
	char date[40];
	unsigned int seq_num;

	srand(time(NULL));
	seq_num = rand()%10000;
	if (gettimeofday(&tv, NULL) == 0) {
		snprintf(date, sizeof(date), "audit(%lld.%03u:%u)",
			 (long long int)tv.tv_sec, (unsigned)(tv.tv_usec/1000),
			 seq_num);
	} else {
		snprintf(date, sizeof(date),
			"audit(%lld.%03d:%u)", (long long int)time(NULL),
			 0, seq_num);
	}

	e->reply.type = AUDIT_DAEMON_CONFIG;
	e->reply.len = snprintf(e->reply.msg.data, MAX_AUDIT_MESSAGE_LENGTH-2,
	"%s: op=reconfigure state=changed auid=%u pid=%d subj=%s res=success",
		date, uid, pid, sender_ctx );
	e->reply.message = e->reply.msg.data;
	free((char *)sender_ctx);
}

/*
 * auditd_reconfigure - Apply the new configuration carried by an event.
 * @ctx: Reconfigure context containing configuration, state, and callbacks.
 *
 * Returns: None.
 */
void auditd_reconfigure(struct auditd_reconfigure_context *ctx)
{
	struct daemon_conf *nconf = ctx->event->reply.conf;
	uid_t uid = nconf->sender_uid;
	pid_t pid = nconf->sender_pid;
	const char *sender_ctx = nconf->sender_ctx;
	char txt[MAX_AUDIT_MESSAGE_LENGTH];

	snprintf(txt, sizeof(txt),
		"config change requested by pid=%d auid=%u subj=%s",
		pid, uid, sender_ctx);
	audit_msg(LOG_NOTICE, "%s", txt);

	/* Do the reconfiguring. These are done in a specific
	 * order from least invasive to most invasive. We will
	 * start with general system parameters. */
	reconfigure_general_options(ctx);
	reconfigure_network_options(ctx);
	reconfigure_dispatcher_options(ctx);
	reconfigure_log_file_options(ctx);
	reconfigure_disk_space_options(ctx);
	reconfigure_dispatcher(ctx->config);
	emit_reconfigure_event(ctx);
}
