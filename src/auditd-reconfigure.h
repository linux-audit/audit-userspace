/* auditd-reconfigure.h --
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef AUDITD_RECONFIGURE_H
#define AUDITD_RECONFIGURE_H

#include <stdio.h>
#include "auditd-event.h"

struct auditd_reconfigure_state {
	FILE **log_file;
	unsigned int *disk_err_warning;
	int *fs_space_warning;
	int *fs_admin_space_warning;
	int *fs_space_left;
	int *logging_suspended;
};

struct auditd_reconfigure_ops {
	void (*check_log_file_size)(void);
	void (*check_space_left)(void);
	int (*fix_disk_permissions)(void);
	void (*check_excess_logs)(void);
	void (*do_disk_error_action)(const char *func, int err);
	int (*open_audit_log)(void);
	int (*get_log_fd)(void);
};

struct auditd_reconfigure_context {
	struct auditd_event *event;
	struct daemon_conf *config;
	struct auditd_reconfigure_state state;
	struct auditd_reconfigure_ops ops;
	int need_size_check;
	int need_reopen;
	int need_space_check;
};

void auditd_reconfigure(struct auditd_reconfigure_context *ctx);

#endif
