/* auditd-log.h --
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef AUDITD_LOG_H
#define AUDITD_LOG_H

#include <sys/types.h>

struct auditd_log_path {
	int dir_fd;
	char *file_name;
};

struct auditd_log_policy {
	uid_t owner;
	gid_t group;
	unsigned int num_logs;
};

int auditd_log_path_open(struct auditd_log_path *path, const char *file,
		const struct auditd_log_policy *policy);
int auditd_log_path_openat(struct auditd_log_path *path, int root_fd,
		const char *file, const struct auditd_log_policy *policy);
int auditd_log_repair_permissions(const struct auditd_log_path *path,
		const struct auditd_log_policy *policy);
void auditd_log_path_close(struct auditd_log_path *path);

#endif
