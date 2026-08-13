/* auditd-log.c --
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "auditd-log.h"

/*
 * validate_directory - verify that only the trusted owner can modify a dir
 * @dir_fd: descriptor for the directory to validate
 * @policy: ownership policy for the audit log hierarchy
 *
 * Returns 0 for a trusted directory and -1 with errno set otherwise.
 */
static int validate_directory(int dir_fd,
		const struct auditd_log_policy *policy)
{
	struct stat st;

	if (fstat(dir_fd, &st) < 0)
		return -1;
	if (!S_ISDIR(st.st_mode)) {
		errno = ENOTDIR;
		return -1;
	}
	if (st.st_uid != policy->owner ||
			(st.st_mode & (S_IWGRP|S_IWOTH))) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

/*
 * open_directory - open and validate one non-symlink directory component
 * @dir_fd: descriptor for the containing directory
 * @name: component name to open
 * @policy: ownership policy for the audit log hierarchy
 *
 * Returns an owned directory descriptor on success and -1 on failure.
 */
static int open_directory(int dir_fd, const char *name,
		const struct auditd_log_policy *policy)
{
	int fd;

	fd = openat(dir_fd, name,
		O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (validate_directory(fd, policy) < 0) {
		int saved_errno = errno;

		close(fd);
		errno = saved_errno;
		return -1;
	}
	return fd;
}

/*
 * open_trusted_directory - open a directory without following symlinks
 * @root_fd: descriptor treated as the root of the absolute path
 * @directory: directory path to resolve
 * @policy: ownership policy for every traversed component
 *
 * Returns an owned descriptor for the resolved directory or -1 on failure.
 */
static int open_trusted_directory(int root_fd, const char *directory,
		const struct auditd_log_policy *policy)
{
	char *component, *copy, *saveptr;
	int dir_fd;

	dir_fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
	if (dir_fd < 0)
		return -1;
	if (validate_directory(dir_fd, policy) < 0)
		goto bad_dir;

	copy = strdup(directory);
	if (copy == NULL)
		goto bad_dir;
	component = strtok_r(copy, "/", &saveptr);
	while (component) {
		int fd;

		/* Dot components make the configured path needlessly ambiguous. */
		if (strcmp(component, ".") == 0 ||
				strcmp(component, "..") == 0) {
			errno = EINVAL;
			goto bad_copy;
		}
		fd = open_directory(dir_fd, component, policy);
		if (fd < 0)
			goto bad_copy;
		close(dir_fd);
		dir_fd = fd;
		component = strtok_r(NULL, "/", &saveptr);
	}
	free(copy);
	return dir_fd;

bad_copy:
	{
		int saved_errno = errno;

		free(copy);
		close(dir_fd);
		errno = saved_errno;
	}
	return -1;
bad_dir:
	{
		int saved_errno = errno;

		close(dir_fd);
		errno = saved_errno;
	}
	return -1;
}

/*
 * auditd_log_path_openat - resolve an audit log beneath a supplied root
 * @path: result containing the pinned directory and log-file name
 * @root_fd: descriptor treated as the root of absolute paths
 * @file: absolute audit log path to resolve
 * @policy: ownership policy for every traversed component
 *
 * Returns 0 on success and -1 with errno set on failure.
 */
int auditd_log_path_openat(struct auditd_log_path *path, int root_fd,
		const char *file, const struct auditd_log_policy *policy)
{
	char *parent, *slash;
	int dir_fd;

	path->dir_fd = -1;
	path->file_name = NULL;
	if (file[0] != '/') {
		errno = EINVAL;
		return -1;
	}
	parent = strdup(file);
	if (parent == NULL)
		return -1;
	slash = strrchr(parent, '/');
	if (slash == NULL || slash[1] == 0 ||
			strcmp(slash + 1, ".") == 0 ||
			strcmp(slash + 1, "..") == 0) {
		free(parent);
		errno = EINVAL;
		return -1;
	}
	path->file_name = strdup(slash + 1);
	if (path->file_name == NULL) {
		free(parent);
		return -1;
	}
	if (slash == parent)
		slash[1] = 0;
	else
		*slash = 0;

	dir_fd = open_trusted_directory(root_fd, parent, policy);
	free(parent);
	if (dir_fd < 0) {
		free(path->file_name);
		path->file_name = NULL;
		return -1;
	}
	path->dir_fd = dir_fd;
	return 0;
}

/*
 * auditd_log_path_open - resolve an audit log beneath the system root
 * @path: result containing the pinned directory and log-file name
 * @file: absolute audit log path to resolve
 * @policy: ownership policy for every traversed component
 *
 * Returns 0 on success and -1 with errno set on failure.
 */
int auditd_log_path_open(struct auditd_log_path *path, const char *file,
		const struct auditd_log_policy *policy)
{
	int root_fd, rc, saved_errno;

	root_fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	if (root_fd < 0)
		return -1;
	rc = auditd_log_path_openat(path, root_fd, file, policy);
	saved_errno = errno;
	close(root_fd);
	errno = saved_errno;
	return rc;
}

/*
 * validate_log_file - require an opened historical log to be trusted
 * @fd: descriptor for the historical log
 * @policy: ownership policy for audit log objects
 *
 * Returns 0 for a trusted regular file and -1 otherwise.
 */
static int validate_log_file(int fd,
		const struct auditd_log_policy *policy)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return -1;
	if (!S_ISREG(st.st_mode) || st.st_uid != policy->owner) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

/*
 * auditd_log_repair_permissions - repair a pinned log directory and archives
 * @path: pinned audit log directory and current-log name
 * @policy: desired owner, group, and numbered-log count
 *
 * Returns 0 on success and -1 with errno set on failure.
 */
int auditd_log_repair_permissions(const struct auditd_log_path *path,
		const struct auditd_log_policy *policy)
{
	mode_t dir_mode = policy->group ? 0750 : 0700;
	mode_t log_mode = policy->group ? 0440 : 0400;
	size_t name_len;
	char *name;
	unsigned int i;

	/* Never repair a directory that was writable by an untrusted user. */
	if (validate_directory(path->dir_fd, policy) < 0)
		return -1;
	if (fchown(path->dir_fd, policy->owner, policy->group) < 0)
		return -1;
	if (fchmod(path->dir_fd, dir_mode) < 0)
		return -1;

	name_len = strlen(path->file_name) + 16;
	name = malloc(name_len);
	if (name == NULL)
		return -1;
	for (i = 1; i < policy->num_logs; i++) {
		int fd;

		snprintf(name, name_len, "%s.%u", path->file_name, i);
		fd = openat(path->dir_fd, name,
			O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
		if (fd < 0 && errno == ENOENT)
			break;
		if (fd < 0)
			goto bad;
		if (validate_log_file(fd, policy) < 0 ||
				fchmod(fd, log_mode) < 0) {
			int saved_errno = errno;

			close(fd);
			errno = saved_errno;
			goto bad;
		}
		close(fd);
	}
	free(name);
	return 0;

bad:
	{
		int saved_errno = errno;

		free(name);
		errno = saved_errno;
	}
	return -1;
}

/*
 * auditd_log_path_close - release a pinned audit log path
 * @path: path object to release
 *
 * Returns: None.
 */
void auditd_log_path_close(struct auditd_log_path *path)
{
	if (path->dir_fd >= 0)
		close(path->dir_fd);
	free(path->file_name);
	path->dir_fd = -1;
	path->file_name = NULL;
}
