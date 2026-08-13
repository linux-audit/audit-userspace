/* auditd_log_test.c - audit log path permission tests
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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "auditd-log.h"

/*
 * make_path - construct a path within the disposable test root
 * @path: output buffer
 * @size: size of the output buffer
 * @root: test-root pathname
 * @suffix: path relative to the test root
 *
 * Returns: None. The test aborts if the path does not fit.
 */
static void make_path(char *path, size_t size, const char *root,
		const char *suffix)
{
	int rc = snprintf(path, size, "%s/%s", root, suffix);

	assert(rc > 0 && (size_t)rc < size);
}

/*
 * make_directory - create one test directory with an exact mode
 * @path: directory pathname
 * @mode: directory mode
 *
 * Returns: None. The test aborts on failure.
 */
static void make_directory(const char *path, mode_t mode)
{
	assert(mkdir(path, mode) == 0);
	assert(chmod(path, mode) == 0);
}

/*
 * make_file - create one disposable regular file with an exact mode
 * @path: file pathname
 * @mode: file mode
 *
 * Returns: None. The test aborts on failure.
 */
static void make_file(const char *path, mode_t mode)
{
	int fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, mode);

	assert(fd >= 0);
	assert(close(fd) == 0);
	assert(chmod(path, mode) == 0);
}

/*
 * object_mode - read the permission bits for one test object
 * @path: object pathname
 *
 * Returns the permission bits. The test aborts on failure.
 */
static mode_t object_mode(const char *path)
{
	struct stat st;

	assert(stat(path, &st) == 0);
	return st.st_mode & 0777;
}

/*
 * object_group - read the group owner for one test object
 * @path: object pathname
 *
 * Returns the group ID. The test aborts on failure.
 */
static gid_t object_group(const char *path)
{
	struct stat st;

	assert(stat(path, &st) == 0);
	return st.st_gid;
}

/*
 * setup_tree - create the trusted and untrusted path test fixtures
 * @root: disposable test-root pathname
 *
 * Returns: None. The test aborts on failure.
 */
static void setup_tree(const char *root)
{
	char path[PATH_MAX];

	make_path(path, sizeof(path), root, "trusted");
	make_directory(path, 0700);
	make_path(path, sizeof(path), root, "trusted/log-dir");
	make_directory(path, 0700);
	make_path(path, sizeof(path), root, "trusted/victim-dir");
	make_directory(path, 0700);
	make_path(path, sizeof(path), root, "trusted/log-link");
	assert(symlink("/trusted/log-dir", path) == 0);

	make_path(path, sizeof(path), root, "unsafe");
	make_directory(path, 0770);
	make_path(path, sizeof(path), root, "unsafe/log-dir");
	make_directory(path, 0700);
}

/*
 * test_group_repair_and_leaf_symlinks - verify legitimate repair behavior
 * @root: disposable test-root pathname
 * @root_fd: descriptor treated as the test resolution root
 * @policy: ownership and mode policy for the test
 *
 * Returns: None. The test aborts on failure.
 */
static void test_group_repair_and_leaf_symlinks(const char *root,
		int root_fd, const struct auditd_log_policy *policy)
{
	struct auditd_log_path log_path;
	char archive[PATH_MAX], skipped[PATH_MAX], current[PATH_MAX];
	char victim[PATH_MAX], numbered_link[PATH_MAX];

	make_path(archive, sizeof(archive), root,
		"trusted/log-dir/audit.log.1");
	make_file(archive, 0600);
	make_path(skipped, sizeof(skipped), root,
		"trusted/log-dir/audit.log.3");
	make_file(skipped, 0600);
	make_path(current, sizeof(current), root,
		"trusted/log-dir/audit.log");
	make_path(victim, sizeof(victim), root, "trusted/current-victim");
	make_file(victim, 0666);
	assert(symlink("../current-victim", current) == 0);

	assert(auditd_log_path_openat(&log_path, root_fd,
		"/trusted/log-dir/audit.log", policy) == 0);
	assert(auditd_log_repair_permissions(&log_path, policy) == 0);
	errno = 0;
	assert(openat(log_path.dir_fd, log_path.file_name,
		O_WRONLY|O_NOFOLLOW|O_CLOEXEC) == -1);
	assert(errno == ELOOP);
	auditd_log_path_close(&log_path);
	make_path(current, sizeof(current), root, "trusted/log-dir");
	assert(object_mode(current) == 0750);
	assert(object_group(current) == policy->group);
	assert(object_mode(archive) == 0440);
	assert(object_mode(skipped) == 0600);
	assert(object_mode(victim) == 0666);

	assert(unlink(archive) == 0);
	make_path(numbered_link, sizeof(numbered_link), root,
		"trusted/log-dir/audit.log.1");
	make_path(victim, sizeof(victim), root, "trusted/numbered-victim");
	make_file(victim, 0666);
	assert(symlink("../numbered-victim", numbered_link) == 0);
	assert(auditd_log_path_openat(&log_path, root_fd,
		"/trusted/log-dir/audit.log", policy) == 0);
	errno = 0;
	assert(auditd_log_repair_permissions(&log_path, policy) == -1);
	assert(errno == ELOOP);
	auditd_log_path_close(&log_path);
	assert(object_mode(victim) == 0666);
}

/*
 * test_untrusted_components_are_rejected - reject writable and symlink paths
 * @root: disposable test-root pathname
 * @root_fd: descriptor treated as the test resolution root
 * @policy: ownership policy for the test
 *
 * Returns: None. The test aborts on failure.
 */
static void test_untrusted_components_are_rejected(const char *root,
		int root_fd, const struct auditd_log_policy *policy)
{
	struct auditd_log_path log_path;
	char victim[PATH_MAX];

	make_path(victim, sizeof(victim), root, "trusted/victim-dir");
	errno = 0;
	assert(auditd_log_path_openat(&log_path, root_fd,
		"/unsafe/log-dir/audit.log", policy) == -1);
	assert(errno == EPERM);
	assert(object_mode(victim) == 0700);

	errno = 0;
	assert(auditd_log_path_openat(&log_path, root_fd,
		"/trusted/log-link/audit.log", policy) == -1);
	assert(object_mode(victim) == 0700);
}

/*
 * cleanup_tree - remove every disposable test fixture
 * @root: disposable test-root pathname
 *
 * Returns: None. The test aborts on failure.
 */
static void cleanup_tree(const char *root)
{
	static const char *files[] = {
		"trusted/log-dir/audit.log",
		"trusted/log-dir/audit.log.1",
		"trusted/log-dir/audit.log.3",
		"trusted/current-victim",
		"trusted/numbered-victim",
		"trusted/log-link",
		NULL,
	};
	char path[PATH_MAX];
	unsigned int i;

	for (i = 0; files[i]; i++) {
		make_path(path, sizeof(path), root, files[i]);
		assert(unlink(path) == 0);
	}
	make_path(path, sizeof(path), root, "trusted/log-dir");
	assert(rmdir(path) == 0);
	make_path(path, sizeof(path), root, "trusted/victim-dir");
	assert(rmdir(path) == 0);
	make_path(path, sizeof(path), root, "trusted");
	assert(rmdir(path) == 0);
	make_path(path, sizeof(path), root, "unsafe/log-dir");
	assert(rmdir(path) == 0);
	make_path(path, sizeof(path), root, "unsafe");
	assert(rmdir(path) == 0);
	assert(rmdir(root) == 0);
}

/*
 * main - run audit log path permission regression coverage
 *
 * Returns EXIT_SUCCESS when every assertion passes.
 */
int main(void)
{
	struct auditd_log_policy policy = {
		.owner = geteuid(),
		.group = geteuid() == 0 ? 1 : getegid(),
		.num_logs = 4,
	};
	char root[] = "auditd-log-test-XXXXXX";
	int root_fd;

	assert(mkdtemp(root) != NULL);
	assert(chmod(root, 0700) == 0);
	root_fd = open(root, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
	assert(root_fd >= 0);
	setup_tree(root);
	test_untrusted_components_are_rejected(root, root_fd, &policy);
	test_group_repair_and_leaf_symlinks(root, root_fd, &policy);
	assert(close(root_fd) == 0);
	cleanup_tree(root);
	return EXIT_SUCCESS;
}
