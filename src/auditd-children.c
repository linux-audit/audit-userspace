/* auditd-children.c -- exact-PID reaping for auditd helper processes
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * auditd must not use waitpid(-1) because that can reap a dispatcher plugin
 * and make its configured PID reusable before the dispatcher clears it.
 * Register action and mail helpers here so auditd can reap only the children
 * it owns, leaving plugin reaping entirely to the dispatcher thread.
 */

#include "config.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "auditd-children.h"

struct auditd_child {
	pid_t pid;
	auditd_child_callback callback;
	struct auditd_child *next;
};

static struct auditd_child *children;

/*
 * Fork and register an auditd-owned helper before SIGCHLD can reap it.
 * @callback: optional function to call in the parent after the child exits
 *
 * Returns the child PID to the parent, 0 to the child, and -1 on failure.
 * Registration and reaping both run on auditd's libev thread, so the child
 * list does not require cross-thread synchronization.
 */
pid_t auditd_fork_child(auditd_child_callback callback)
{
	struct auditd_child *child;
	pid_t pid;

	child = malloc(sizeof(*child));
	if (child == NULL)
		return -1;

	pid = fork();
	if (pid > 0) {
		child->pid = pid;
		child->callback = callback;
		child->next = children;
		children = child;
		return pid;
	}
	if (pid < 0) {
		int saved_errno = errno;

		free(child);
		errno = saved_errno;
	}
	return pid;
}

/*
 * Reap every exited helper registered with auditd_fork_child().
 * Returns nothing. Completion callbacks run after removing the list entry.
 */
void auditd_reap_children(void)
{
	struct auditd_child **link = &children;

	while (*link) {
		auditd_child_callback callback;
		struct auditd_child *child = *link;
		pid_t rc;

		do {
			rc = waitpid(child->pid, NULL, WNOHANG);
		} while (rc < 0 && errno == EINTR);
		if (rc != child->pid && !(rc < 0 && errno == ECHILD)) {
			link = &child->next;
			continue;
		}

		*link = child->next;
		callback = child->callback;
		free(child);
		if (callback)
			callback();
	}
}
