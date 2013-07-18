/* auditd-dispatch.c -- 
 * Copyright 2005-07,2013 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Junji Kanemaru <junji.kanemaru@linuon.com>
 */

#include "config.h"
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "libaudit.h"
#include "private.h"
#include "auditd-dispatch.h"

/* This is the communications channel between auditd & the dispatcher */
static int disp_pipe[2] = {-1, -1};
static pid_t pid = 0;
static int n_errs = 0;
#define REPORT_LIMIT 10

int dispatcher_pid(void)
{
	return pid;
}

void dispatcher_reaped(void)
{
	audit_msg(LOG_INFO, "dispatcher %d reaped\n", pid);
	pid = 0;
	shutdown_dispatcher();
}

/* set_flags: to set flags to file desc */
static int set_flags(int fn, int flags)
{
	int fl;

	if ((fl = fcntl(fn, F_GETFL, 0)) < 0) {
		audit_msg(LOG_ERR, "fcntl failed. Cannot get flags (%s)\n", 
			strerror(errno));
		return fl;
	}

	fl |= flags;

	return fcntl(fn, F_SETFL, fl);
}

/* This function returns 1 on error & 0 on success */
int init_dispatcher(const struct daemon_conf *config)
{
	struct sigaction sa;

	if (config->dispatcher == NULL) 
		return 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, disp_pipe)) {
		audit_msg(LOG_ERR, "Failed creating disp_pipe");
		return 1;
	}

	/* Make both disp_pipe non-blocking */
	if (config->qos == QOS_NON_BLOCKING) {
		if (set_flags(disp_pipe[0], O_NONBLOCK) < 0 ||
			set_flags(disp_pipe[1], O_NONBLOCK) < 0) {
			audit_msg(LOG_ERR, "Failed to set O_NONBLOCK flag");
			return 1;
		}
	}

	// do the fork
	pid = fork();
	switch(pid) {
		case 0:	// child
			dup2(disp_pipe[0], 0);
			close(disp_pipe[0]);
			close(disp_pipe[1]);
			sigfillset (&sa.sa_mask);
			sigprocmask (SIG_UNBLOCK, &sa.sa_mask, 0);
			setsid();
			execl(config->dispatcher, config->dispatcher, NULL);
			audit_msg(LOG_ERR, "exec() failed");
			exit(1);
			break;
		case -1:	// error
			return 1;
			break;
		default:	// parent
			close(disp_pipe[0]);
			disp_pipe[0] = -1;
			/* Avoid leaking this */
			if (fcntl(disp_pipe[1], F_SETFD, FD_CLOEXEC) < 0) {
				audit_msg(LOG_ERR,
					"Failed to set FD_CLOEXEC flag");
				return 1;
			}
			audit_msg(LOG_INFO, "Started dispatcher: %s pid: %u",
					config->dispatcher, pid);
			break;
	}

	return 0;
}

void shutdown_dispatcher(void)
{
	// kill child
	if (pid)
		kill(pid, SIGTERM);
	// wait for term
	// if not in time, send sigkill
	pid = 0;

	// cleanup comm pipe
	if (disp_pipe[0] >= 0) {
		close(disp_pipe[0]);
		disp_pipe[0] = -1;
	}
	if (disp_pipe[1] >= 0) {
		close(disp_pipe[1]);
		disp_pipe[1] = -1;
	}
}

void reconfigure_dispatcher(const struct daemon_conf *config)
{
	// signal child or start it so it can see if config changed
	if (pid)
		kill(pid, SIGHUP);
	else
		init_dispatcher(config);
}

/* Returns -1 on err, 0 on success, and 1 if eagain occurred and not an err */
int dispatch_event(const struct audit_reply *rep, int is_err)
{
	int rc, count = 0;
	struct iovec vec[2];
	struct audit_dispatcher_header hdr;

	if (disp_pipe[1] == -1)
		return 0;

	// Don't send reconfig or rotate as they are purely internal to daemon
	if (rep->type == AUDIT_DAEMON_RECONFIG ||
					rep->type == AUDIT_DAEMON_ROTATE)
		return 0;

	hdr.ver = AUDISP_PROTOCOL_VER; /* Hard-coded to current protocol */
	hdr.hlen = sizeof(struct audit_dispatcher_header);
	hdr.type = rep->type;
	hdr.size = rep->len;

	vec[0].iov_base = (void*)&hdr;
	vec[0].iov_len = sizeof(hdr);
	vec[1].iov_base = (void*)rep->message;
	vec[1].iov_len = rep->len;

	do {
		rc = writev(disp_pipe[1], vec, 2);
	} while (rc < 0 && errno == EAGAIN && count++ < 8);

	// close pipe if no child or peer has been lost
	if (rc <= 0) {
		if (errno == EPIPE) {
			shutdown_dispatcher();
			n_errs = 0;
		} else if (errno == EAGAIN && !is_err) {
			return 1;
		} else {
			if (n_errs <= REPORT_LIMIT) {
				audit_msg(LOG_ERR, 
					"dispatch err (%s) event lost",
					errno == EAGAIN ? "pipe full" :
					strerror(errno));
				n_errs++;
			}
			if (n_errs == REPORT_LIMIT) {
				audit_msg(LOG_ERR, 
					"dispatch error reporting limit"
					" reached - ending report"
					" notification.");
				n_errs++;
			}
			return -1;
		}
	} else
		n_errs = 0;
	return 0;
}

