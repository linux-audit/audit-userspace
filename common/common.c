/* common.c --
 * Copyright 2023 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <utmpx.h>
#include <fcntl.h>
#include <stdlib.h>	// strtol
#include <errno.h>
#include <string.h>
#include <libgen.h>     // basename
#include <signal.h>
#include <sys/wait.h>
#include "libaudit.h"
#include "private.h"    // audit_msg
#include "common.h"

/*
 * This function returns 1 if it is the last record in an event.
 * It returns 0 otherwise.
 *
 * When processing an event stream we define the end of an event via
 *  record type = AUDIT_EOE (audit end of event type record), or
 *  record type = AUDIT_PROCTITLE   (we note the AUDIT_PROCTITLE is always
 *                                    the last record), or
 *  record type = AUDIT_KERNEL (kernel events are one record events), or
 *  record type < AUDIT_FIRST_EVENT (only single record events appear
 *                                    before this type), or
 *  record type >= AUDIT_FIRST_ANOM_MSG (only single record events appear
 *                                      after this type), or
 *  record type >= AUDIT_MAC_UNLBL_ALLOW && record type <= AUDIT_MAC_CALIPSO_DEL
 *                                       (these are also one record events)
 */
int audit_is_last_record(int type)
{
	if (type == AUDIT_PROCTITLE ||
	    type == AUDIT_EOE ||
	    (type > AUDIT_LOGIN &&
	     type < AUDIT_FIRST_EVENT) ||
	    type == AUDIT_USER ||
	    type >= AUDIT_FIRST_ANOM_MSG ||
	    type == AUDIT_KERNEL ||
	    (type >= AUDIT_MAC_UNLBL_ALLOW &&
	     type <= AUDIT_MAC_CALIPSO_DEL)) {
		return 1;
	}
	return 0;
}

int write_to_console(const char *fmt, ...)
{
	int fd;
	int res = 1;
	va_list args;

	if ((fd = open("/dev/console", O_WRONLY)) < 0)
		return 0;

	va_start(args, fmt);
	if (vdprintf(fd, fmt, args) < 0)
		res = 0;

	va_end(args);
	close(fd);

	return res;
}

void wall_message(const char* format, ...)
{
	struct utmpx* entry;
	char message[512];
	va_list args;
	int fd;

	// Format the message
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);

	setutxent();

	// Send the message to all active users
	while ((entry = getutxent())) {
		// Only active users have a valid terminal
		if (entry->ut_type == USER_PROCESS) {
			char tty_path[128];
			snprintf(tty_path, sizeof(tty_path), "/dev/%s",
				 entry->ut_line);

			fd = open(tty_path, O_WRONLY | O_NOCTTY);
			if (fd != -1) {
				dprintf(fd, "\nBroadcast message from audit daemon:\n%s\n", message);
				close(fd);
			}
		}
	}

	endutxent();
}

// Returns converted time in seconds on success and -1 on failure.
long time_string_to_seconds(const char *time_string,
			    const char *subsystem, int line)
{
	char *end;
	long i;

	errno = 0;
	i = strtol(time_string, &end, 10);
	if (errno || time_string == end) {
		if (subsystem)
			syslog(LOG_ERR,
			       "%s: Error converting %s to a number - line %d",
			       subsystem, time_string, line);
		return -1;
	}

	if (*end && end[1]) {
		if (subsystem)
			syslog(LOG_ERR,
			       "%s: Unexpected characters in %s - line %d",
			       subsystem, time_string, line);
		return -1;
	}
	switch (*end) {
	case 'm':
		i *= MINUTES;
		break;
	case 'h':
		i *= HOURS;
		break;
	case 'd':
		i *= DAYS;
		break;
	case 'M':
		i *= MONTHS;
		break;
	case '\0':
		break;
	default:
		if (subsystem)
			syslog(LOG_ERR,
			       "%s: Unknown time unit in %s - line %d",
			       subsystem, time_string, line);
		return -1;
	}
	return i;
}

const char *get_progname(void)
{
	static char progname[256];
	if (progname[0] == 0) {
		char tname[256];
		ssize_t len = readlink("/proc/self/exe",tname,sizeof(tname)-1);
		if (len != -1) {
			tname[len] = '\0';
			strcpy(progname, basename(progname));
		} else
			strcpy(progname, "unknown");
	}
	return progname;
}

const char *SINGLE = "1";
const char *HALT = "0";
void change_runlevel(const char *level)
{
	char *argv[3];
	int pid;
	struct sigaction sa;
	static const char *init_pgm = "/sbin/init";

	// In case of halt, we need to log the message before we halt
	if (strcmp(level, HALT) == 0) {
		write_to_console("%s: will try to change runlevel to %s\n",
				 get_progname(), level);
	}

	pid = fork();
	if (pid < 0) {
		audit_msg(LOG_ALERT,
			  "%s failed to fork switching runlevels",
			  get_progname());
		return;
	}
	if (pid) {      /* Parent */
		int status;

		// Wait until child exits
		if (waitpid(pid, &status, 0) < 0) {
			audit_msg(LOG_ALERT,
				  "%s failed to wait for child",get_progname());
			return;
		}
		// If child exited normally, runlevel change was successful
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			write_to_console("%s: changed runlevel to %s\n",
					 get_progname(), level);
		}

		return;
	}
	/* Child */
	sigfillset (&sa.sa_mask);
	sigprocmask (SIG_UNBLOCK, &sa.sa_mask, 0);

	argv[0] = (char *)init_pgm;
	argv[1] = (char *)level;
	argv[2] = NULL;
	execve(init_pgm, argv, NULL);
	audit_msg(LOG_ALERT, "%s failed to exec %s", get_progname(), init_pgm);
	exit(1);
}

