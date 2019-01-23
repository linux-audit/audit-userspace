/* audisp-syslog.c --
 * Copyright 2018 Red Hat Inc., Durham, North Carolina.
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
 *
 */

#include "config.h"
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include <syslog.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "common.h"

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static int priority;

/*
 * SIGTERM handler
 */
static void term_handler( int sig )
{
        stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler( int sig )
{
        hup = 1;
}

static void reload_config(void)
{
	hup = 0;
}

static int init_syslog(int argc, const char *argv[])
{
	int i, facility = LOG_USER;
	priority = LOG_INFO;

	for (i = 1; i < argc; i++) {
		if (argv[i]) {
			if (strcasecmp(argv[i], "LOG_DEBUG") == 0)
				priority = LOG_DEBUG;
			else if (strcasecmp(argv[i], "LOG_INFO") == 0)
				priority = LOG_INFO;
			else if (strcasecmp(argv[i], "LOG_NOTICE") == 0)
				priority = LOG_NOTICE;
			else if (strcasecmp(argv[i], "LOG_WARNING") == 0)
				priority = LOG_WARNING;
			else if (strcasecmp(argv[i], "LOG_ERR") == 0)
				priority = LOG_ERR;
			else if (strcasecmp(argv[i], "LOG_CRIT") == 0)
				priority = LOG_CRIT;
			else if (strcasecmp(argv[i], "LOG_ALERT") == 0)
				priority = LOG_ALERT;
			else if (strcasecmp(argv[i], "LOG_EMERG") == 0)
				priority = LOG_EMERG;
			else if (strcasecmp(argv[i], "LOG_LOCAL0") == 0)
				facility = LOG_LOCAL0;
			else if (strcasecmp(argv[i], "LOG_LOCAL1") == 0)
				facility = LOG_LOCAL1;
			else if (strcasecmp(argv[i], "LOG_LOCAL2") == 0)
				facility = LOG_LOCAL2;
			else if (strcasecmp(argv[i], "LOG_LOCAL3") == 0)
				facility = LOG_LOCAL3;
			else if (strcasecmp(argv[i], "LOG_LOCAL4") == 0)
				facility = LOG_LOCAL4;
			else if (strcasecmp(argv[i], "LOG_LOCAL5") == 0)
				facility = LOG_LOCAL5;
			else if (strcasecmp(argv[i], "LOG_LOCAL6") == 0)
				facility = LOG_LOCAL6;
			else if (strcasecmp(argv[i], "LOG_LOCAL7") == 0)
				facility = LOG_LOCAL7;
			else if (strcasecmp(argv[i], "LOG_AUTH") == 0)
				facility = LOG_AUTH;
			else if (strcasecmp(argv[i], "LOG_AUTHPRIV") == 0)
				facility = LOG_AUTHPRIV;
			else if (strcasecmp(argv[i], "LOG_DAEMON") == 0)
				facility = LOG_DAEMON;
			else if (strcasecmp(argv[i], "LOG_SYSLOG") == 0)
				facility = LOG_SYSLOG;
			else if (strcasecmp(argv[i], "LOG_USER") == 0)
				facility = LOG_USER;
			else {
				syslog(LOG_ERR,
					"Unknown log priority/facility %s",
					argv[i]);
				return 1;
			}
		}
	}
	syslog(LOG_INFO,
		"syslog plugin initialized with facility %d and priority %d",
		facility, priority);
	if (facility != LOG_USER)
		openlog("audispd", 0, facility);
	return 0;
}

static inline void write_syslog(char *s)
{
	char *c = strchr(s, AUDIT_INTERP_SEPARATOR);
	if (c)
		*c = ' ';
	syslog(priority, "%s", s);
}

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;

	if (init_syslog(argc, argv))
		return 1;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
	capng_clear(CAPNG_SELECT_BOTH);
        capng_apply(CAPNG_SELECT_BOTH);
#endif

	do {
		fd_set read_mask;
		int retval = -1;

		/* Load configuration */
		if (hup) {
			reload_config();
		}
		do {
			FD_ZERO(&read_mask);
			FD_SET(0, &read_mask);
			retval= select(1, &read_mask, NULL, NULL, NULL);
		} while (retval == -1 && errno == EINTR && !hup && !stop);

		/* Now the event loop */
		 if (!stop && !hup && retval > 0) {
			if (FD_ISSET(0, &read_mask)) {
				do {
					if (audit_fgets(tmp,
					    MAX_AUDIT_MESSAGE_LENGTH, 0))
						write_syslog(tmp);
				} while (audit_fgets_more(
						MAX_AUDIT_MESSAGE_LENGTH));
			}
		}
		if (audit_fgets_eof())
			break;
	} while (stop == 0);

	return 0;
}

