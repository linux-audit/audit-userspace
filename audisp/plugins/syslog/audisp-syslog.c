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

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static int priority;

/* Local declarations */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

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

static int init_syslog(int argc, char *argv[])
{
	int i, facility = LOG_USER;
	priority = LOG_INFO;

	for (i = 1; i < argc; i++) {
		if (argv[i]) {
			if (strcasecmp(conf->args[i], "LOG_DEBUG") == 0)
				priority = LOG_DEBUG;
			else if (strcasecmp(conf->args[i], "LOG_INFO") == 0)
				priority = LOG_INFO;
			else if (strcasecmp(conf->args[i], "LOG_NOTICE") == 0)
				priority = LOG_NOTICE;
			else if (strcasecmp(conf->args[i], "LOG_WARNING") == 0)
				priority = LOG_WARNING;
			else if (strcasecmp(conf->args[i], "LOG_ERR") == 0)
				priority = LOG_ERR;
			else if (strcasecmp(conf->args[i], "LOG_CRIT") == 0)
				priority = LOG_CRIT;
			else if (strcasecmp(conf->args[i], "LOG_ALERT") == 0)
				priority = LOG_ALERT;
			else if (strcasecmp(conf->args[i], "LOG_EMERG") == 0)
				priority = LOG_EMERG;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL0") == 0)
				facility = LOG_LOCAL0;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL1") == 0)
				facility = LOG_LOCAL1;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL2") == 0)
				facility = LOG_LOCAL2;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL3") == 0)
				facility = LOG_LOCAL3;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL4") == 0)
				facility = LOG_LOCAL4;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL5") == 0)
				facility = LOG_LOCAL5;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL6") == 0)
				facility = LOG_LOCAL6;
			else if (strcasecmp(conf->args[i], "LOG_LOCAL7") == 0)
				facility = LOG_LOCAL7;
			else if (strcasecmp(conf->args[i], "LOG_AUTH") == 0)
				facility = LOG_AUTH;
			else if (strcasecmp(conf->args[i], "LOG_AUTHPRIV") == 0)
				facility = LOG_AUTHPRIV;
			else if (strcasecmp(conf->args[i], "LOG_DAEMON") == 0)
				facility = LOG_DAEMON;
			else if (strcasecmp(conf->args[i], "LOG_SYSLOG") == 0)
				facility = LOG_SYSLOG;
			else if (strcasecmp(conf->args[i], "LOG_USER") == 0)
				facility = LOG_USER;
			else {
				syslog(LOG_ERR,
					"Unknown log priority/facility %s",
					conf->args[i]);
				return 1;
			}
		}
	}
	syslog(LOG_INFO, "syslog plugin initialized");
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

	if (init_syslog(int argc, char *argv[]))
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
		struct timeval tv;
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
		if (audit_fgets_feof(stdin))
			break;
	} while (stop == 0);

	if (stop)
		printf("audisp-syslog is exiting on stop request\n");
	else
		printf("audisp-syslog is exiting on stdin EOF\n");

	return 0;
}

/* This function shows how to dump a whole event by iterating over records */
static void dump_whole_event(auparse_state_t *au)
{
	auparse_first_record(au);
	do {
		printf("%s\n", auparse_get_record_text(au));
	} while (auparse_next_record(au) > 0);
	printf("\n");
}

/* This function shows how to dump a whole record's text */
static void dump_whole_record(auparse_state_t *au)
{
	printf("%s: %s\n", audit_msg_type_to_name(auparse_get_type(au)),
		auparse_get_record_text(au));
	printf("\n");
}

/* This function shows how to iterate through the fields of a record
 * and print its name and raw value and interpretted value. */
static void dump_fields_of_record(auparse_state_t *au)
{
	printf("record type %d(%s) has %d fields\n", auparse_get_type(au),
		audit_msg_type_to_name(auparse_get_type(au)),
		auparse_get_num_fields(au));

	printf("line=%d file=%s\n", auparse_get_line_number(au),
		auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");

	const au_event_t *e = auparse_get_timestamp(au);
	if (e == NULL) {
		printf("Error getting timestamp - aborting\n");
		return;
	}
	/* Note that e->sec can be treated as time_t data if you want
	 * something a little more readable */
	printf("event time: %u.%u:%lu, host=%s\n", (unsigned)e->sec,
		e->milli, e->serial, e->host ? e->host : "?");
		auparse_first_field(au);

	do {
		printf("field: %s=%s (%s)\n",
		auparse_get_field_name(au),
		auparse_get_field_str(au),
		auparse_interpret_field(au));
	} while (auparse_next_field(au) > 0);
	printf("\n");
}

/* This function receives a single complete event at a time from the auparse
 * library. This is where the main analysis code would be added. */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, num=0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	/* Loop through the records in the event looking for one to process.
	   We use physical record number because we may search around and
	   move the cursor accidentally skipping a record. */
	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		/* Now we can branch based on what record type we find.
		   This is just a few suggestions, but it could be anything. */
		switch (type) {
			case AUDIT_AVC:
				dump_fields_of_record(au);
				break;
			case AUDIT_SYSCALL:
				dump_whole_record(au); 
				break;
			case AUDIT_USER_LOGIN:
				break;
			case AUDIT_ANOM_ABEND:
				break;
			case AUDIT_MAC_STATUS:
				dump_whole_event(au); 
				break;
			default:
				break;
		}
		num++;
	}
}

