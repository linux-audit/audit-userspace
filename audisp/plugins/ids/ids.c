/* ids.c --
 * Copyright 202-23 Steve Grubb.
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
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h> // umask
#include <unistd.h>
#include <sys/timerfd.h>
#include "auparse.h"
#include "common.h"
#include "ids.h"
#include "ids_config.h"
#include "origin.h"
#include "account.h"
#include "session.h"
#include "model_bad_event.h"
#include "model_behavior.h"
#include "timer-services.h"

/* Global Data */
int debug = 1;
// mode 3 == file, mode 2 == syslog, 1 == stderr, 0 == nothing
int mode = 0;

/* Local Data */
static FILE *l = NULL;	// Log file
static volatile int stop = 0;
static volatile int hup = 0;
static volatile int dump_state = 0;
static auparse_state_t *au = NULL;
#define NO_ACTIONS (!hup && !stop && !dump_state)
#define STATE_FILE "/var/run/ids-state"
#define TIMER_INTERVAL 30	// Run every 30 seconds
static struct ids_conf config;

/* Local declarations */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

void my_printf(const char *fmt, ...)
{
	va_list   ap;

	va_start(ap, fmt);
	if (mode == 2)
		vsyslog(LOG_WARNING, fmt, ap);
	else if (mode == 1) {
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	} else if (mode == 3) {
		if (l == NULL) {
			l = fopen("/var/run/audisp-ids.log", "wt");
			if (l == NULL) {
				va_end(ap);
				return;
			}
			setlinebuf(l);
		}
		vfprintf(l, fmt, ap);
		fputc('\n', l);
	}
	va_end(ap);
}

static int audit_fd = -1;
static void init_audit(void)
{
	audit_fd = audit_open();
	if (audit_fd < 0) {
		syslog(LOG_ERR, "Cannot open audit connection");
		exit(1);
	}
}


static void destroy_audit(void)
{
	audit_close(audit_fd);
}


int log_audit_event(int type, const char *text, int res)
{
	return audit_log_user_message(audit_fd, type, text,
				      NULL, NULL, NULL, res);
}


/*
 * SIGTERM handler
 */
static void term_handler(int sig __attribute__((unused)))
{
        stop = 1;
}


static void child_handler(int sig __attribute__((unused)))
{
	int status;
	while (waitpid(-1, &status, WNOHANG)>0)
		; /* empty */
}


/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig __attribute__((unused)))
{
        hup = 1;
}


static void reload_config(void)
{
	hup = 0;
	free_config(&config);
	load_config(&config);
}


static void sigusr1_handler(int sig __attribute__((unused)))
{
	dump_state = 1;
}


static void output_state(void)
{
	FILE *f = fopen(STATE_FILE, "wt");
	dump_state = 0;
	if (f) {
		char *metrics = auparse_metrics(au);
		if (metrics) {
			fprintf(f, "auparse\n=======\n");
			fprintf(f, "%s\n\n", metrics);
			free(metrics);
		}
		traverse_origins(f);
		fprintf(f, "\n");
		traverse_accounts(f);
		fprintf(f, "\n");
		traverse_sessions(f);
		dump_config(&config, f);
		fclose(f);
	}
}


int main(void)
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;
	struct itimerspec itval;
	int tfd;
	fd_set read_mask;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = sigusr1_handler;
	sigaction(SIGUSR1, &sa, NULL);
	(void) umask(0177);

	if (load_config(&config))
		return 1;

	init_audit();

	// Initialize the model
	init_origins();
	init_accounts();
	init_sessions();

	/* Initialize the auparse library */
	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		my_printf("ids is exiting due to auparse init errors");
		return -1;
	}
	auparse_set_eoe_timeout(2);
	auparse_add_callback(au, handle_event, NULL, NULL);

	init_timer_services();
	tfd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
	if (tfd < 0) {
		my_printf("ids is exiting due to timerfd_create failing");
		return -1;
	}
	itval.it_interval.tv_sec = TIMER_INTERVAL;
	itval.it_interval.tv_nsec = 0;
	itval.it_value.tv_sec = itval.it_interval.tv_sec;
	itval.it_value.tv_nsec = 0;
	timerfd_settime(tfd, 0, &itval, NULL);

	do {
		int retval;

		/* Handle dump_state */
		if (dump_state)
			output_state();

		/* Load configuration */
		if (hup)
			reload_config();

		/* Probably not needed, but maybe reload took some time?  */
		if (stop)
			break;

		do {
			FD_ZERO(&read_mask);
			FD_SET(0, &read_mask);
			FD_SET(tfd, &read_mask);

			if (auparse_feed_has_data(au)) {
				// We'll do a 1 second timeout to try to
				// age events as quick as possible
				struct timeval tv;
				tv.tv_sec = 1;
				tv.tv_usec = 0;
				//my_printf("auparse_feed_has_data");
				retval= select(tfd+1, &read_mask,
					       NULL, NULL, &tv);
			} else
				retval= select(tfd+1, &read_mask,
					       NULL, NULL, NULL);

			/* If we timed out & have events, shake them loose */
			if (retval == 0 && auparse_feed_has_data(au)) {
				//my_printf("auparse_feed_age_events");
				auparse_feed_age_events(au);
			}
		} while (retval == -1 && errno == EINTR && NO_ACTIONS);

		/* Now the event loop */
		 if (NO_ACTIONS && retval > 0) {
			if (FD_ISSET(0, &read_mask)) {
				do {
					int len;
					if ((len = audit_fgets(tmp,
						MAX_AUDIT_MESSAGE_LENGTH,
								0)) > 0) {
					/*	char *buf = strndup(tmp, 40);
					     my_printf("auparse_feed %s", buf);
						free(buf); */
						auparse_feed(au, tmp, len);
					}
				} while (audit_fgets_more(
						MAX_AUDIT_MESSAGE_LENGTH));
			}
			if (FD_ISSET(tfd, &read_mask)) {
				unsigned long long missed;
				//my_printf("do_timer_services");
				do_timer_services(TIMER_INTERVAL);
				missed=read(tfd, &missed, sizeof (missed));
			}

		}
		if (audit_fgets_eof())
			break;
	} while (stop == 0);

	shutdown_timer_services();
	close(tfd);

	/* Flush any accumulated events from queue */
	auparse_flush_feed(au);
	auparse_destroy(au);
	destroy_sessions();
	destroy_accounts();
	destroy_origins();
	destroy_audit();
	free_config(&config);

	if (stop)
		my_printf("ids is exiting on stop request");
	else
		my_printf("ids is exiting on stdin EOF");

	if (l)
		fclose(l);

	return 0;
}


/* This function receives a single complete event from the auparse library. */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type,
		void *user_data __attribute__((unused)))
{
	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	//my_printf("handle_event %s", auparse_get_type_name(au));

	/* Do this once for all models */
	if (auparse_normalize(au, NORM_OPT_NO_ATTRS))
		my_printf("Error normalizing %s", auparse_get_type_name(au));

	/* Check for events that are known bad */
	process_bad_event_model(au, &config);

	/* Check if user doing something strange */
	process_behavior_model(au, &config);
}

