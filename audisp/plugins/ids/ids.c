/* ids.c --
 * Copyright 202-25 Steve Grubb.
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
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h> // umask
#include <unistd.h>
#include "auparse.h"
#include "libaudit.h"
#include "auplugin.h"
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
volatile int hup = 0;
volatile int dump_state = 0;
static auparse_state_t *au = NULL;
#define NO_ACTIONS (!hup && !stop && !dump_state)
#define STATE_FILE AUDIT_RUN_DIR"/ids-state"
#define TIMER_INTERVAL 30	// Run every 30 seconds
struct ids_conf config;

/* Local declarations */
static void handle_event(auparse_state_t *p,
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
			l = fopen(AUDIT_RUN_DIR"/audisp-ids.log", "w");
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
 *
 * Only honor the signal if it comes from the parent process so that other
 * tasks (cough, systemctl, cough) can't make the plugin exit without
 * the dispatcher in agreement. Otherwise it will restart the plugin.
 */
static void term_handler(int sig __attribute__((unused)), siginfo_t *info, void *ucontext)
{
	if (info && info->si_pid != getppid())
		return;
        stop = 1;
	auplugin_stop();
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


void reload_config(void)
{
	hup = 0;
	free_config(&config);
	load_config(&config);
}


static void sigusr1_handler(int sig __attribute__((unused)))
{
	dump_state = 1;
}


void output_state(void)
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
	struct sigaction sa;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = sigusr1_handler;
	sigaction(SIGUSR1, &sa, NULL);
	sa.sa_sigaction = term_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGTERM, &sa, NULL);
	(void) umask(0177);

	if (load_config(&config))
		return 1;

	init_audit();

	// Initialize the model
	init_origins();
	init_accounts();
	init_sessions();

	if (auplugin_init(0, 128, AUPLUGIN_Q_IN_MEMORY, NULL))
		return -1;

	auplugin_event_feed(handle_event, TIMER_INTERVAL, do_timer_services);

	shutdown_timer_services();

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
static void handle_event(auparse_state_t *p,
		auparse_cb_event_t cb_event_type,
		void *user_data __attribute__((unused)))
{
	// Service signal requests before event processing
	if (dump_state)
		output_state();

	if (hup)
		reload_config();

	//my_printf("handle_event %s", auparse_get_type_name(au));

	/* Save for metrics reporting */
	au = p;

	/* Do this once for all models */
	if (auparse_normalize(au, NORM_OPT_NO_ATTRS))
		my_printf("Error normalizing %s", auparse_get_type_name(au));

	/* Check for events that are known bad */
	process_bad_event_model(au, &config);

	/* Check if user doing something strange */
	process_behavior_model(au, &config);
}

