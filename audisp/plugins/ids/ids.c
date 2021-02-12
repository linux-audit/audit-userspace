/* ids.c --
 * Copyright 2021 Steve Grubb.
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
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/stat.h> // umask
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
#include "reactions.h"

/* Global Data */
int debug = 1;
// mode 2 == syslog, 1 == stderr, 0 == nothing
int mode = 0;

/* Local Data */
static volatile int stop = 0;
static volatile int hup = 0;
static volatile int dump_state = 0;
static auparse_state_t *au = NULL;
#define NO_ACTIONS (!hup && !stop && !dump_state)
#define STATE_FILE "/var/run/ids-state"
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

void log_audit_event(int type, const char *text, int res)
{
	audit_log_user_message(audit_fd, type, text, NULL, NULL, NULL, res);
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
	auparse_add_callback(au, handle_event, NULL, NULL);
	
	init_timer_services();

	do {
		int retval = -1;

		/* Handle dump_state */
		if (dump_state)
			output_state();

		/* Load configuration */
		if (hup)
			reload_config();

		/* Probably not needed, but maybe reload took some time?  */
		if (stop)
			break;

		FD_ZERO(&read_mask);
		FD_SET(0, &read_mask);
		do {
			retval= select(1, &read_mask, NULL, NULL, NULL);
		} while (retval == -1 && errno == EINTR && NO_ACTIONS);

		/* Now the event loop */
		 if (NO_ACTIONS && retval > 0) {
			if (FD_ISSET(0, &read_mask)) {
				do {
					if (audit_fgets(tmp,
						MAX_AUDIT_MESSAGE_LENGTH, 0)) {
						auparse_feed(au, tmp,
							       strnlen(tmp,
						    MAX_AUDIT_MESSAGE_LENGTH));
					}
				} while (audit_fgets_more(
						MAX_AUDIT_MESSAGE_LENGTH));
			}
		}
		if (audit_fgets_eof())
			break;
	} while (stop == 0);

	shutdown_timer_services();

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

	return 0;
}

#define MINUTES	60
#define HOURS	60*MINUTES
#define DAYS 	24*HOURS
#define WEEKS	7*DAYS
#define MONTHS	30*DAYS

static void block_address(unsigned int reaction)
{
	int res;
	char buf[32];
	origin_data_t *o = current_origin();
	const char *addr = sockint_to_ipv4(o->address);
	snprintf(buf, sizeof(buf), "daddr=%s", addr);
	log_audit_event(AUDIT_ANOM_LOGIN_FAILURES, buf, 1);

	if (debug)
		my_printf("Blocking address %s", addr);

	if (reaction == REACTION_BLOCK_ADDRESS)
		res = block_ip_address(addr);
	else
		res = block_ip_address_timed(addr, 2*DAYS);

	if (res == 0) {
		o->blocked = 1;
		if (reaction == REACTION_BLOCK_ADDRESS)
			log_audit_event(AUDIT_RESP_ORIGIN_BLOCK, buf, 1);
		else
			log_audit_event(AUDIT_RESP_ORIGIN_BLOCK_TIMED, buf, 1);
	}
}

static void do_reaction(unsigned int answer)
{
//my_printf("Answer: %u", answer);
	unsigned int num = 0;

	do {
		unsigned int tmp = 1 << num;
		if (answer & tmp) {
			switch (tmp) {
				// FIXME: do the reactions
				case REACTION_IGNORE:
					break;
				case REACTION_LOG:
				case REACTION_EMAIL:
				case REACTION_TERMINATE_PROCESS:
					break;
				case REACTION_TERMINATE_SESSION:
				{
					// FIXME: need to add audit events
					session_data_t *s = current_session();
					kill_session(s->session);
					break;
				}
				case REACTION_RESTRICT_ROLE:
				case REACTION_PASSWORD_RESET:
				case REACTION_LOCK_ACCOUNT_TIMED:
				case REACTION_LOCK_ACCOUNT:
					break;
				case REACTION_BLOCK_ADDRESS_TIMED:
				case REACTION_BLOCK_ADDRESS:
					block_address(tmp);
					break;
				case REACTION_SYSTEM_REBOOT:
				case REACTION_SYSTEM_SINGLE_USER:
				case REACTION_SYSTEM_HALT:
				default:
					if (debug)
					    my_printf("Unknown reaction: %X",
							tmp);
					break;
			}
		}
		num ++;
	} while (num < 32);

}

/* This function receives a single complete event from the auparse library. */
static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type,
		void *user_data __attribute__((unused)))
{
	unsigned int answer;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	/* Do this once for all models */
	if (auparse_normalize(au, NORM_OPT_NO_ATTRS)) {
		my_printf("Error normalizing %s", auparse_get_type_name(au));
	}

	/* Check for events that are known bad */
	answer = process_bad_event_model(au, &config);

	/* Check if user doing something strange */
	answer |= process_behavior_model(au, &config);
	if (answer == 0)
		return;

	do_reaction(answer);
}

