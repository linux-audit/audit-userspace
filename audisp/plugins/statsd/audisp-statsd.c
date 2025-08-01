/* audisp-statsd.c --
 * Copyright 2021 Steve Grubb
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 */
#include "config.h"
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "auparse.h"
#include "common.h"
#include "auplugin.h"

/* Global Definitions */
#define STATE_REPORT AUDIT_RUN_DIR"/auditd.state"
#define CONFIG "/etc/audit/audisp-statsd.conf"

struct daemon_config
{
	char address[65];
	unsigned int port;
	unsigned int interval;
	int sock;
	struct sockaddr_storage addr;
	socklen_t addrlen;
};

struct audit_report
{
	unsigned int backlog;
	unsigned int lost;
	long long unsigned int free_space;
	unsigned int plugin_current_depth;
	unsigned int plugin_max_depth;
	unsigned long long total_memory;
	unsigned long long memory_in_use;
	unsigned long long memory_free;
	unsigned int events_total_count;
	unsigned int events_total_failed;
	unsigned int events_avc_count;
	unsigned int events_fanotify_count;
	unsigned int events_logins_success;
	unsigned int events_logins_failed;
	unsigned int events_anomaly_count;
	unsigned int events_response_count;
};

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static int audit_fd = -1;
static struct daemon_config d;
static struct audit_report r;

/* Local function prototypes */
static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type,
			 void *user_data);


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

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig __attribute__((unused)))
{
	hup = 1;
}

/*
 * Get the next config file line and clean it up a little
 */
static char *get_line(FILE *f, char *buf, size_t len)
{
        if (fgets(buf, len, f)) {
                /* remove newline */
                char *ptr = strchr(buf, 0x0a);
                if (ptr)
                        *ptr = 0;
                return buf;
        }
        return NULL;
}

/*
 * Load the plugin's configuration. Returns 1 on failure and 0 on success.
 */
static int load_config(void)
{
	unsigned int status = 0;
	int line = 0;
	char buf[128];
	FILE *f = fopen(CONFIG, "rt");
	if (f == NULL) {
		fprintf(stderr, "Cannot open config file\n");
		return 1;
	}

	while (get_line(f, buf, sizeof(buf))) {
		line++;
		switch (buf[0])
		{
		case 'a':
			sscanf(buf, "address = %64s", d.address);
			status |= 0x01;
			break;
		case 'p':
			sscanf(buf, "port = %u", &d.port);
			status |= 0x02;
			break;
		case 'i':
		{
			char tstr[64];
			long t;

			if (sscanf(buf, "interval = %63s", tstr) != 1) {
				fprintf(stderr, "bad interval format\n");
				fclose(f);
				return 1;
			}
			t = time_string_to_seconds(tstr, "statsd", line);
			if (t < 0) {
				fclose(f);
				return 1;
			}
			d.interval = (unsigned int)t;
			status |= 0x04;
			break;
		}
		case 0:
		case '#':
			// Comments
			break;
		default:
			fprintf(stderr, "unknown option\n");
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	if (status != 0x07) {
		fprintf(stderr, "Not all config options specified\n");
		return 1;
	}
	return 0;
}

/*
 * Given the configuration data, turn it into a usable address for use
 * with sendto later.
 */
int make_socket(void)
{
	int rc;
	struct addrinfo hints, *ai;
	char port[16];

	// Resolve the remote host
	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG|AI_NUMERICSERV;
	hints.ai_socktype = SOCK_DGRAM;

	snprintf(port, sizeof(port), "%u", d.port);
	rc = getaddrinfo(d.address, port, &hints, &ai);
	if (rc) {
		syslog(LOG_ERR, "error looking up statsd service\n");
		return -1;
	}

	d.sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	memcpy(&d.addr, ai->ai_addr, ai->ai_addrlen);
	d.addrlen = ai->ai_addrlen;
	freeaddrinfo(ai);

	return d.sock;
}

/*
 * Reset all the report parameters
 */
static void clear_report(void)
{
	r.lost = 0;
	r.backlog = 0;
	r.free_space = 0;
	r.plugin_current_depth = 0;
	r.plugin_max_depth = 0;
	r.total_memory = 0;
	r.memory_in_use = 0;
	r.memory_free = 0;
	r.events_total_count = 0;
        r.events_total_failed = 0;
        r.events_avc_count = 0;
        r.events_fanotify_count = 0;
        r.events_logins_success = 0;
        r.events_logins_failed = 0;
	r.events_anomaly_count = 0;
	r.events_response_count = 0;
}

/*
 * Pull the current status from the kernel
 */
static void get_kernel_status(void)
{
	struct audit_reply rep;

	audit_request_status(audit_fd);
	int rc = audit_get_reply(audit_fd, &rep, GET_REPLY_BLOCKING, 0);

	if (rc > 0 && rep.type == AUDIT_GET) {
		// add info to global audit event struct
		r.lost = rep.status->lost;
		r.backlog = rep.status->backlog;
	}
}

/*
 * Collect free_space, plugin_current_depth, and plugin_max_depth
 * out of the auditd state report.
 */
static void get_auditd_status(void)
{
	// auditd generates the state report periodically on its own
	FILE *f = fopen(STATE_REPORT, "rt");
	if (f) {
		char buf[80];

		__fsetlocking(f, FSETLOCKING_BYCALLER);

		while (fgets(buf, sizeof(buf), f)) {
			if (memcmp(buf, "Logging", 7) == 0) {
				sscanf(buf,
				       "Logging partition free space = %llu",
				       &r.free_space);
			} else if (memcmp(buf, "current plugin", 14) == 0) {
				sscanf(buf,
				       "current plugin queue depth = %u",
				       &r.plugin_current_depth);
			} else if (memcmp(buf, "max plugin", 10) == 0) {
				sscanf(buf,
				       "max plugin queue depth used = %u",
				       &r.plugin_max_depth);
			} else if (memcmp(buf, "glibc arena", 11) == 0) {
				sscanf(buf,
				       "glibc total memory is: %llu",
				       &r.total_memory);
			} else if (memcmp(buf, "glibc uordblks", 13) == 0) {
				sscanf(buf,
				       "glibc in use memory is: %llu",
				       &r.memory_in_use);
			} else if (memcmp(buf, "glibc fordblks", 14) == 0) {
				sscanf(buf,
				       "glibc total free space is: %llu",
				       &r.memory_free);
				break; // This is last item, break free
			}
		}
		fclose(f);
	}
}

/*
 * Format and send the report metrics to the statsd service.
 */
static void send_statsd(void)
{
	// The message size has to stay under the MTU for the network
	// 512 should be low enough to survive the commodity internet
	char message[512];
	int len;

	// grab the global audit event struct and format it
	// format - <metric_name>:<metric_value>|<metric_type>
	// Things pulled from kernel or auditd are gauges. Anything
	// incremented (events) are counters.
	len = snprintf(message, sizeof(message),
	  "kernel.lost:%u|g\nkernel.backlog:%u|g\n"
	  "auditd.free_space:%llu|g\nauditd.plugin_current_depth:%u|g\nauditd.plugin_max_depth:%u|g\n"
	  "auditd.total_memory:%llu|g\nauditd.memory_in_use:%llu|g\nauditd.memory_free:%llu|g\n"
	  "events.total_count:%u|c\nevents.total_failed:%u|c\n"
	  "events.avc_count:%u|c\nevents.fanotify_count:%u|c\n"
	  "events.logins_success:%u|c\nevents.logins_failed:%u|c\n"
	  "events.anomaly_count:%u|c\nevents.response_count:%u|c\n",
		r.lost, r.backlog,
		r.free_space, r.plugin_current_depth, r.plugin_max_depth,
		r.total_memory, r.memory_in_use, r.memory_free,
		r.events_total_count, r.events_total_failed,
		r.events_avc_count, r.events_fanotify_count,
		r.events_logins_success, r.events_logins_failed,
		r.events_anomaly_count, r.events_response_count);

	if (len > 0 && len < (int)sizeof(message))
		sendto(d.sock, message, len, 0, (struct sockaddr *)&d.addr,
		       d.addrlen);
}

static void statsd_timer(unsigned int interval __attribute__((unused)))
{
	get_kernel_status();
	get_auditd_status();
	send_statsd();
	clear_report();
}

int main(void)
{
	struct sigaction sa;

	if (geteuid() != 0) {
		fprintf(stderr, "You need to be root to run this\n");
		return 1;
	}

	if (load_config()) {
		syslog(LOG_ERR, "Failed loading config - exiting");
		return 1;
	}

	// Setup signal handlers
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	/* Set handler for the ones we care about */
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_sigaction= term_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGTERM, &sa, NULL);

	// Create the socket
	d.sock = make_socket();
	if (d.sock < 0) {
		syslog(LOG_ERR, "Failed creating socket - exiting");
		return 1;
	}

#ifdef HAVE_LIBCAP_NG
	// Drop capabilities - audit control required for AUDIT_GET
	capng_clear(CAPNG_SELECT_BOTH);
	capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
		    CAP_AUDIT_CONTROL);
	if (capng_apply(CAPNG_SELECT_BOTH))
		syslog(LOG_WARNING, "audisp-statsd failed dropping capabilities, continuing with elevated priviliges");
#endif

	clear_report();
	audit_fd = audit_open();
	if (audit_fd < 0) {
		close(d.sock);
		syslog(LOG_ERR, "unable to open audit socket");
		return 1;
	}

	if (auplugin_init(0, 128, AUPLUGIN_Q_IN_MEMORY, NULL)) {
		close(audit_fd);
		close(d.sock);
		syslog(LOG_ERR, "failed to init auplugin");
		return 1;
	}

	auplugin_event_feed(handle_event, d.interval, statsd_timer);

	// tear down everything
	close(audit_fd);
	close(d.sock);

	if (stop)
		syslog(LOG_INFO, "audisp-statsd is exiting on stop request");
	else
		syslog(LOG_INFO, "audisp-statsd is exiting");

	return 0;
}

/*
 * Given a completed event, parse it up and increment various counters
 * based on what we see.
 */
static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type,
			 void *user_data __attribute__((unused)))
{
	int type;
	const char *success;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	// Need to put everything in the global struct
	//         r.events_total_count;
	//         r.events_total_failed;
	//         r.events_avc_count;
	//         r.events_fanotify_count;
	//         r.events_logins_success;
	//         r.events_logins_failed;
	//         r.events_anomaly_count;
	//         r.events_response_count
	r.events_total_count++;
	auparse_normalize(au, NORM_OPT_NO_ATTRS);
	auparse_normalize_get_results(au);
	success = auparse_interpret_field(au);
	if (success && strcmp(success, "no") == 0)
		r.events_total_failed++;

	auparse_first_record(au);
	type = auparse_get_type(au);
	switch (type)
	{
		// These take advantage of knowing that this is the first
		// record in the whole event. If this ever changes then all
		// bets are off.
		case AUDIT_USER_LOGIN:
			if (success) {
				if (strcmp(success, "no") == 0)
					r.events_logins_failed++;
				else
					r.events_logins_success++;
			}
			break;
                case AUDIT_FANOTIFY:
			r.events_fanotify_count++;
			break;
                case AUDIT_AVC:
			r.events_avc_count++;
			break;
		case AUDIT_FIRST_ANOM_MSG...AUDIT_LAST_ANOM_MSG:
			r.events_anomaly_count++;
			break;
		case AUDIT_FIRST_ANOM_RESP...AUDIT_LAST_ANOM_RESP:
			r.events_response_count++;
			break;
	}
}

