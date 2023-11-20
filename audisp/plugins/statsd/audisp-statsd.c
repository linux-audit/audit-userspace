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
#include <poll.h>
#include <sys/timerfd.h>
#include <errno.h>
#include "libaudit.h"
#include "auparse.h"


/* Global Definitions */
#define STATE_REPORT "/var/run/auditd.state"
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
	unsigned int free_space;
	unsigned int plugin_current_depth;
	unsigned int plugin_max_depth;
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
static pid_t auditd_pid = 0;
static auparse_state_t *au = NULL;
static int timer_fd = -1;
static char msg[MAX_AUDIT_MESSAGE_LENGTH + 1];
static struct daemon_config d;
static struct audit_report r;

/* Local function prototypes */
static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type,
			 void *user_data);


/*
 * SIGTERM handler: exit time
 */
static void term_handler(int sig)
{
	stop = sig;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig)
{
	hup = sig;
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
	char buf[128];
	FILE *f = fopen(CONFIG, "rt");
	if (f == NULL) {
		fprintf(stderr, "Cannot open config file\n");
		return 1;
	}

	while (get_line(f, buf, sizeof(buf))) {
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
			sscanf(buf, "interval = %u", &d.interval);
			status |= 0x04;
			break;
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
	// SIGCONT was sent previously, hopefully the report is ready now
	FILE *f = fopen(STATE_REPORT, "rt");
	if (f) {
		char buf[80];

		__fsetlocking(f, FSETLOCKING_BYCALLER);

		while (fgets(buf, sizeof(buf), f)) {
			if (memcmp(buf, "Logging", 7) == 0) {
				sscanf(buf,
				       "Logging partition free space %u",
				       &r.free_space);
			} else if (memcmp(buf, "current plugin", 14) == 0) {
				sscanf(buf,
				       "current plugin queue depth = %u",
				       &r.plugin_current_depth);
			} else if (memcmp(buf, "max plugin", 10) == 0) {
				sscanf(buf,
				       "max plugin queue depth used = %u",
				       &r.plugin_max_depth);
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
	  "auditd.free_space:%u|g\nauditd.plugin_current_depth:%u|g\nauditd.plugin_max_depth:%u|g\n"
	  "events.total_count:%u|c\nevents.total_failed:%u|c\n"
	  "events.avc_count:%u|c\nevents.fanotify_count:%u|c\n"
	  "events.logins_success:%u|c\nevents.logins_failed:%u|c\n"
	  "events.anomaly_count:%u|c\nevents.response_count:%u|c\n",
		r.lost, r.backlog,
		r.free_space, r.plugin_current_depth, r.plugin_max_depth,
		r.events_total_count, r.events_total_failed,
		r.events_avc_count, r.events_fanotify_count,
		r.events_logins_success, r.events_logins_failed,
		r.events_anomaly_count, r.events_response_count);

	if (len > 0 && len < (int)sizeof(message))
		sendto(d.sock, message, len, 0, (struct sockaddr *)&d.addr,
		       d.addrlen);
}


int main(void)
{
	struct sigaction sa;
	struct pollfd pfd[2];
	struct itimerspec itval;
	int rc;

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
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

	// Create the socket
	d.sock = make_socket();
	if (d.sock < 0) {
		syslog(LOG_ERR, "Failed creating socket - exiting");
		return 1;
	}

	// Initialize audit
	clear_report();
	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		close(d.sock);
		syslog(LOG_ERR, "exiting due to auparse init errors");
		return 1;
	}
	auparse_set_eoe_timeout(5);
	auparse_add_callback(au, handle_event, NULL, NULL);
	audit_fd = audit_open();
	if (audit_fd < 0) {
		close(d.sock);
		syslog(LOG_ERR, "unable to open audit socket");
		return 1;
	}
	auditd_pid = getppid();
	fcntl(0, F_SETFL, O_NONBLOCK); /* Set STDIN non-blocking */
	pfd[0].fd = 0;		// add stdin to the poll group
	pfd[0].events = POLLIN;

	// Initialize interval timer
	timer_fd = timerfd_create (CLOCK_MONOTONIC, 0);
	if (timer_fd < 0) {
		syslog(LOG_ERR, "unable to open a timerfd");
		return 1;
	}
	pfd[1].fd = timer_fd;
	pfd[1].events = POLLIN;
	itval.it_interval.tv_sec = d.interval;
	itval.it_interval.tv_nsec = 0;
	itval.it_value.tv_sec = itval.it_interval.tv_sec;
	itval.it_value.tv_nsec = 0;
	timerfd_settime(timer_fd, 0, &itval, NULL);

	// Start event loop
	while (!stop) {
		rc = poll(pfd, 2, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
		} else if (rc > 0) {
			// timer
			if (pfd[1].revents & POLLIN) {
				unsigned long long missed;
				missed=read(timer_fd, &missed, sizeof (missed));
				kill(auditd_pid, SIGCONT); // Run auditd report
				// Clear any old events if possible
				if (auparse_feed_has_data(au))
					auparse_feed_age_events(au);
				get_kernel_status();
				get_auditd_status();
				send_statsd();
				clear_report();
			}
			// audit event
			if (pfd[0].revents & POLLIN) {
				int len;
				while ((len = read(0, msg,
					    MAX_AUDIT_MESSAGE_LENGTH)) > 0) {
					msg[len] = 0;
					auparse_feed(au, msg, len);
				}
			}
		}
	}

	// tear down everything
	close(timer_fd);
	auparse_destroy(au);
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

