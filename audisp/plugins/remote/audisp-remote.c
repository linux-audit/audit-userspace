/* audisp-remote.c --
 * Copyright 2008-2012,2016,2018,2019-20 Red Hat Inc.
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
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#ifdef HAVE_MALLINFO2
#include <malloc.h>
#endif
#include <fcntl.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#ifdef USE_GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <krb5.h>
#endif
#ifdef HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "autls.h"
#endif
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "auplugin.h"
#include "private.h"
#include "remote-config.h"
#include "common.h"
#include "queue.h"

#define CONFIG_FILE "/etc/audit/audisp-remote.conf"
#define BUF_SIZE 32

/* Error types */
#define ET_SUCCESS	 0
#define ET_PERMANENT	-1
#define ET_TEMPORARY	-2

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static volatile int suspend = 0;
static volatile int dump = 0;
static volatile int transport_ok = 0;
static volatile int sock=-1;
// We start with remote_ended true so it retries on startup
static volatile int remote_ended = 1, quiet = 0;
static int ifd;
remote_conf_t config;
static int warned = 0;
#ifdef HAVE_MALLINFO2
static struct mallinfo2 last_mi;
#endif
static size_t max_queued_length = 0;

/* Constants */
static const char *SPOOL_FILE = "/var/spool/audit/remote.log";
#define STATE_FILE AUDIT_RUN_DIR"/remote.state"

/* Local function declarations */
static int check_message(void);
static int relay_event(const char *s, size_t len)
	__attr_access ((__read_only__, 1, 2));
static int relay_sock(const char *s, size_t len)
	__attr_access ((__read_only__, 1, 2));
static int relay_sock_managed(const char *s, size_t len)
	__attr_access ((__read_only__, 1, 2));
static int relay_sock_ascii(const char *s, size_t len)
	__attr_access ((__read_only__, 1, 2));
static int send_msg_tcp (unsigned char *header, const char *msg, uint32_t mlen)
	__attr_access ((__read_only__, 2, 3));
static int init_transport(void);
static int stop_transport(void);
static int ar_read (int, void *, int)
	__attr_access ((__write_only__, 2, 3));
static int ar_write (int, const void *, int)
	__attr_access ((__read_only__, 2, 3));

#ifdef USE_GSSAPI
/* We only ever talk to one server, so we don't need per-connection
   credentials.  These are the ones we talk to the server with.  */
gss_ctx_id_t my_context;

#define KEYTAB_NAME "/etc/audit/audisp-remote.key"
#define CCACHE_NAME "MEMORY:audisp-remote"

#define REQ_FLAGS GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG
#define USE_GSS (config.transport == T_KRB5)
#endif

#ifdef HAVE_TLS
static SSL_CTX *tls_ctx = NULL;
static SSL *tls_ssl = NULL;
#define USE_TLS (config.transport == T_TLS)

static int init_tls_context(void);
static void destroy_tls_context(void);
static int tls_connect(void);
static void tls_disconnect(void);
static int tls_read(SSL *ssl, void *buf, int len);
static int send_msg_tls(unsigned char *header, const char *msg, uint32_t mlen);
static int recv_msg_tls(unsigned char *header, char *msg, uint32_t *mlen);
#endif

/* Compile-time expression verification */
#define verify(E) do {				\
		char verify__[(E) ? 1 : -1];	\
		(void)verify__;			\
	} while (0)

/*
 * SIGTERM handler
 *
 * Only honor the signal if it comes from the parent process so that other
 * tasks (cough, systemctl, cough) can't make the plugin exit without
 * the dispatcher in agreement. Otherwise it will restart the plugin.
 */
static void term_handler(int sig, siginfo_t *info, void *ucontext)
{
	if (info && info->si_pid != getppid())
		return;
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
	if (transport_ok)
		stop_transport();
#ifdef HAVE_TLS
	destroy_tls_context();
#endif
	transport_ok = 0;
	remote_ended = 1;
	hup = 0;
}

/*
 * SIGUSR1 handler: write a state report
 */
static void user1_handler( int sig )
{
        dump = 1;
}

#ifdef HAVE_MALLINFO2
/* Write glibc memory statistics to FILE */
static void write_memory_state(FILE *f)
{
	struct mallinfo2 mi = mallinfo2();

	fprintf(f, "glibc arena (total memory) is: %zu KiB, was: %zu KiB\n",
		(size_t)mi.arena/1024, (size_t)last_mi.arena/1024);
	fprintf(f, "glibc uordblks (in use memory) is: %zu KiB, was: %zu KiB\n",
		(size_t)mi.uordblks/1024,(size_t)last_mi.uordblks/1024);
	fprintf(f,"glibc fordblks (total free space) is: %zu KiB, was: %zu KiB\n",
		(size_t)mi.fordblks/1024,(size_t)last_mi.fordblks/1024);

	memcpy(&last_mi, &mi, sizeof(struct mallinfo2));
}
#endif

/* Write plugin state to STATE_FILE */
static void write_state_report(struct queue *queue)
{
        char buf[64];
        mode_t u = umask(0137); // allow 0640
        FILE *f = fopen(STATE_FILE, "w");
        umask(u);
        if (f == NULL)
                return;

        time_t now = time(NULL);
        strftime(buf, sizeof(buf), "%x %X", localtime(&now));
        fprintf(f, "current_time = %s\n", buf);
        fprintf(f, "suspend = %s\n", suspend ? "yes" : "no");
        fprintf(f, "remote_ended = %s\n", remote_ended ? "yes" : "no");
        fprintf(f, "transport_ok = %s\n", transport_ok ? "yes" : "no");
        fprintf(f, "queue_length = %zu\n", q_queue_length(queue));
        fprintf(f, "max_queued_length = %zu\n", max_queued_length);
        fprintf(f, "queue_depth = %u\n", config.queue_depth);
#ifdef HAVE_MALLINFO2
	write_memory_state(f);
#endif
	fclose(f);
	dump = 0;
}

/*
 * SIGSUR2 handler: resume logging
 */
static void user2_handler( int sig )
{
        suspend = 0;
}

/*
 * SIGCHLD handler: reap exiting processes
 */
static void child_handler(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0)
		; /* empty */
}

/*
 * Handlers for various events coming back from the remote server.
 * Return -1 if the remote dispatcher should exit.
 */

/* Loss of sync - got an invalid response.  */
static int sync_error_handler (const char *why)
{
	/* "why" has human-readable details on why we've lost (or will
	   be losing) sync.  Sync errors are transient - if a retry
	   doesn't fix it, we eventually call network_failure_handler
	   which has all the user-tweakable actions.  */
	syslog (LOG_ERR, "lost/losing sync, %s", why);
	return 0;
}

static int is_pipe(int fd)
{
	struct stat st;

	if (fstat(fd, &st) == 0) {
		if (S_ISFIFO(st.st_mode))
			return 1;
	}
	return 0;
}

static void safe_exec(const char *exe, const char *message)
{
	char *argv[3];
	int pid;
	struct sigaction sa;

	if (exe == NULL) {
		syslog(LOG_ALERT,
			"Safe_exec passed NULL for program to execute");
		return;
	}

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ALERT,
			"audisp-remote failed to fork doing safe_exec");
		return;
	}
	if (pid)	/* Parent */
		return;

	/* Child */
	sigfillset (&sa.sa_mask);
	sigprocmask (SIG_UNBLOCK, &sa.sa_mask, 0);
#ifdef HAVE_CLOSE_RANGE
	close_range(3, ~0U, 0); /* close all past stderr */
#else
	for (int i=3; i<24; i++)     /* Arbitrary number */
		close(i);
#endif

	argv[0] = (char *)exe;
	argv[1] = (char *)message;
	argv[2] = NULL;
	execve(exe, argv, NULL);
	syslog(LOG_ALERT, "audisp-remote failed to exec %s", exe);
	exit(1);
}

static int do_action (const char *desc, const char *message,
		       int log_level,
		       failure_action_t action, const char *exe)
{
	switch (action)
	{
	case FA_IGNORE:
		return 0;
	case FA_SYSLOG:
		syslog (log_level, "%s, %s", desc, message);
		return 0;
	case FA_EXEC:
		safe_exec (exe, message);
		return 0;
	case FA_WARN_ONCE_CONT:
		if (warned & 1)
			return -1;
		warned |= 1;
		syslog (log_level, "%s, %s", desc, message);
		return 0;
	case FA_WARN_ONCE:
		if (warned & 2)
			return -1;
		warned |= 2;
		syslog (log_level, "%s, %s", desc, message);
		return -1;
	case FA_SUSPEND:
		syslog (log_level,
			"suspending remote logging due to %s", desc);
		suspend = 1;
		return -1;
	case FA_RECONNECT:
		syslog (log_level,
	"remote logging disconnected due to %s, will attempt reconnection",
			desc);
		return -1;
	case FA_SINGLE:
		syslog (log_level,
	"remote logging is switching system to single user mode due to %s",
			desc);
		change_runlevel(SINGLE);
		return -1;
	case FA_HALT:
		syslog (log_level,
			"remote logging halting system due to %s", desc);
		change_runlevel(HALT);
		return -1;
	case FA_STOP:
		syslog (log_level, "remote logging stopping due to %s, %s",
			desc, message);
		stop = 1;
		return -1;
	}
	syslog (log_level, "unhandled action %d for %s", action, desc);
	return -1;
}

static int network_failure_handler (const char *message)
{
	return do_action ("network failure", message,
			  LOG_WARNING,
			  config.network_failure_action,
			  config.network_failure_exe);
}

static int remote_disk_low_handler (const char *message)
{
	return do_action ("remote server is low on disk space", message,
			  LOG_WARNING,
			  config.disk_low_action, config.disk_low_exe);
}

static int remote_disk_full_handler (const char *message)
{
	return do_action ("remote server's disk is full", message,
			  LOG_ERR,
			  config.disk_full_action, config.disk_full_exe);
}

static int remote_disk_error_handler (const char *message)
{
	return do_action ("remote server has a disk error", message,
			  LOG_ERR,
			  config.disk_error_action, config.disk_error_exe);
}

static int remote_server_ending_handler (const char *message)
{
	stop_transport();
	remote_ended = 1;
	return do_action ("remote server is going down", message,
			  LOG_WARNING,
			  config.remote_ending_action,
			  config.remote_ending_exe);
}

static int generic_remote_error_handler (const char *message)
{
	return do_action ("unrecognized remote error", message,
			  LOG_ERR, config.generic_error_action,
			  config.generic_error_exe);
}

static int generic_remote_warning_handler (const char *message)
{
	return do_action ("unrecognized remote warning", message,
			  LOG_WARNING,
			  config.generic_warning_action,
			  config.generic_warning_exe);
}

/* Report and handle a queue error, using errno. */
static void queue_error(void)
{
	char *errno_str;

	errno_str = strerror(errno);
	do_action("queue error", errno_str, LOG_ERR, config.queue_error_action,
		  config.queue_error_exe);
}

static int startup_failure_handler(const char *message)
{
	return do_action("startup network failure", message,
			  LOG_WARNING,
			  config.startup_failure_action,
			  config.startup_failure_exe);
}

static void send_heartbeat (void)
{
	relay_event (NULL, 0);
}

static void do_overflow_action(void)
{
        switch (config.overflow_action)
        {
                case OA_IGNORE:
			break;
                case OA_SYSLOG:
			syslog(LOG_ERR, "queue is full - dropping event");
                        break;
                case OA_SUSPEND:
                        syslog(LOG_ALERT,
                            "Audisp-remote is suspending event processing due to overflowing its queue.");
			suspend = 1;
                        break;
                case OA_SINGLE:
                        syslog(LOG_ALERT,
                                "Audisp-remote is now changing the system to single user mode due to overflowing its queue");
                        change_runlevel(SINGLE);
                        break;
                case OA_HALT:
                        syslog(LOG_ALERT,
                                "Audisp-remote is now halting the system due to overflowing its queue");
                        change_runlevel(HALT);
                        break;
                default:
                        syslog(LOG_ALERT, "Unknown overflow action requested");
                        break;
        }
}

/* Initialize and return a queue depending on user's configuration.
   On error return NULL and set errno. */
static struct queue *init_queue(void)
{
	const char *path;
	int q_flags;

	if (config.queue_file != NULL)
		path = config.queue_file;
	else
		path = SPOOL_FILE;
	q_flags = Q_IN_MEMORY;
	if (config.mode == M_STORE_AND_FORWARD)
		/* FIXME: let user control Q_SYNC? Consider this
		 * only after something like INCREMENTAL_ASYNC is
		 * in place. The user can choose between none and async. */
		q_flags |= Q_IN_FILE | Q_CREAT | Q_RESIZE;
	verify(QUEUE_ENTRY_SIZE >= MAX_AUDIT_MESSAGE_LENGTH);
	return q_open(q_flags, path, config.queue_depth, QUEUE_ENTRY_SIZE);
}

/* Send a record from QUEUE to the remote system */
static void send_one(struct queue *queue)
{
	char event[MAX_AUDIT_MESSAGE_LENGTH];
	int len;

	if (suspend || !transport_ok)
		return;

	len = q_peek(queue, event, sizeof(event));
	if (len == 0)
		return;
	if (len < 0) {
		queue_error();
		return;
	}

	/* We send len -1 to remove trailing \n */
	if (relay_event(event, len-1) < 0)
		return;

	/* reset on all successful transmissions */
	warned = 0;
	if (q_drop_head(queue) != 0)
		queue_error();
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	struct queue *queue;
	size_t q_len;
	int connected_once = 0;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = user1_handler;
	sigaction(SIGUSR1, &sa, NULL);
	sa.sa_handler = user2_handler;
	sigaction(SIGUSR2, &sa, NULL);
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);
	sa.sa_sigaction = term_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGTERM, &sa, NULL);
	if (load_config(&config, CONFIG_FILE))
		return 6;

	(void) umask( umask( 077 ) | 027 );
	// ifd = open("test.log", O_RDONLY);
	ifd = 0;
	fcntl(ifd, F_SETFL, O_NONBLOCK);

	// Start up the queue
	queue = init_queue();
	if (queue == NULL) {
		syslog(LOG_ERR, "Error initializing audit record queue: %m");
		return 1;
	}
	max_queued_length = q_queue_length(queue);

#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
	capng_clear(CAPNG_SELECT_BOTH);
	if (config.local_port && config.local_port < 1024)
		capng_update(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
			CAP_NET_BIND_SERVICE);
	if (capng_apply(CAPNG_SELECT_BOTH))
		syslog(LOG_WARNING, "audisp-remote plugin was unable to drop capabilities, continuing with elevated priviles");
#endif
	syslog(LOG_NOTICE, "Audisp-remote started with queue_size: %zu",
		q_queue_length(queue));

	while (stop == 0) {
		fd_set rfd, wfd;
		struct timeval tv;
		char event[MAX_AUDIT_MESSAGE_LENGTH];
		int n, fds = ifd + 1;

		/* Load configuration */
		if (hup)
			reload_config();

		if (dump)
			write_state_report(queue);

		/* Setup select flags */
		FD_ZERO(&rfd);
		FD_SET(ifd, &rfd);	// input fd
		FD_ZERO(&wfd);
		if (sock >= 0) {
			// Setup socket to read acks from server
			FD_SET(sock, &rfd); // remote socket
			if (sock > ifd)
				fds = sock + 1;
			// If we have anything in the queue,
			// find out if we can send it
			if (q_queue_length(queue) && !suspend && transport_ok)
				FD_SET(sock, &wfd);
		}

#ifdef HAVE_TLS
		/* Drain any TLS data buffered by OpenSSL before
		   blocking on select(). */
		{
			int drain = 0;
			while (USE_TLS && tls_ssl &&
			       SSL_has_pending(tls_ssl) &&
			       !stop && !hup && ++drain < 200)
				check_message();
		}
#endif

		if (config.format==F_MANAGED && config.heartbeat_timeout>0) {
			tv.tv_sec = config.heartbeat_timeout;
			tv.tv_usec = 0;
			n = select(fds, &rfd, &wfd, NULL, &tv);
		} else
			n = select(fds, &rfd, &wfd, NULL, NULL);
		if (n < 0)
			continue; // If here, we had some kind of problem

		if ((config.heartbeat_timeout > 0) && n == 0 && !remote_ended) {
			/* We attempt a heartbeat if select fails, which
			 * may give us more heartbeats than we need. This
			 * is safer than too few heartbeats.  */
			if (config.format == F_MANAGED) {
				quiet = 1;
				send_heartbeat();
				quiet = 0;
				continue;
			}
		}

		// See if we got a shutdown message from the server
		if (sock >= 0 && FD_ISSET(sock, &rfd))
			check_message();

		// If we broke out due to one of these, cycle to start
		if (hup != 0 || stop != 0)
			continue;

		// See if input fd is also set
		if (FD_ISSET(ifd, &rfd)) {
			do {
				if (auplugin_fgets(event,sizeof(event),ifd) > 0) {
					if (!transport_ok && remote_ended &&
						(config.remote_ending_action ==
								FA_RECONNECT ||
							!connected_once)) {
						quiet = 1;
						if (init_transport() ==
								ET_SUCCESS) {
							remote_ended = 0;
							connected_once = 1;
						} else if (!connected_once) {
							startup_failure_handler(
			"First attempt at connecting to server unsuccessful");
						}
						quiet = 0;
					}
					/* Strip out EOE records */
					if (*event == 't') {
						if (strncmp(event,
							"type=EOE", 8) == 0)
							continue;
					} else {
						char *ptr = strchr(event, ' ');
						if (ptr) {
							ptr++;
							if (strncmp(ptr,
								"type=EOE",
									8) == 0)
								continue;
						} else
							continue; //malformed
					}
					if (q_append(queue, event) != 0) {
						if (errno == ENOSPC)
							do_overflow_action();
						else
							queue_error();
					} else {
						size_t len = q_queue_length(queue);
						if (len > max_queued_length)
							max_queued_length = len;
					}
				} else if (auplugin_fgets_eof())
					stop = 1;
			} while (auplugin_fgets_more(sizeof(event)));
		}
		// See if output fd is also set
		if (sock >= 0 && FD_ISSET(sock, &wfd)) {
			// If so, try to drain backlog
			while (q_queue_length(queue) && !suspend &&
					!stop && transport_ok)
				send_one(queue);
		}
	}

	// If stdin is a pipe, then flush the queue
	if (is_pipe(0)) {
		while (q_queue_length(queue) && !suspend && transport_ok)
			send_one(queue);
	}

	stop_transport();
#ifdef HAVE_TLS
	destroy_tls_context();
#endif
	free_config(&config);
	q_len = q_queue_length(queue);
	q_close(queue);
	if (stop)
		syslog(LOG_NOTICE, "audisp-remote is exiting on stop request, queue_size: %zu", q_len);

	return q_len ? 1 : 0;
}

#ifdef USE_GSSAPI

/* Communications under GSS is done by token exchanges. Each "token" may
   contain a message, perhaps signed, perhaps encrypted. The messages within
   are what we're interested in, but the network sees the tokens. The
   protocol we use for transferring tokens is to send the length first,
   four bytes MSB first, then the token data. We return nonzero on error. */
static int recv_token(int s, gss_buffer_t tok)
{
	int ret;
	unsigned char lenbuf[4];
	unsigned int len;

	ret = ar_read(s, (char *) lenbuf, 4);
	if (ret < 0) {
		syslog(LOG_ERR, "GSS-API error reading token length");
		return -1;
	} else if (!ret) {
		return 0;
	} else if (ret != 4) {
		syslog(LOG_ERR, "GSS-API error reading token length");
		return -1;
	}

	len = (   ((uint32_t)(lenbuf[0] & 0xFF) << 24)
		| ((uint32_t)(lenbuf[1] & 0xFF) << 16)
		| ((uint32_t)(lenbuf[2] & 0xFF) << 8)
		|  (uint32_t)(lenbuf[3] & 0xFF));

	if (len > MAX_AUDIT_MESSAGE_LENGTH) {
		syslog(LOG_ERR,
			"GSS-API error: event length exceeds MAX_AUDIT_LENGTH");
		return -1;
	}
	tok->length = len;
	tok->value = (char *) malloc(tok->length ? tok->length : 1);
	if (tok->length && tok->value == NULL) {
		syslog(LOG_ERR, "Out of memory allocating token data %zd %zx",
				tok->length, tok->length);
		return -1;
	}

	ret = ar_read(s, (char *) tok->value, tok->length);
	if (ret < 0) {
		syslog(LOG_ERR, "GSS-API error reading token data");
		free(tok->value);
		return -1;
	} else if (ret != (int) tok->length) {
		syslog(LOG_ERR, "GSS-API error reading token data");
		free(tok->value);
		return -1;
	}

	return 0;
}

/* Same here.  */
static int send_token(int s, gss_buffer_t tok)
{
	int ret;
	unsigned char lenbuf[4];
	unsigned int len;

	if (sizeof(tok->length) > sizeof(uint32_t) &&
	    tok->length > 0xffffffffUL)
		return -1;

	len = tok->length;
	lenbuf[0] = (len >> 24) & 0xff;
	lenbuf[1] = (len >> 16) & 0xff;
	lenbuf[2] = (len >> 8) & 0xff;
	lenbuf[3] = len & 0xff;

	ret = ar_write(s, (char *) lenbuf, 4);
	if (ret < 0) {
		syslog(LOG_ERR, "GSS-API error sending token length");
		return -1;
	} else if (ret != 4) {
		syslog(LOG_ERR, "GSS-API error sending token length");
		return -1;
	}

	ret = ar_write(s, tok->value, tok->length);
	if (ret < 0) {
		syslog(LOG_ERR, "GSS-API error sending token data");
		return -1;
	} else if (ret != (int) tok->length) {
		syslog(LOG_ERR, "GSS-API error sending token data");
		return -1;
	}

	return 0;
}

static void gss_failure_2 (const char *msg, int status, int type)
{
	OM_uint32 message_context = 0;
	OM_uint32 min_status = 0;
	gss_buffer_desc status_string;

	do {
		gss_display_status (&min_status,
				    status,
				    type,
				    GSS_C_NO_OID,
				    &message_context,
				    &status_string);

		syslog (LOG_ERR, "GSS error: %s: %s",
			msg, (char *)status_string.value);

		gss_release_buffer(&min_status, &status_string);
	} while (message_context != 0);
}

static void gss_failure (const char *msg, int major_status, int minor_status)
{
	gss_failure_2 (msg, major_status, GSS_C_GSS_CODE);
	if (minor_status)
		gss_failure_2 (msg, minor_status, GSS_C_MECH_CODE);
}

#define KLOG(x,f) { \
	const char *kstr = krb5_get_error_message(kcontext, x); \
	syslog (LOG_ERR, "krb5 error: %s in %s\n", kstr, f); \
	krb5_free_error_message(kcontext, kstr); }
static krb5_context kcontext = NULL;
static char *realm_name = NULL;
static krb5_principal audit_princ;
static krb5_ccache ccache = NULL;
static krb5_get_init_creds_opt options;
static krb5_keytab keytab = NULL;

/* Each time we connect to the server, we negotiate a set of credentials and
   a security context. To do this, we need our own credentials first. For
   other Kerberos applications, the user will have called kinit (or otherwise
   authenticated) first, but we don't have that luxury. So, we implement part
   of kinit here. When our tickets expire, the usual close/open/retry logic
   has us calling here again, where we re-init and get new tickets. */
static int negotiate_credentials (void)
{
	gss_buffer_desc empty_token_buf = { 0, (void *) "" };
	gss_buffer_t empty_token = &empty_token_buf;
	gss_buffer_desc send_tok, recv_tok, *token_ptr;
	gss_ctx_id_t *gss_context = &my_context;
	gss_buffer_desc name_buf;
	gss_name_t service_name_e;
	OM_uint32 major_status, minor_status, init_sec_min_stat;
	OM_uint32 ret_flags;

	/* Getting an initial ticket is outside the scope of GSS, so
	   we use Kerberos calls here.  */

	int krberr;
	krb5_creds my_creds;
	int have_creds = 0;
	const char *krb5_client_name;
	char *slashptr;
	char host_name[255];
	struct stat st;
	const char *key_file;

	token_ptr = GSS_C_NO_BUFFER;
	*gss_context = GSS_C_NO_CONTEXT;
	recv_tok.value = NULL;

	krberr = krb5_init_context (&kcontext);
	if (krberr) {
		KLOG (krberr, "krb5_init_context");
		return -1;
	}

	if (config.krb5_key_file)
		key_file = config.krb5_key_file;
	else
		key_file = KEYTAB_NAME;
	unsetenv ("KRB5_KTNAME");
	setenv ("KRB5_KTNAME", key_file, 1);

	if (stat (key_file, &st) == 0) {
		if ((st.st_mode & 07777) != 0400) {
			if (!quiet)
				syslog (LOG_ERR,
			"%s is not mode 0400 (it's %#o) - compromised key?",
					key_file, st.st_mode & 07777);
			goto error1;
		}
		if (st.st_uid != 0) {
			if (!quiet)
				syslog (LOG_ERR,
			"%s is not owned by root (it's %d) - compromised key?",
					key_file, st.st_uid);
			goto error1;
		}
	}

	/* This looks up the default real (*our* realm) from
	   /etc/krb5.conf (or wherever)  */
	krberr = krb5_get_default_realm (kcontext, &realm_name);
	if (krberr) {
		KLOG (krberr, "krb5_get_default_realm");
		goto error1;
	}

	krb5_client_name = config.krb5_client_name ?
				config.krb5_client_name : "auditd";
	if (gethostname(host_name, sizeof(host_name)) != 0) {
		if (!quiet)
			syslog (LOG_ERR,
			"gethostname: host name longer than %lu characters?",
				sizeof (host_name));
		goto error2;
	}

	syslog (LOG_ERR, "kerberos principal: %s/%s@%s\n",
		krb5_client_name, host_name, realm_name);
	/* Encode our own "name" as auditd/remote@EXAMPLE.COM.  */
	krberr = krb5_build_principal (kcontext, &audit_princ,
				       strlen(realm_name), realm_name,
				       krb5_client_name, host_name, NULL);
	if (krberr) {
		KLOG (krberr, "krb5_build_principal");
		goto error2;
	}

	/* Locate our machine's key table, where our private key is
	 * held.  */
	krberr = krb5_kt_resolve (kcontext, key_file, &keytab);
	if (krberr) {
		KLOG (krberr, "krb5_kt_resolve");
		goto error3;
	}

	/* Identify a cache to hold the key in.  The GSS wrappers look
	   up our credentials here.  */
	krberr = krb5_cc_resolve (kcontext, CCACHE_NAME, &ccache);
	if (krberr) {
		KLOG (krberr, "krb5_cc_resolve");
		goto error4;
	}

	setenv("KRB5CCNAME", CCACHE_NAME, 1);

	memset(&my_creds, 0, sizeof(my_creds));
	memset(&options, 0, sizeof(options));
	krb5_get_init_creds_opt_set_address_list(&options, NULL);
	krb5_get_init_creds_opt_set_forwardable(&options, 0);
	krb5_get_init_creds_opt_set_proxiable(&options, 0);
	krb5_get_init_creds_opt_set_tkt_life(&options, 24*60*60);

	/* Load our credentials from the key table.  */
	krberr = krb5_get_init_creds_keytab(kcontext, &my_creds, audit_princ,
					    keytab, 0, NULL,
					    &options);
	if (krberr) {
		KLOG (krberr, "krb5_get_init_creds_keytab");
		goto error5;
	}
	have_creds = 1;

	/* Create the cache... */
	krberr = krb5_cc_initialize(kcontext, ccache, audit_princ);
	if (krberr) {
		KLOG (krberr, "krb5_cc_initialize");
		goto error5;
	}

	/* ...and store our credentials in it.  */
	krberr = krb5_cc_store_cred(kcontext, ccache, &my_creds);
	if (krberr) {
		KLOG (krberr, "krb5_cc_store_cred");
		goto error5;
	}

	/* The GSS code now has a set of credentials for this program.
	   I.e.  we know who "we" are.  Now we talk to the server to
	   get its credentials and set up a security context for encryption. */
	if (config.krb5_principal == NULL) {
		const char *name = config.krb5_client_name ?
					config.krb5_client_name : "auditd";
		size_t length = strlen(name) + 1 +
				strlen(config.remote_server) + 1;
		config.krb5_principal = malloc(length);
		snprintf(config.krb5_principal, length, "%s@%s",
			name, config.remote_server);
	}
	slashptr = strchr(config.krb5_principal, '/');
	if (slashptr)
		*slashptr = '@';

	name_buf.value = config.krb5_principal;
	name_buf.length = strlen(name_buf.value) + 1;
	major_status = gss_import_name(&minor_status, &name_buf,
			       (gss_OID) gss_nt_service_name, &service_name_e);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("importing name", major_status, minor_status);
		goto error5;
	}

	/* Someone has to go first.  In this case, it's us.  */
	if (send_token(sock, empty_token) < 0) {
		(void) gss_release_name(&minor_status, &service_name_e);
		goto error5;
	}

	/* The server starts this loop with the token we just sent
	   (the empty one).  We start this loop with "no token".  */
	token_ptr = GSS_C_NO_BUFFER;
	*gss_context = GSS_C_NO_CONTEXT;

	do {
		/* Give GSS a chance to digest what we have so far.  */
		major_status = gss_init_sec_context(&init_sec_min_stat,
			GSS_C_NO_CREDENTIAL, gss_context,
			service_name_e, NULL, REQ_FLAGS, 0,
			NULL,			/* no channel bindings */
			token_ptr, NULL,	/* ignore mech type */
			&send_tok, &ret_flags, NULL);	/* ignore time_rec */

		if (token_ptr != GSS_C_NO_BUFFER)
			free(recv_tok.value);

		/* Send the server any tokens requested of us.  */
		if (send_tok.length != 0) {
			if (send_token(sock, &send_tok) < 0) {
				(void) gss_release_buffer(&minor_status,
						&send_tok);
				(void) gss_release_name(&minor_status,
						&service_name_e);
				goto error5;
			}
		}
		(void) gss_release_buffer(&minor_status, &send_tok);

		if (major_status != GSS_S_COMPLETE
		    && major_status != GSS_S_CONTINUE_NEEDED) {
			gss_failure("initializing context", major_status,
				    init_sec_min_stat);
			(void) gss_release_name(&minor_status, &service_name_e);
			if (*gss_context != GSS_C_NO_CONTEXT)
				gss_delete_sec_context(&minor_status,
						gss_context, GSS_C_NO_BUFFER);
			goto error5;
		}

		/* Now get any tokens the sever sends back.  We use
		   these back at the top of the loop.  */
		if (major_status == GSS_S_CONTINUE_NEEDED) {
			if (recv_token(sock, &recv_tok) < 0) {
				(void) gss_release_name(&minor_status,
							&service_name_e);
				goto error5;
			}
			token_ptr = &recv_tok;
		}
	} while (major_status == GSS_S_CONTINUE_NEEDED);

	(void) gss_release_name(&minor_status, &service_name_e);

#if 0
	major_status = gss_inquire_context (&minor_status, &my_context, NULL,
					    &service_name_e, NULL, NULL,
					    NULL, NULL, NULL);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("inquiring target name", major_status, minor_status);
		return -1;
	}
	major_status = gss_display_name(&minor_status, service_name_e,
					&recv_tok, NULL);
	gss_release_name(&minor_status, &service_name_e);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("displaying name", major_status, minor_status);
		return -1;
	}
	syslog(LOG_INFO, "GSS-API Connected to: %s",
		  (char *)recv_tok.value);
#endif
	krb5_free_cred_contents(kcontext, &my_creds);
	return 0;

error5:
	if (have_creds)
		krb5_free_cred_contents(kcontext, &my_creds);
	krb5_cc_close(kcontext, ccache);
	ccache = NULL;
error4:
	krb5_kt_close(kcontext, keytab);
	keytab = NULL;
error3:
	krb5_free_principal(kcontext, audit_princ);
error2:
	krb5_free_default_realm(kcontext, realm_name);
	realm_name = NULL;
error1:
	krb5_free_context(kcontext);
	kcontext = NULL;
	return -1;
}
#endif // USE_GSSAPI

#ifdef HAVE_TLS

/* PSK callback data for TLS 1.3 */
static unsigned char *psk_key = NULL;
static size_t psk_key_len = 0;
static char psk_identity_buf[256];

/*
 * tls_psk_use_session_cb - TLS 1.3 client PSK callback
 * @ssl: SSL connection handle
 * @md: hash algorithm hint from OpenSSL, or NULL
 * @id: output PSK identity to present to server
 * @idlen: output PSK identity length
 * @sess: output SSL_SESSION containing the PSK
 *
 * Called by OpenSSL during TLS 1.3 handshake to supply the external PSK.
 * Builds a session from the configured PSK key and identity.
 * Returns 1 on success, 0 on failure.
 */
static int tls_psk_use_session_cb(SSL *ssl, const EVP_MD *md,
		const unsigned char **id, size_t *idlen,
		SSL_SESSION **sess)
{
	SSL_SESSION *s;
	const SSL_CIPHER *cipher;
	const char *identity;

	if (psk_key == NULL || psk_key_len == 0)
		return 0;

	identity = psk_identity_buf;

	cipher = autls_find_tls13_cipher(ssl, md);
	if (cipher == NULL) {
		syslog(LOG_ERR, "Unable to find suitable TLS 1.3 cipher");
		return 0;
	}

	s = SSL_SESSION_new();
	if (s == NULL)
		return 0;

	if (!SSL_SESSION_set1_master_key(s, psk_key, psk_key_len) ||
	    !SSL_SESSION_set_cipher(s, cipher) ||
	    !SSL_SESSION_set_protocol_version(s, TLS1_3_VERSION)) {
		SSL_SESSION_free(s);
		return 0;
	}

	*id = (const unsigned char *)identity;
	*idlen = strlen(identity);
	*sess = s;

	return 1;
}

/*
 * init_tls_context - create and configure the client SSL_CTX
 *
 * Sets up TLS 1.3 with the configured cipher suites, key exchange
 * groups, and either PSK or certificate authentication.
 * Returns 0 on success, -1 on error.
 */
static int init_tls_context(void)
{
	const char *cipher_suites;
	const char *key_exchange;

	tls_ctx = SSL_CTX_new(TLS_client_method());
	if (tls_ctx == NULL) {
		syslog(LOG_ERR, "Unable to create TLS context");
		return -1;
	}

	/* TLS 1.3 minimum */
	if (!SSL_CTX_set_min_proto_version(tls_ctx, TLS1_3_VERSION)) {
		syslog(LOG_ERR, "Unable to set TLS 1.3 minimum version");
		goto err;
	}

	/* Disable 0-RTT to prevent audit event replay */
	if (!SSL_CTX_set_max_early_data(tls_ctx, 0)) {
		syslog(LOG_ERR, "Unable to disable TLS early data");
		goto err;
	}

	SSL_CTX_set_options(tls_ctx, SSL_OP_NO_COMPRESSION);

	/* Disable session resumption -- force fresh PQC key exchange */
	SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_options(tls_ctx, SSL_OP_NO_TICKET);

	/* Configure cipher suites */
	cipher_suites = config.tls_cipher_suites ?
		config.tls_cipher_suites :
		"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
	if (!SSL_CTX_set_ciphersuites(tls_ctx, cipher_suites)) {
		syslog(LOG_ERR, "Unable to set TLS cipher suites");
		goto err;
	}

	/* Configure key exchange groups (PQC hybrid first) */
	key_exchange = config.tls_key_exchange ?
		config.tls_key_exchange : "X25519MLKEM768:X25519";
	if (!SSL_CTX_set1_groups_list(tls_ctx, key_exchange)) {
		ERR_clear_error();
		if (config.tls_require_pqc || config.tls_key_exchange) {
			syslog(LOG_ERR,
				"Unable to set key exchange groups '%s'",
				key_exchange);
			goto err;
		}
		syslog(LOG_WARNING,
			"PQC key exchange groups not available, "
			"falling back to X25519");
		if (!SSL_CTX_set1_groups_list(tls_ctx, "X25519")) {
			syslog(LOG_ERR,
				"Unable to set any key exchange groups");
			goto err;
		}
	}

	/* PSK mode */
	if (config.tls_psk_file) {
		if (autls_load_psk(config.tls_psk_file,
				&psk_key, &psk_key_len, syslog))
			goto err;

		SSL_CTX_set_psk_use_session_callback(tls_ctx,
						tls_psk_use_session_cb);
		{
			const char *id = config.tls_psk_identity ?
				config.tls_psk_identity : "audit-client";
			if (strlen(id) >= sizeof(psk_identity_buf)) {
				syslog(LOG_ERR,
					"PSK identity too long (max %zu bytes)",
					sizeof(psk_identity_buf) - 1);
				goto err;
			}
			snprintf(psk_identity_buf,
				sizeof(psk_identity_buf), "%s", id);
		}
	}

	/* Certificate mode */
	if (config.tls_cert_file) {
		if (SSL_CTX_use_certificate_chain_file(tls_ctx,
				config.tls_cert_file) != 1) {
			syslog(LOG_ERR, "Unable to load TLS certificate %s",
				config.tls_cert_file);
			goto err;
		}
	}

	if (config.tls_key_file) {
		if (autls_validate_key_file(config.tls_key_file,
				syslog) != 0)
			goto err;

		if (SSL_CTX_use_PrivateKey_file(tls_ctx,
				config.tls_key_file,
				SSL_FILETYPE_PEM) != 1) {
			syslog(LOG_ERR, "Unable to load TLS private key %s",
				config.tls_key_file);
			goto err;
		}
	}

	/* Verify cert and key match */
	if (config.tls_cert_file && config.tls_key_file) {
		if (SSL_CTX_check_private_key(tls_ctx) != 1) {
			syslog(LOG_ERR,
				"TLS certificate and private key do not match");
			goto err;
		}
	}

	/* Server certificate verification */
	if (config.tls_ca_file) {
		if (SSL_CTX_load_verify_locations(tls_ctx,
				config.tls_ca_file, NULL) != 1) {
			syslog(LOG_ERR,
				"Unable to load TLS CA file %s",
				config.tls_ca_file);
			goto err;
		}
		SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, NULL);
	} else if (!config.tls_psk_file) {
		syslog(LOG_NOTICE,
			"tls_ca_file not set, using system CA store "
			"for server verification");
		SSL_CTX_set_default_verify_paths(tls_ctx);
		SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, NULL);
	}

	return 0;
err:
	if (psk_key) {
		OPENSSL_cleanse(psk_key, psk_key_len);
		OPENSSL_free(psk_key);
		psk_key = NULL;
		psk_key_len = 0;
	}
	SSL_CTX_free(tls_ctx);
	tls_ctx = NULL;
	return -1;
}

static void destroy_tls_context(void)
{
	if (tls_ssl) {
		autls_ssl_shutdown(tls_ssl);
		SSL_free(tls_ssl);
		tls_ssl = NULL;
	}
	if (tls_ctx) {
		SSL_CTX_free(tls_ctx);
		tls_ctx = NULL;
	}
	if (psk_key) {
		OPENSSL_cleanse(psk_key, psk_key_len);
		OPENSSL_free(psk_key);
		psk_key = NULL;
		psk_key_len = 0;
	}
}

static int tls_error_cb(const char *str, size_t len, void *u)
{
	syslog(LOG_ERR, "TLS error: %.*s", (int)len, str);
	return 1;
}

/*
 * tls_connect - establish a TLS connection to the remote collector
 *
 * Creates an SSL session on the open socket, performs hostname
 * verification when server certificate checking is active, and
 * enforces PQC key exchange when tls_require_pqc is set.
 * Returns 0 on success, -1 on error.
 */
static int tls_connect(void)
{
	const char *kex_name;

	tls_ssl = SSL_new(tls_ctx);
	if (tls_ssl == NULL) {
		syslog(LOG_ERR, "Unable to create TLS session");
		return -1;
	}

	if (SSL_set_fd(tls_ssl, sock) != 1) {
		syslog(LOG_ERR, "Unable to attach TLS to socket");
		SSL_free(tls_ssl);
		tls_ssl = NULL;
		return -1;
	}

	/* Hostname verification when server cert verification is active */
	if (SSL_CTX_get_verify_mode(tls_ctx) & SSL_VERIFY_PEER) {
		struct in_addr ipv4;
		struct in6_addr ipv6;
		if (inet_pton(AF_INET, config.remote_server, &ipv4) == 1 ||
		    inet_pton(AF_INET6, config.remote_server, &ipv6) == 1) {
			/* IP address: verify against IP SANs */
			X509_VERIFY_PARAM *param = SSL_get0_param(tls_ssl);
			X509_VERIFY_PARAM_set1_ip_asc(param,
				config.remote_server);
		} else {
			/* Hostname: set SNI and verify against DNS SANs */
			SSL_set_tlsext_host_name(tls_ssl,
				config.remote_server);
			SSL_set1_host(tls_ssl, config.remote_server);
		}
	}

	/* Bound the blocking SSL_connect so a blackholed server cannot
	 * stall the client indefinitely */
	{
		struct timeval tv;
		tv.tv_sec = config.max_time_per_record;
		tv.tv_usec = 0;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv,
			sizeof(tv));
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv,
			sizeof(tv));
	}

	if (SSL_connect(tls_ssl) != 1) {
		syslog(LOG_ERR, "TLS handshake with %s failed",
			config.remote_server);
		ERR_print_errors_cb(tls_error_cb, NULL);
		SSL_free(tls_ssl);
		tls_ssl = NULL;
		return -1;
	}



#ifdef HAVE_SSL_GROUP_TO_NAME
	kex_name = SSL_group_to_name(tls_ssl,
			SSL_get_negotiated_group(tls_ssl));
#else
	kex_name = NULL;
#endif
	syslog(LOG_NOTICE, "TLS connected to %s using %s kex=%s",
		config.remote_server, SSL_get_cipher(tls_ssl),
		kex_name ? kex_name : "unknown");

	if (config.tls_require_pqc && !autls_is_pqc_group(kex_name)) {
		syslog(LOG_ERR,
			"PQC key exchange required but negotiated "
			"group '%s' is not PQC",
			kex_name ? kex_name : "unknown");
		tls_disconnect();
		return -1;
	}

	/* Set receive timeout so SSL_read does not block indefinitely
	 * on a network partition without TCP RST */
	{
		struct timeval tv;
		tv.tv_sec = config.max_time_per_record;
		tv.tv_usec = 0;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	return 0;
}

static void tls_disconnect(void)
{
	if (tls_ssl) {
		autls_ssl_shutdown(tls_ssl);
		SSL_free(tls_ssl);
		tls_ssl = NULL;
	}
}

/* TLS I/O wrapper for reads with configurable timeout */

static int tls_read(SSL *ssl, void *buf, int len)
{
	int rc = 0, r, remaining;
	int timeout_ms = config.max_time_per_record > (unsigned)(INT_MAX / 1000)
		? INT_MAX : (int)(config.max_time_per_record * 1000);
	struct pollfd pfd;
	struct timespec deadline;

	pfd.fd = SSL_get_fd(ssl);
	if (pfd.fd < 0)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += timeout_ms / 1000;
	deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	while (len > 0) {
		r = SSL_read(ssl, buf, len);
		if (r <= 0) {
			int err = SSL_get_error(ssl, r);
			if (err == SSL_ERROR_WANT_READ)
				pfd.events = POLLIN;
			else if (err == SSL_ERROR_WANT_WRITE)
				pfd.events = POLLOUT;
			else
				return -1;
			remaining = autls_remaining_ms(&deadline);
			if (remaining <= 0)
				return -1;
			{
				int prc;
				do {
					prc = poll(&pfd, 1, remaining);
				} while (prc < 0 && errno == EINTR);
				if (prc <= 0)
					return -1;
			}
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
				return -1;
			continue;
		}
		rc += r;
		buf = (char *)buf + r;
		len -= r;
	}
	return rc;
}

static int send_msg_tls(unsigned char *header, const char *msg, uint32_t mlen)
{
	unsigned char buf[AUDIT_RMW_HEADER_SIZE + MAX_AUDIT_MESSAGE_LENGTH];
	int total;

	memcpy(buf, header, AUDIT_RMW_HEADER_SIZE);
	total = AUDIT_RMW_HEADER_SIZE;

	if (msg != NULL && mlen > 0) {
		if (mlen > MAX_AUDIT_MESSAGE_LENGTH) {
			syslog(LOG_ERR,
				"TLS message length %u exceeds maximum",
				mlen);
			return -1;
		}
		memcpy(buf + AUDIT_RMW_HEADER_SIZE, msg, mlen);
		total += mlen;
	}

	{
		int wt = config.max_time_per_record > (unsigned)(INT_MAX / 1000)
			? INT_MAX : (int)(config.max_time_per_record * 1000);
		if (autls_ssl_write(tls_ssl, buf, total, wt) < 0) {
			syslog(LOG_ERR, "TLS send to %s failed",
				config.remote_server);
			return -1;
		}
	}
	return 0;
}

static int recv_msg_tls(unsigned char *header, char *msg, uint32_t *mlen)
{
	int hver, mver;
	uint32_t type, rlen, seq;

	if (tls_read(tls_ssl, header, AUDIT_RMW_HEADER_SIZE) < 0) {
		syslog(LOG_ERR, "TLS read from %s failed",
			config.remote_server);
		return -1;
	}

	if (!AUDIT_RMW_IS_MAGIC(header, AUDIT_RMW_HEADER_SIZE)) {
		sync_error_handler("bad magic number");
		return -1;
	}

	AUDIT_RMW_UNPACK_HEADER(header, hver, mver, type, rlen, seq);

	if (rlen > MAX_AUDIT_MESSAGE_LENGTH) {
		sync_error_handler("message too long");
		return -1;
	}

	if (rlen > 0 && tls_read(tls_ssl, msg, rlen) < 0) {
		sync_error_handler("ran out of data reading reply");
		return -1;
	}

	*mlen = rlen;
	return 0;
}
#endif /* HAVE_TLS */

static int stop_sock(void)
{
	if (sock >= 0) {
#ifdef HAVE_TLS
		if (USE_TLS)
			tls_disconnect();
#endif
#ifdef USE_GSSAPI
		if (USE_GSS) {
			if (my_context != GSS_C_NO_CONTEXT) {
				OM_uint32 minor_status;
				gss_delete_sec_context(&minor_status, &my_context,
							GSS_C_NO_BUFFER);
				my_context = GSS_C_NO_CONTEXT;
			}

			if (kcontext != NULL) {
				if (ccache != NULL) {
					krb5_cc_close(kcontext, ccache);
					ccache = NULL;
				}
				if (keytab != NULL) {
					krb5_kt_close(kcontext, keytab);
					keytab = NULL;
				}
				if (audit_princ != NULL) {
					krb5_free_principal(kcontext, audit_princ);
					audit_princ = NULL;
				}
				if (realm_name != NULL) {
					krb5_free_default_realm(kcontext, realm_name);
					realm_name = NULL;
				}
				krb5_free_context(kcontext);
				kcontext = NULL;
			}
		}
#endif
		shutdown(sock, SHUT_RDWR);
		close(sock);
	}
	sock = -1;
	transport_ok = 0;

	return 0;
}

static int stop_transport(void)
{
	int rc;

	switch (config.transport)
	{
		case T_TCP:
		case T_TLS:
		case T_KRB5:
			rc = stop_sock();
			break;
		default:
			rc = -1;
			break;
	}
	return rc;
}

static int init_sock(void)
{
	int rc;
	struct addrinfo *ai, *runp;
	struct addrinfo hints;
	char remote[BUF_SIZE];
	int one=1;

	if (sock >= 0) {
		syslog(LOG_NOTICE, "socket already setup");
		transport_ok = 1;
		return ET_SUCCESS;
	}

	// Resolve the remote host
	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG|AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(remote, BUF_SIZE, "%u", config.port);
	rc = getaddrinfo(config.remote_server, remote, &hints, &ai);
	if (rc) {
		if (!quiet)
			syslog(LOG_ERR,
				"Error looking up remote host: %s - exiting",
				gai_strerror(rc));
		if (rc == EAI_NONAME || rc == EAI_NODATA)
			return ET_PERMANENT;
		else
			return ET_TEMPORARY;
	}

	// Cycle through the list until we connect
	runp = ai;
	while (runp) {
		if (sock >= 0)
			close(sock);
		sock = socket(runp->ai_family, runp->ai_socktype,
					runp->ai_protocol);
		if (sock < 0) {
			if (!quiet)
				syslog(LOG_ERR, "Error creating socket: %s",
				strerror(errno));
			goto next_try;
		}

		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
					(char *)&one, sizeof (int));

		// If we are binding, resolve something relative to
		// the address of the aggregating server
		if (config.local_port != 0) {
			struct addrinfo *ai2;
			struct addrinfo hints2;
			char local[BUF_SIZE];

			// Ask for setting that can be used for bind
			memset(&hints2, '\0', sizeof(hints2));
			hints2.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
			hints2.ai_socktype = SOCK_STREAM;
			hints2.ai_family = runp->ai_family;
			hints2.ai_protocol = runp->ai_protocol;
			snprintf(local, BUF_SIZE, "%u", config.local_port);

			rc = getaddrinfo(NULL, local, &hints2, &ai2);
			if (rc) {
				if (!quiet)
					syslog(LOG_ERR,
				"Error looking up local host: %s - retrying",
						gai_strerror(rc));
				stop_sock();
				goto next_try;
			}
			// We are not going to cycle through the list.
			// If done right only one should be on list.
			if (bind(sock,  ai2->ai_addr, ai2->ai_addrlen)) {
				if (!quiet)
					syslog(LOG_ERR,
				       "Cannot bind local socket to port %u",
						config.local_port);
				stop_sock();
				freeaddrinfo(ai2);
				goto next_try;
			}
			freeaddrinfo(ai2);
		}
		if (connect(sock, runp->ai_addr, runp->ai_addrlen)) {
			if (!quiet)
				syslog(LOG_ERR, "Error connecting to %s: %s",
					config.remote_server, strerror(errno));
			stop_sock();
		} else
			break;	// Success, quit trying
next_try:
		runp = runp->ai_next;
	}
	// If the list was exhausted and no connection, we failed.
	if (runp == NULL) {
		rc = ET_PERMANENT;
		goto out;
	}
	rc = ET_SUCCESS;
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof (int));

	/* The idea here is to minimize the time between the message
	   and the ACK, assuming that individual messages are
	   infrequent enough that we can ignore the inefficiency of
	   sending the header and message in separate packets.  */
	if (config.format == F_MANAGED)
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
				(char *)&one, sizeof (int));

#ifdef HAVE_TLS
	if (USE_TLS) {
		if (tls_ctx == NULL && init_tls_context()) {
			close(sock);
			sock = -1;
			rc = ET_PERMANENT;
			goto out;
		}
		if (tls_connect()) {
			close(sock);
			sock = -1;
			rc = ET_PERMANENT;
			goto out;
		}
	}
#endif
#ifdef USE_GSSAPI
	if (USE_GSS) {
		if (negotiate_credentials()) {
			rc = ET_PERMANENT;
			goto out;
		}
	}
#endif

	transport_ok = 1;
	syslog(LOG_NOTICE, "Connected to %s", config.remote_server);
out:
	freeaddrinfo(ai);
	return rc;
}

static int init_transport(void)
{
	int rc;

	switch (config.transport)
	{
		case T_TCP:
		case T_TLS:
		case T_KRB5:
			rc = init_sock();
			// We set this so that it will retry the connection
			if (rc == ET_TEMPORARY)
				remote_ended = 1;
			break;
		default:
			rc = ET_PERMANENT;
			break;
	}
	return rc;
}

static int ar_write (int sk, const void *buf, int len)
{
	int rc = 0, r;
	while (len > 0) {
		do {
			r = write(sk, buf, len);
		} while (r < 0 && errno == EINTR);
		if (r < 0) {
			if (errno == EPIPE)
				stop_sock();
			return r;
		}
		if (r == 0)
			break;
		rc += r;
		buf = (void *)((char *)buf + r);
		len -= r;
	}
	return rc;
}

// Returns positive number on success, -1 on failure
static int ar_read (int sk, void *buf, int len)
{
	int rc = 0, r, timeout = config.max_time_per_record * 1000;
	struct pollfd pfd;

	errno = 0;
	pfd.fd = sk;
	pfd.events = POLLIN | POLLPRI | POLLHUP | POLLERR | POLLNVAL;
	while (len > 0) {
		do {
			// Reads can hang if cable is disconnected
			int prc = poll(&pfd, (nfds_t) 1, timeout);
			if (prc <= 0)
				return -1;
			r = read(sk, buf, len);
		} while (r < 0 && errno == EINTR);
		if (r < 0) {
			// This means real network problem happened
			if (errno == EPIPE)
				stop_sock();
			return r;
		}
		if (r == 0) {
			// If errno == 0, remote end closed socket normally
			if (errno == 0) {
				stop_sock();
				remote_ended = 1;
			}
			break;
		}
		rc += r;
		buf = (void *)((char *)buf + r);
		len -= r;
	}
	return rc;
}

static int relay_sock_ascii(const char *s, size_t len)
{
	int rc;

	if (len == 0)
		return 0;

	if (!transport_ok) {
		if (init_transport ())
			return -1;
	}

	rc = ar_write(sock, s, len);
	if (rc <= 0) {
		stop = 1;
		stop_transport();
		syslog(LOG_ERR,"Connection to %s closed unexpectedly - exiting",
		       config.remote_server);
		return -1;
	}

	return 0;
}

#ifdef USE_GSSAPI

/* Sending an encrypted message is pretty simple - wrap the message in
   a token, and send the token.  The server unwraps it to get the
   original message.  */
static int send_msg_gss (unsigned char *header, const char *msg, uint32_t mlen)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc utok, etok;
	int rc;

	utok.length = AUDIT_RMW_HEADER_SIZE + mlen;
	utok.value = malloc (utok.length);

	memcpy (utok.value, header, AUDIT_RMW_HEADER_SIZE);

	if (msg != NULL && mlen > 0)
		memcpy (utok.value+AUDIT_RMW_HEADER_SIZE, msg, mlen);

	major_status = gss_wrap (&minor_status,
				 my_context,
				 1,
				 GSS_C_QOP_DEFAULT,
				 &utok,
				 NULL,
				 &etok);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("encrypting message", major_status, minor_status);
		free (utok.value);
		return -1;
	}
	rc = send_token (sock, &etok);
	free (utok.value);
	(void) gss_release_buffer(&minor_status, &etok);

	return rc ? -1 : 0;
}

/* Likewise here.  */
static int recv_msg_gss (unsigned char *header, char *msg, uint32_t *mlen)
{
	OM_uint32 major_status, minor_status;
	gss_buffer_desc utok, etok;
	int hver, mver, rc;
	uint32_t type, rlen, seq;

	rc = recv_token (sock, &etok);
	if (rc)
		return -1;

	major_status = gss_unwrap (&minor_status, my_context, &etok,
					&utok, NULL, NULL);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("decrypting message", major_status, minor_status);
		free (utok.value);
		free (etok.value);
		return -1;
	}

	if (utok.length < AUDIT_RMW_HEADER_SIZE) {
		sync_error_handler ("message too short");
		free (utok.value);
		free (etok.value);
		return -1;
	}
	memcpy (header, utok.value, AUDIT_RMW_HEADER_SIZE);

	if (! AUDIT_RMW_IS_MAGIC (header, AUDIT_RMW_HEADER_SIZE)) {
		sync_error_handler ("bad magic number");
		free (utok.value);
		free (etok.value);
		return -1;
	}

	AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, rlen, seq);

	if (rlen > MAX_AUDIT_MESSAGE_LENGTH) {
		sync_error_handler ("message too long");
		free (utok.value);
		free (etok.value);
		return -1;
	}

	memcpy (msg, utok.value+AUDIT_RMW_HEADER_SIZE, rlen);

	*mlen = rlen;

	free (utok.value);
	free (etok.value);
	return 0;
}
#endif // USE_GSSAPI

static int send_msg_tcp (unsigned char *header, const char *msg, uint32_t mlen)
{
	int rc;

	rc = ar_write(sock, header, AUDIT_RMW_HEADER_SIZE);
	if (rc <= 0) {
		syslog(LOG_ERR, "send to %s failed", config.remote_server);
		return 1;
	}

	if (msg != NULL && mlen > 0) {
		rc = ar_write(sock, msg, mlen);
		if (rc <= 0) {
			syslog(LOG_ERR, "send to %s failed",
				config.remote_server);
			return 1;
		}
	}
	return 0;
}

// Returns 0 on success and -1 on failure
static int recv_msg_tcp (unsigned char *header, char *msg, uint32_t *mlen)
{
	int hver, mver, rc;
	uint32_t type, rlen, seq;

	errno = 0;
	rc = ar_read (sock, header, AUDIT_RMW_HEADER_SIZE);
	if (rc < 16) {
		if (rc == -1 && errno == 0)
			syslog(LOG_ERR, "ack from %s timed out",
						config.remote_server);
		else
			syslog(LOG_ERR, "read from %s failed",
						config.remote_server);
		return -1;
	}

	if (! AUDIT_RMW_IS_MAGIC (header, AUDIT_RMW_HEADER_SIZE)) {
		/* close the socket and start a new one.  */
		sync_error_handler ("bad magic number");
		stop_transport();
		init_transport();
		return -1;

	}

	AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, rlen, seq);

	if (rlen > MAX_AUDIT_MESSAGE_LENGTH) {
		sync_error_handler ("message too long");
		return -1;
	}

	if (rlen > 0 && ar_read (sock, msg, rlen) < rlen) {
		sync_error_handler ("ran out of data reading reply");
		return -1;
	}
	return 0;
}

static int check_message_managed(void)
{
	unsigned char header[AUDIT_RMW_HEADER_SIZE];
	int hver, mver;
	uint32_t type, rlen, seq;
	char msg[MAX_AUDIT_MESSAGE_LENGTH+1];

#ifdef HAVE_TLS
	if (USE_TLS) {
		if (recv_msg_tls (header, msg, &rlen)) {
			stop_transport();
			return -1;
		}
	} else
#endif
#ifdef USE_GSSAPI
	if (USE_GSS) {
		if (recv_msg_gss (header, msg, &rlen)) {
			stop_transport();
			return -1;
		}
	} else
#endif
	if (recv_msg_tcp(header, msg, &rlen)) {
		stop_transport();
		return -1;
	}

	AUDIT_RMW_UNPACK_HEADER(header, hver, mver, type, rlen, seq);
	msg[rlen] = 0;

	if (type == AUDIT_RMW_TYPE_ENDING)
		return remote_server_ending_handler(msg);
	if (type == AUDIT_RMW_TYPE_DISKLOW)
		return remote_disk_low_handler(msg);
	if (type == AUDIT_RMW_TYPE_DISKFULL) {
		// Can't log for a while might want a delay
		stop_transport();
		return remote_disk_full_handler(msg);
	}
	if (type == AUDIT_RMW_TYPE_DISKERROR) {
		// Can't log for a while might want a delay
		stop_transport();
		return remote_disk_error_handler(msg);
	}
	return 0;
}

/* If this gets called, it most likely means that the remote end died.
 * We need to try a read to get the EPIPE so that we can close out the
 * connection. */
static int check_message_ascii(void)
{
	int rc;
	char buf[64];

	rc = ar_read(sock, buf, sizeof(buf));
	if (rc <= 0 || remote_ended)
		stop = 1;

	return 0;
}

/* This is to check for async notification like server is shutting down */
static int check_message(void)
{
	int rc;

	switch (config.format)
	{
		case F_MANAGED:
			rc = check_message_managed();
			break;
		case F_ASCII:
			rc = check_message_ascii();
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}

static int relay_sock_managed(const char *s, size_t len)
{
	static int sequence_id = 1;
	unsigned char header[AUDIT_RMW_HEADER_SIZE];
	int hver, mver;
	uint32_t type, rlen, seq;
	char msg[MAX_AUDIT_MESSAGE_LENGTH+1];
	unsigned int n_tries_this_message = 0;
	time_t now, then = 0;

	sequence_id ++;

try_again:
	time (&now);
	if (then == 0)
		then = now;

	/* We want the first retry to be quick, in case the network
	   failed for some fail-once reason.  In this case, it goes
	   "failure - reconnect - send".  Only if this quick retry
	   fails do we start pausing between retries to prevent
	   swamping the local computer and the network.  */
	if (n_tries_this_message > 1)
		sleep (config.network_retry_time);

	if (n_tries_this_message > config.max_tries_per_record) {
		network_failure_handler ("max retries exhausted");
		return -1;
	}
	if ((now - then) > config.max_time_per_record) {
		network_failure_handler ("max retry time exhausted");
		return -1;
	}

	n_tries_this_message ++;

	if (!transport_ok) {
		if (init_transport ())
			goto try_again;
	}

	type = (s != NULL) ? AUDIT_RMW_TYPE_MESSAGE : AUDIT_RMW_TYPE_HEARTBEAT;
	AUDIT_RMW_PACK_HEADER (header, 0, type, len, sequence_id);

#ifdef HAVE_TLS
	if (USE_TLS) {
		if (send_msg_tls (header, s, len)) {
			stop_transport ();
			goto try_again;
		}
	} else
#endif
#ifdef USE_GSSAPI
	if (USE_GSS) {
		if (send_msg_gss (header, s, len)) {
			stop_transport ();
			goto try_again;
		}
	} else
#endif
	if (send_msg_tcp (header, s, len)) {
		stop_transport ();
		goto try_again;
	}

#ifdef HAVE_TLS
	if (USE_TLS) {
		if (recv_msg_tls (header, msg, &rlen)) {
			stop_transport ();
			goto try_again;
		}
	} else
#endif
#ifdef USE_GSSAPI
	if (USE_GSS) {
		if (recv_msg_gss (header, msg, &rlen)) {
			stop_transport ();
			goto try_again;
		}
	} else
#endif
	if (recv_msg_tcp (header, msg, &rlen)) {
		stop_transport ();
		goto try_again;
	}

	AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, rlen, seq);
	msg[rlen] = 0;

	/* Handle this first. It doesn't matter if seq compares or not
	 * since the other end is going down...deal with it. */
	if (type == AUDIT_RMW_TYPE_ENDING)
		return remote_server_ending_handler (msg);

	if (seq != sequence_id) {
		/* FIXME: should we read another header and
		   see if it matches?  If so, we need to deal
		   with timeouts.  */
		if (sync_error_handler ("mismatched response"))
			return -1;
		stop_transport();
		goto try_again;
	}

	/* Specific errors we know how to deal with.  */
	if (type == AUDIT_RMW_TYPE_DISKLOW)
		return remote_disk_low_handler (msg);
	if (type == AUDIT_RMW_TYPE_DISKFULL) {
		// Can't log for a while might want a delay
		stop_transport();
		return remote_disk_full_handler (msg);
	}
	if (type == AUDIT_RMW_TYPE_DISKERROR) {
		// Can't log for a while might want a delay
		stop_transport();
		return remote_disk_error_handler (msg);
	}

	/* Generic errors.  */
	if (type & AUDIT_RMW_TYPE_FATALMASK)
		return generic_remote_error_handler (msg);
	if (type & AUDIT_RMW_TYPE_WARNMASK)
		return generic_remote_warning_handler (msg);

	return 0;
}

static int relay_sock(const char *s, size_t len)
{
	int rc;

	switch (config.format)
	{
		case F_MANAGED:
			rc = relay_sock_managed (s, len);
			break;
		case F_ASCII:
			rc = relay_sock_ascii (s, len);
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}

/* Send audit event to remote system */
static int relay_event(const char *s, size_t len)
{
	int rc;

	switch (config.transport)
	{
		case T_TCP:
		case T_TLS:
		case T_KRB5:
			rc = relay_sock(s, len);
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}
