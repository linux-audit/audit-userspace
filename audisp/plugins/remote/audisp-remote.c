/* audisp-remote.c --
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
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

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "libaudit.h"
#include "private.h"
#include "remote-config.h"

#define CONFIG_FILE "/etc/audisp/audisp-remote.conf"
#define BUF_SIZE 32

/* Error types */
#define ET_SUCCESS	 0
#define ET_PERMANENT	-1
#define ET_TEMPORARY	-2

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static volatile int suspend = 0;
static remote_conf_t config;
static int sock=-1;

static const char *SINGLE = "1";
static const char *HALT = "0";

static int transport_ok = 0;

/* Local function declarations */
static int relay_event(const char *s, size_t len);
static int init_transport(void);
static int stop_transport(void);


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
	stop_transport ();
	hup = 0;
}

/*
 * SIGSUR2 handler: resume logging
 */
static void user2_handler( int sig )
{
        suspend = 0;
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
	if (config.network_failure_action == FA_SYSLOG)
		syslog (LOG_ERR, "lost/losing sync, %s", why);
	return 0;
}

static void change_runlevel(const char *level)
{
	char *argv[3];
	int pid;
	static const char *init_pgm = "/sbin/init";

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ALERT, 
		       "Audit daemon failed to fork switching runlevels");
		return;
	}
	if (pid)	/* Parent */
		return;
	/* Child */
	argv[0] = (char *)init_pgm;
	argv[1] = (char *)level;
	argv[2] = NULL;
	execve(init_pgm, argv, NULL);
	syslog(LOG_ALERT, "Audit daemon failed to exec %s", init_pgm);
	exit(1);
}

static void safe_exec(const char *exe, const char *message)
{
	char *argv[3];
	int pid;

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ALERT, 
			"Audit daemon failed to fork doing safe_exec");
		return;
	}
	if (pid)	/* Parent */
		return;
	/* Child */
	argv[0] = (char *)exe;
	argv[1] = (char *)message;
	argv[2] = NULL;
	execve(exe, argv, NULL);
	syslog(LOG_ALERT, "Audit daemon failed to exec %s", exe);
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
	case FA_SUSPEND:
		suspend = 1;
		return 0;
	case FA_SINGLE:
		change_runlevel(SINGLE);
		return 1;
	case FA_HALT:
		change_runlevel(HALT);
		return 1;
	case FA_STOP:
		syslog (log_level, "stopping due to %s, %s", desc, message);
		stop = 1;
		return 1;
	}
}

static int network_failure_handler (const char *message)
{
	return do_action ("network failure", message,
			  LOG_WARNING,
			  config.network_failure_action, config.network_failure_exe);
}

static int remote_disk_low_handler (const char *message)
{
	return do_action ("remote disk low", message,
			  LOG_WARNING,
			  config.disk_low_action, config.disk_low_exe);
}

static int remote_disk_full_handler (const char *message)
{
	return do_action ("remote disk full", message,
			  LOG_ERR,
			  config.disk_full_action, config.disk_full_exe);
}

static int remote_disk_error_handler (const char *message)
{
	return do_action ("remote disk error", message,
			  LOG_ERR,
			  config.disk_error_action, config.disk_error_exe);
}

static int remote_server_ending_handler (const char *message)
{
	return do_action ("remote server ending", message,
			  LOG_INFO,
			  config.remote_ending_action, config.remote_ending_exe);
}

static int generic_remote_error_handler (const char *message)
{
	return do_action ("unrecognized remote error", message,
			  LOG_ERR,
			  config.generic_error_action, config.generic_error_exe);
}
static int generic_remote_warning_handler (const char *message)
{
	return do_action ("unrecognized remote warning", message,
			  LOG_WARNING,
			  config.generic_warning_action, config.generic_warning_exe);
}


int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH+1];
	struct sigaction sa;
	int rc;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = user2_handler;
	sigaction(SIGUSR2, &sa, NULL);
	if (load_config(&config, CONFIG_FILE))
		return 6;

	/* We fail here if the transport can't be initialized because
	 * of some permenent (i.e. operator) problem, such as
	 * misspelled host name. */
	rc = init_transport();
	if (rc == ET_PERMANENT)
		return 1;

	syslog(LOG_INFO, "audisp-remote is ready for events");
	do {
		/* Load configuration */
		if (hup) {
			reload_config();
		}


		/* Now the event loop */
		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
							hup==0 && stop==0) {
			if (!suspend) {
				rc = relay_event(tmp, strnlen(tmp,
							      MAX_AUDIT_MESSAGE_LENGTH));
				if (rc < 0) {
					break;
				}
			}
		}
		if (feof(stdin))
			break;
	} while (stop == 0);
	close(sock);
	syslog(LOG_INFO, "audisp-remote is exiting on stop request");

	return 0;
}

static int init_sock(void)
{
	int rc;
	struct addrinfo *ai;
	struct addrinfo hints;
	char remote[BUF_SIZE];
	int one=1;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG|AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(remote, BUF_SIZE, "%u", config.port);
	rc=getaddrinfo(config.remote_server, remote, &hints, &ai);
	if (rc) {
		syslog(LOG_ERR, "Error looking up remote host: %s - exiting",
			gai_strerror(rc));
		return ET_PERMANENT;
	}
	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock < 0) {
		syslog(LOG_ERR, "Error creating socket: %s - exiting",
			strerror(errno));
		freeaddrinfo(ai);
		return ET_TEMPORARY;
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof (int));

	if (config.local_port != 0) {
		struct sockaddr_in address;
		
		memset (&address, 0, sizeof(address));
		address.sin_family = htons(AF_INET);
		address.sin_port = htons(config.local_port);
		address.sin_addr.s_addr = htonl(INADDR_ANY);

		if ( bind ( sock, (struct sockaddr *)&address, sizeof(address)) ) {
			syslog(LOG_ERR, "Cannot bind local socket to port %d - exiting",
			       config.local_port);
			close(sock);
			return ET_TEMPORARY;
		}

	}
	if (connect(sock, ai->ai_addr, ai->ai_addrlen)) {
		syslog(LOG_ERR, "Error connecting to %s: %s - exiting",
			config.remote_server, strerror(errno));
		freeaddrinfo(ai);
		return ET_TEMPORARY;
	}

	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof (int));

	/* The idea here is to minimize the time between the message
	   and the ACK, assuming that individual messages are
	   infrequent enough that we can ignore the inefficiency of
	   sending the header and message in separate packets.  */
	if (config.format == F_MANAGED)
		setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof (int));

	transport_ok = 1;

	freeaddrinfo(ai);
	return ET_SUCCESS;
}

static int init_transport(void)
{
	int rc;

	switch (config.transport)
	{
		case T_TCP:
			rc = init_sock();
			break;
		default:
			rc = ET_PERMANENT;
			break;
	}
	return rc;
}

static int stop_sock(void)
{
	close (sock);
	transport_ok = 0;
}

static int stop_transport(void)
{
	int rc;

	switch (config.transport)
	{
		case T_TCP:
			rc = stop_sock();
			break;
		default:
			rc = -1;
			break;
	}
	return rc;
}

static int ar_write (int sock, const void *buf, int len)
{
	int rc = 0, r;
	while (len > 0) {
		do {
			r = write(sock, buf, len);
		} while (r < 0 && errno == EINTR);
		if (r < 0)
			return r;
		if (r == 0)
			break;
		rc += r;
		buf = (void *)((char *)buf + r);
		len -= r;
	}
	return rc;
}

static int ar_read (int sock, void *buf, int len)
{
	int rc = 0, r;
	while (len > 0) {
		do {
			r = read(sock, buf, len);
		} while (r < 0 && errno == EINTR);
		if (r < 0)
			return r;
		if (r == 0)
			break;
		rc += r;
		buf = (void *)((char *)buf + r);
		len -= r;
	}
	return rc;
}

static int relay_sock_ascii(const char *s, size_t len)
{
	int rc;

	if (!transport_ok)
		if (init_transport ())
			return -1;

	rc = ar_write(sock, s, len);
	if (rc <= 0) {
		stop = 1;
		syslog(LOG_ERR, "connection to %s closed unexpectedly - exiting",
		       config.remote_server);
		return -1;
	}

	return 0;
}

static int relay_sock_managed(const char *s, size_t len)
{
	static int sequence_id = 1;
	int rc;
	unsigned char header[AUDIT_RMW_HEADER_SIZE];
	int hver, mver;
	uint32_t type, rlen, seq;
	char msg[MAX_AUDIT_MESSAGE_LENGTH+1];
	int n_tries_this_message = 0;
	time_t now, then;

	sequence_id ++;

	time (&then);
try_again:
	time (&now);

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

	AUDIT_RMW_PACK_HEADER (header, 0, 0, len, sequence_id);
	rc = ar_write(sock, header, AUDIT_RMW_HEADER_SIZE);
	if (rc <= 0) {
		if (config.network_failure_action == FA_SYSLOG)
			syslog(LOG_ERR, "connection to %s closed unexpectedly",
			       config.remote_server);
		stop_transport();
		goto try_again;
	}

	rc = ar_write(sock, s, len);
	if (rc <= 0) {
		if (config.network_failure_action == FA_SYSLOG)
			syslog(LOG_ERR, "connection to %s closed unexpectedly",
			       config.remote_server);
		stop_transport();
		goto try_again;
	}

	rc = ar_read (sock, header, AUDIT_RMW_HEADER_SIZE);
	if (rc < 16) {
		if (config.network_failure_action == FA_SYSLOG)
			syslog(LOG_ERR, "connection to %s closed unexpectedly",
			       config.remote_server);
		stop_transport();
		goto try_again;
	}


	if (! AUDIT_RMW_IS_MAGIC (header, AUDIT_RMW_HEADER_SIZE)) {
		/* FIXME: the right thing to do here is close the socket and start a new one.  */
		if (sync_error_handler ("bad magic number"))
			return -1;
		stop_transport();
		goto try_again;
	}

	AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, rlen, seq);

	if (rlen > MAX_AUDIT_MESSAGE_LENGTH) {
		if (sync_error_handler ("message too long"))
			return -1;
		stop_transport();
		goto try_again;
	}

	if (rlen > 0
	    && ar_read (sock, msg, rlen) < rlen) {
		if (sync_error_handler ("ran out of data reading reply"))
			return -1;
		stop_transport();
		goto try_again;
	}
	msg[rlen] = 0;

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

	if (type == AUDIT_RMW_TYPE_ENDING)
		return remote_server_ending_handler (msg);
	if (type == AUDIT_RMW_TYPE_DISKLOW)
		return remote_disk_low_handler (msg);
	if (type == AUDIT_RMW_TYPE_DISKFULL)
		return remote_disk_full_handler (msg);
	if (type == AUDIT_RMW_TYPE_DISKERROR)
		return remote_disk_error_handler (msg);

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

static int relay_event(const char *s, size_t len)
{
	int rc;

	switch (config.transport)
	{
		case T_TCP:
			rc = relay_sock(s, len);
			break;
		default:
			rc = -1;
			break;
	}
	return rc;
}

