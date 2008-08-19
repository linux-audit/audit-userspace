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

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static remote_conf_t config;
static int sock=-1;

/* Local function declarations */
static int relay_event(const char *s, size_t len);
static int init_transport(void);


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

/*
 * Handlers for various events coming back from the remote server.
 * Return -1 if the remote dispatcher should exit.
 */

/* Loss of sync - got an invalid response.  */
static int sync_error_handler (const char *why)
{
	/* "why" has human-readable details on why we've lost (or will
	   be losing) sync.  */
	syslog (LOG_ERR, "lost/losing sync, %s", why);
	return -1;
}

static int remote_disk_low_handler (const char *message)
{
	syslog (LOG_WARNING, "remote disk low, %s", message);
	return 0;
}

static int remote_disk_full_handler (const char *message)
{
	syslog (LOG_ERR, "remote disk full, %s", message);
	return -1;
}

static int remote_disk_error_handler (const char *message)
{
	syslog (LOG_ERR, "remote disk error, %s", message);
	return -1;
}

static int remote_server_ending_handler (const char *message)
{
	syslog (LOG_INFO, "remote server ending, %s", message);
	return -1;
}

static int generic_remote_error_handler (const char *message)
{
	stop = 1;
	syslog(LOG_INFO, "audisp-remote: remote error: %s", message);
	return -1;
}
static int generic_remote_warning_handler (const char *message)
{
	syslog(LOG_INFO, "audisp-remote: remote warning: %s", message);
	return 0;
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
	if (load_config(&config, CONFIG_FILE))
		return 6;

	rc = init_transport();
	if (rc < 0)
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
			rc = relay_event(tmp, strnlen(tmp,
						MAX_AUDIT_MESSAGE_LENGTH));
			if (rc < 0) {
				break;
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
		return -1;
	}
	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock < 0) {
		syslog(LOG_ERR, "Error creating socket: %s - exiting",
			strerror(errno));
		freeaddrinfo(ai);
		return -1;
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
			return -1;
		}

	}
	if (connect(sock, ai->ai_addr, ai->ai_addrlen)) {
		syslog(LOG_ERR, "Error connecting to %s: %s - exiting",
			config.remote_server, strerror(errno));
		freeaddrinfo(ai);
		return -1;
	}

	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof (int));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof (int));

	freeaddrinfo(ai);
	return 0;
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
			rc = -1;
			break;
	}
	return rc;
}

static int ar_write (int sock, const void *buf, int len)
{
	int rc;
	do {
		rc = write(sock, buf, len);
	} while (rc < 0 && errno == EINTR);
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

	sequence_id ++;
	AUDIT_RMW_PACK_HEADER (header, 0, 0, len, sequence_id);
	rc = ar_write(sock, header, AUDIT_RMW_HEADER_SIZE);
	if (rc <= 0) {
		stop = 1;
		syslog(LOG_ERR, "connection to %s closed unexpectedly - exiting",
		       config.remote_server);
		return -1;
	}

	rc = ar_write(sock, s, len);
	if (rc <= 0) {
		stop = 1;
		syslog(LOG_ERR, "connection to %s closed unexpectedly - exiting",
		       config.remote_server);
		return -1;
	}

	rc = ar_read (sock, header, AUDIT_RMW_HEADER_SIZE);
	if (rc < 16) {
		stop = 1;
		syslog(LOG_ERR, "connection to %s closed unexpectedly - exiting",
		       config.remote_server);
		return -1;
	}


	if (! AUDIT_RMW_IS_MAGIC (header, AUDIT_RMW_HEADER_SIZE))
		/* FIXME: the right thing to do here is close the socket and start a new one.  */
		return sync_error_handler ("bad magic number");

	AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, rlen, seq);

	if (rlen > MAX_AUDIT_MESSAGE_LENGTH)
		return sync_error_handler ("message too long");

	if (rlen > 0
	    && ar_read (sock, msg, rlen) < rlen)
		return sync_error_handler ("ran out of data reading reply");
	msg[rlen] = 0;

	if (seq != sequence_id)
		/* FIXME: should we read another header and
		   see if it matches?  If so, we need to deal
		   with timeouts.  */
		return sync_error_handler ("mismatched response");

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

