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
#include "libaudit.h"
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
	if (connect(sock, ai->ai_addr, ai->ai_addrlen)) {
		syslog(LOG_ERR, "Error connecting to %s: %s - exiting",
			config.remote_server, strerror(errno));
		freeaddrinfo(ai);
		return -1;
	}
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

static int relay_sock(const char *s, size_t len)
{
	int rc;

	do {
		rc = write(sock, s, len);
	} while (rc < 0 && errno == EINTR);
	if (rc > 0)
		return 0;
	return -1;
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

