/*
 * af_unix.c - implementation of the audisp-af_unix plugin
 * Copyright (c) 2023 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
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
 */

#include "config.h"
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "common.h"

#define DEFAULT_PATH "/var/run/audispd_events"
//#define DEBUG

/* Global Data */
static volatile int stop = 0, hup = 0;
char rx_buf[MAX_AUDIT_MESSAGE_LENGTH];
int sock = -1, conn = -1, client = 0;
struct pollfd pfd[3];
unsigned mode = 0;
char *path = NULL;

/*
 * SIGTERM handler
 */
static void term_handler(int sig)
{
	stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig)
{
	hup = 1;
}

int create_af_unix_socket(const char *spath, int mode)
{
	struct sockaddr_un addr;
	socklen_t len;
	int rc, cmd, one = 1;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		syslog(LOG_ERR, "Couldn't open af_unix socket (%s)",
		       strerror(errno));
		return -1;
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&one, sizeof (int));
#ifdef DEBUG
	printf("%o %s\n", mode, spath);
#else
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(&addr.sun_path[0], 108, "%.107s", spath);
	len = sizeof(addr);
	rc = bind(sock, (const struct sockaddr *)&addr, len);
	if (rc < 0) {
		syslog(LOG_ERR, "Couldn't bind af_unix socket (%s)",
		       strerror(errno));
		close(sock);
		return -1;
	}
	rc = chmod(spath, mode);
	if (rc < 0) {
		syslog(LOG_ERR, "Couldn't chmod %s to %04o (%s)",
		       spath, mode, strerror(errno));
		close(sock);
		unlink(spath);
		return -1;
	}
	// Put socket in nonblock mode and don't leak the descriptor
	cmd = fcntl(sock, F_GETFL);
	fcntl(sock, F_SETFL, cmd|FNDELAY|FD_CLOEXEC);

	// Make socket listening...won't block
	(void)listen(sock, 1);
#endif
	return 0;
}

int setup_socket(int argc, char *argv[])
{
	if (argc != 3) {
		syslog(LOG_ERR, "Missing arguments, using defaults");
		mode = 0640;
		path = DEFAULT_PATH;
	} else {
		int i;
		for (i=1; i < 3; i++) {
			if (isdigit((unsigned char)argv[i][0])) {
				errno = 0;
				mode = strtoul(argv[i], NULL, 8);
				if (errno) {
					syslog(LOG_ERR,
					       "Error converting %s (%s)",
					       argv[i], strerror(errno));
					mode = 0;
				}
			} else {
				char *base;
				path = argv[i];
				// Make sure there are directories
				base = strchr(path, '/');
				if (base) {
					DIR *d;
					char *dir = strdup(path);
					base = dirname(dir);
					d = opendir(base);
					if (d) {
						closedir(d);
						unlink(path);
						free(dir);
					} else {
						syslog(LOG_ERR,
						       "Couldn't open %s (%s)",
						       base, strerror(errno));
						free(dir);
						exit(1);
					}

				} else {
					syslog(LOG_ERR, "Malformed path %s",
					       path);
					exit(1);
				}
			}
		}
		if (mode == 0 || path == NULL) {
			syslog(LOG_ERR, "Bad arguments, using defaults");
			mode = 0640;
			path = DEFAULT_PATH;
		}
	}
	return create_af_unix_socket(path, mode);
}

void read_audit_record(int ifd)
{
	do {
		int len;

		// Read stdin
		if ((len = audit_fgets(rx_buf, sizeof(rx_buf), ifd)) > 0) {
#ifdef DEBUG
			write(1, rx_buf, len);
#else
			if (client) {
				// Send it to the client
				int rc;

				do {
					rc = write(conn, rx_buf, len);
				} while (rc < 0 && errno == EINTR);
				if (rc < 0 && errno == EPIPE) {
					close(conn);
					conn = -1;
					client = 0;
					audit_fgets_clear();
				}
				if (rc >= 0 && rc != len) {
					// what to do with leftovers?
				}
			}
#endif
		} else if (audit_fgets_eof())
			stop = 1;
	} while (audit_fgets_more(sizeof(rx_buf)));
}

void accept_connection(void)
{
	int tmp_conn;

	do {
		tmp_conn = accept4(sock, NULL,NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
	} while (tmp_conn < 0 && errno == EINTR);

	if (tmp_conn >= 0) {
		if (conn < 0) {
			syslog(LOG_INFO, "Client connected");
			client = 1;
			conn = tmp_conn;
		} else
			close(tmp_conn);
	}
}

void event_loop(int ifd)
{
	// setup poll
	pfd[0].fd = ifd;	//stdin
	pfd[0].events = POLLIN;
	pfd[1].fd = sock;	// listen socket
	pfd[1].events = POLLIN|POLLOUT;

	// loop on poll until stop - not doing HUP for now
	while (!stop) {
		int rc;

		if (client) {
			pfd[2].fd = conn;	// the client
			pfd[2].events = POLLHUP;
		}

		rc = poll(pfd, 2 + client, -1);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			syslog(LOG_WARNING, "Poll error (%s), exiting",
			       strerror(errno));
			return;
		}
		if (rc > 0) {
			if (client && (pfd[2].revents & POLLHUP)) {
				// client hung up, do this first in case
				// an inbound audit record is available
				close(conn);
				conn = -1;
				client = 0;
				audit_fgets_clear();
			}
			if (pfd[0].revents & POLLIN) {
				// Inbound audit event
				read_audit_record(ifd);
			}
			// auditd closed it's socket, exit
			if (pfd[0].revents & POLLHUP)
				return;

			if (pfd[1].revents & (POLLIN|POLLOUT)) {
				// someone connected, accept it
				accept_connection();
			}
		}
	}
}


int main(int argc, char *argv[])
{
	struct sigaction sa;
	int i, ifd;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Ignore all signals by default */
	sa.sa_handler = SIG_IGN;
	for (i=1; i<NSIG; i++)
		sigaction( i, &sa, NULL );

	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	/* Set STDIN non-blocking */
	(void) umask( umask( 077 ) | 027 );
	ifd = 0;
#ifdef DEBUG
	ifd = open("test.log", O_RDONLY);
#endif
	fcntl(ifd, F_SETFL, O_NONBLOCK);

	// Initialize the socket
	if (setup_socket(argc, argv)) {
		syslog(LOG_ERR, "audisp-af_unix plugin exiting");
		exit(1);
	}

#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
	capng_clear(CAPNG_SELECT_BOTH);
	if (capng_apply(CAPNG_SELECT_BOTH))
		syslog(LOG_WARNING, "audisp-af_unix plugin was unable to drop capabilities, continuing with elevated priviles");
#endif
	syslog(LOG_INFO, "audisp-af_unix plugin is listening for events");
	event_loop(ifd);

	// close up and delete socket
	if (conn >= 0) close(conn);
	if (sock >= 0) close(sock);
	unlink(path);

	return 0;
}


