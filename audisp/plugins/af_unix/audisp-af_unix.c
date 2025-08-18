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
#include <sys/uio.h>
#include <dirent.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "libaudit.h"
#include "auplugin.h"
#include "audispd-pconfig.h"
#include "queue.h"

#define DEFAULT_PATH AUDIT_RUN_DIR"/audispd_events"
//#define DEBUG

/* Global Data */
static volatile int stop = 0, hup = 0;
char rx_buf[MAX_AUDIT_EVENT_FRAME_SIZE+1];
int sock = -1, conn = -1, client = 0;
struct pollfd pfd[3];
unsigned mode = 0;
format_t format = -1;
char *path = NULL;
int inbound_protocol = -1;

#define QUEUE_DEPTH 64
#define QUEUE_ENTRY_SIZE (3*4096)

static struct queue *queue;
static const unsigned char *out_buf;
static size_t out_len;
static size_t out_off;

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
	for (int i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (isdigit((unsigned char)arg[0])) {
			// parse mode
			errno = 0;
			mode = strtoul(arg, NULL, 8);
			if (errno) {
				syslog(LOG_ERR,
				       "Error converting %s (%s)",
				       argv[i], strerror(errno));
				mode = 0;
			}
		} else if (strchr(arg, '/') != NULL) {
			// parse path
			char* base;
			path = arg;
			// Make sure there are directories
			base = strchr(path, '/');
			if (base) {
				DIR* d;
				char* dir = strdup(path);
				base = dirname(dir);
				d = opendir(base);
				if (d) {
					closedir(d);
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
		} else {
			if (strcmp(arg, "string") == 0)
				format = F_STRING;
			else if (strcmp(arg, "binary") == 0)
				format = F_BINARY;
			else
				syslog(LOG_ERR, "Invalid format detected");
		}
	}

	if (mode == 0 || path == NULL || format == -1) {
		syslog(LOG_ERR, "Bad or not enough arguments, using defaults");
		if (mode == 0) {
			mode = 0640;
			syslog(LOG_INFO, "Using default mode");
		}
		if (path == NULL) {
			path = DEFAULT_PATH;
			syslog(LOG_INFO, "Using default path");
		}
		if (format == -1) {
			format = F_STRING;
			syslog(LOG_INFO, "Using default format");
		}
	}

	return create_af_unix_socket(path, mode);
}

static int event_to_string(struct audit_dispatcher_header *hdr,
			   char *data, char **out, int *outlen)
{
	char *v = NULL, *ptr, unknown[32];
	int len;

	if (inbound_protocol == F_BINARY) {
		if (hdr->ver == AUDISP_PROTOCOL_VER) {
			const char *type;

			/* Get the event formatted */
			type = audit_msg_type_to_name(hdr->type);
			if (type == NULL) {
				snprintf(unknown, sizeof(unknown),
					 "UNKNOWN[%u]", hdr->type);
				type = unknown;
			}
			len = asprintf(&v, "type=%s msg=%.*s\n",
				       type, hdr->size, data);
		} else if (inbound_protocol == F_BINARY &&
			   hdr->ver == AUDISP_PROTOCOL_VER2) {
			// Protocol 2 events are already formatted
			len = asprintf(&v, "%.*s\n", hdr->size, data);
		} else
			len = 0;
	} else if (inbound_protocol == F_STRING) {
		// Inbound strings start at the hdr
		len = asprintf(&v, "%s\n", (char *)hdr);
	} else
		len = 0;
	if (len <= 0) {
		*out = NULL;
		*outlen = 0;
		return -1;
	}

	/* Strip newlines from event record except the last one */
	ptr = v;
	while ((ptr = strchr(ptr, 0x0A)) != NULL) {
		if (ptr != &v[len-1])
			*ptr = ' ';
		else
			break; /* Done - exit loop */
	}

	*out = v;
	*outlen = len;
	return 1;
}

/*
 * read_binary_record - read a binary dispatcher record
 * @fd:  input descriptor
 * @hdr: pointer to header storage
 * @data: pointer to data storage
 *
 * This function reads exactly sizeof(*hdr) bytes followed by hdr->size
 * bytes from @fd.  It returns the total bytes read or -1 on error and
 * 0 when EOF is reached.
 */
static int read_binary_record(int fd, struct audit_dispatcher_header *hdr,
			      char *data)
{
	size_t len = sizeof(*hdr);
	char *ptr = (char *)hdr;
	ssize_t rc;

	while (len) {
		rc = read(fd, ptr, len);
		if (rc <= 0) {
			if (rc < 0 && errno == EINTR)
				continue;
			return rc;
		}
		ptr += rc;
		len -= rc;
	}

	if (hdr->size > MAX_AUDIT_MESSAGE_LENGTH)
		hdr->size = MAX_AUDIT_MESSAGE_LENGTH;

	len = hdr->size;
	ptr = data;
	while (len) {
		rc = read(fd, ptr, len);
		if (rc <= 0) {
			if (rc < 0 && errno == EINTR)
				continue;
			return rc;
		}
		ptr += rc;
		len -= rc;
	}

	return sizeof(*hdr) + hdr->size;
}

void read_audit_record(int ifd)
{
	int len;

	// If it's the first call, detect which inbound protocol we are using
	if (inbound_protocol == -1) {
		unsigned char peek[4];
		ssize_t rc;

		// audisp uses socketpair to setup stdin, use recvfrom to
		// peek into what the protocol might be
		rc = recvfrom(ifd, peek, sizeof(peek), MSG_PEEK, NULL, NULL);
		if (rc < 0) {
			if (errno == ENOTSOCK) {
				syslog(LOG_ERR, "stdin is not a socket (%s)",
				       strerror(errno));
				exit(1);
			}
			return;
		}
		if (rc == 0) {
			stop = 1;
			return;
		}
		if (peek[0] == 0 || peek[0] == 1)
			inbound_protocol = F_BINARY;
		else
			inbound_protocol = F_STRING;
	}

	if (inbound_protocol == F_BINARY) {
		struct audit_dispatcher_header *hdr =
			(struct audit_dispatcher_header *)rx_buf;
		char *data = rx_buf + sizeof(*hdr);

		len = read_binary_record(ifd, hdr, data);
		if (len <= 0) {
			if (len == 0)
				stop = 1;
			return;
		}

		if (!stop) {
			if (format == F_STRING) {
				char *str = NULL;
				int str_len = 0;

				if (event_to_string(hdr, data, &str,
						    &str_len) < 0)
					return;

				if (q_append(queue, str, str_len) != 0)
					syslog(LOG_ERR,
					       "Queue append failed (%s)",
					       strerror(errno));
				free(str);
			} else if (format == F_BINARY) {
				int total = sizeof(*hdr) + hdr->size;
				char *buf = malloc(total);
				if (buf) {
					memcpy(buf, hdr, sizeof(*hdr));
					memcpy(buf + sizeof(*hdr), data,
					       hdr->size);
					if (q_append(queue, buf, total) != 0)
						syslog(LOG_ERR,
						   "Queue append failed (%s)",
						   strerror(errno));
					free(buf);
				}
			}
		}
	} else {
		do {
			len = auplugin_fgets(rx_buf,
					   MAX_AUDIT_EVENT_FRAME_SIZE + 1, ifd);
			if (len > 0) {
				if (inbound_protocol == -1)
					inbound_protocol = F_STRING;
				if (!stop) {
					if (format == F_STRING) {
						if (q_append(queue, rx_buf,
							     len) != 0)
							syslog(LOG_ERR,
						    "Queue append failed (%s)",
							       strerror(errno));
					} else if (format == F_BINARY) {
						struct audit_dispatcher_header hdr;

						hdr.ver = AUDISP_PROTOCOL_VER2;
						hdr.hlen = sizeof(struct audit_dispatcher_header);
						hdr.type = 0;
						hdr.size = len;
						int total = sizeof(hdr) + len;
						char *buf = malloc(total);
						if (buf) {
							memcpy(buf, &hdr,
							       sizeof(hdr));
							memcpy(buf+sizeof(hdr),
							       rx_buf, len);
							if (q_append(queue, buf,
								    total) != 0)
								syslog(LOG_ERR,
						     "Queue append failed (%s)",
							       strerror(errno));
							free(buf);
						}
					}
				}
			} else if (auplugin_fgets_eof())
				stop = 1;
		} while (!stop &&
			 auplugin_fgets_more(MAX_AUDIT_EVENT_FRAME_SIZE));
	}
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

static void send_queue(void)
{
	ssize_t rc;

	while (!q_empty(queue) && client && !stop) {
		if (out_off == 0) {
			int r = q_peek(queue, &out_buf, &out_len);
			if (r <= 0) {
				if (r < 0)
					syslog(LOG_ERR,
					       "Queue peek failed (%s)",
					       strerror(errno));
				return;
			}
		}

		do {
			rc = write(conn, out_buf + out_off,
				   out_len - out_off);
		} while (rc < 0 && errno == EINTR);
		if (rc < 0) {
			if (errno == EAGAIN)
				return;
			if (errno == EPIPE) {
				close(conn);
				conn = -1;
				client = 0;
				auplugin_fgets_clear();
				out_off = 0;
				out_len = 0;
				out_buf = NULL;
			}
			return;
		}
		out_off += rc;
		if (out_off == out_len) {
			q_drop_head(queue);
			out_off = 0;
			out_len = 0;
			out_buf = NULL;
		}
	}
}

void event_loop(int ifd)
{
	// setup poll
	pfd[0].fd = ifd;	//stdin
	pfd[0].events = POLLIN;
	pfd[1].fd = sock;	// listen socket
	pfd[1].events = POLLIN;

	// loop on poll until stop - not doing HUP for now
	while (!stop) {
		int rc;

		if (client) {
			pfd[2].fd = conn;       // the client
			pfd[2].events = POLLHUP;
			if (!q_empty(queue))
				pfd[2].events |= POLLOUT;
		}

		rc = poll(pfd, 2 + client, -1);
		if (rc < 0) {
			if (stop)
				break;

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
				auplugin_fgets_clear();
				out_off = 0;
				out_len = 0;
				out_buf = NULL;
			}
			// auditd closed it's socket, exit
			if (pfd[0].revents & POLLHUP) {
				syslog(LOG_INFO,
				       "Auditd closed it's socket - exiting");
				return;
			}
			if (pfd[0].revents & POLLIN) {
				// Inbound audit event
				read_audit_record(ifd);
			}

			if (pfd[1].revents & POLLIN) {
				// someone connected, accept it
				accept_connection();
				send_queue();
			}

			if (client && (pfd[2].revents & POLLOUT))
				send_queue();
		}
	}
	if (stop == 1)
		syslog(LOG_INFO,
		       "audisp-af_unix plugin is exiting on TERM request");
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
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_sigaction = term_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGTERM, &sa, NULL);
	/* Set STDIN non-blocking */
	(void) umask( umask( 077 ) | 027 );
	ifd = 0;
#ifdef DEBUG
	ifd = open("test.log", O_RDONLY);
#endif
	fcntl(ifd, F_SETFL, O_NONBLOCK);

	// Initialize the socket
	if (setup_socket(argc, argv)) {
		syslog(LOG_ERR,"audisp-af_unix plugin exiting due to errors "
		       "setting up socket");
		exit(1);
	}

#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
	capng_clear(CAPNG_SELECT_BOTH);
	if (capng_apply(CAPNG_SELECT_BOTH))
		syslog(LOG_WARNING, "audisp-af_unix plugin was unable to "
		       "drop capabilities, continuing with elevated priviles");
#endif
	queue = q_open(QUEUE_DEPTH, QUEUE_ENTRY_SIZE);
	if (queue == NULL) {
		syslog(LOG_ERR, "Unable to create queue (%s)",
		       strerror(errno));
		exit(1);
	}
	syslog(LOG_INFO, "audisp-af_unix plugin is listening for events");
	event_loop(ifd);

	// close up and delete socket
	if (conn >= 0) close(conn);
	if (sock >= 0) close(sock);
	if (unlink(path) == -1) {
		syslog(LOG_WARNING, "Failed to unlink socket %s (%s)",
		       path, strerror(errno));
	}
	q_close(queue);

	return 0;
}

