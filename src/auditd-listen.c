/* auditd-listen.c -- 
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
 *   DJ Delorie <dj@redhat.com>
 * 
 */

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>	/* O_NOFOLLOW needs gnu defined */
#include <libgen.h>
#include <arpa/inet.h>
#include <limits.h>	/* INT_MAX */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "libaudit.h"
#include "auditd-event.h"
#include "auditd-config.h"
#include "private.h"

#include "ev.h"

extern volatile int stop;

typedef struct ev_tcp {
	struct ev_io io;
	struct sockaddr_in addr;
	struct ev_tcp *next, *prev;
	int bufptr;
	unsigned char buffer [MAX_AUDIT_MESSAGE_LENGTH + 17];
} ev_tcp;

static int listen_socket;
static struct ev_io tcp_listen_watcher;
static int min_port, max_port;

static struct ev_tcp *client_chain = 0;

static char *sockaddr_to_ip (struct sockaddr_in *addr)
{
	unsigned char *uaddr = (unsigned char *)&(addr->sin_addr);
	static char buf[40];

	sprintf (buf, "%d.%d.%d.%d:%d",
		 uaddr[0], uaddr[1], uaddr[2], uaddr[3], ntohs (addr->sin_port));
	return buf;
}

static void set_close_on_exec (int fd)
{
	int flags = fcntl (fd, F_GETFD);
	if (flags == -1)
		flags = 0;
	flags |= FD_CLOEXEC;
	fcntl (fd, F_SETFD, flags);
}

static void close_client (struct ev_tcp *client)
{
	close (client->io.fd);
	if (client_chain == client)
		client_chain = client->next;
	if (client->next)
		client->next->prev = client->prev;
	if (client->prev)
		client->prev->next = client->next;
	free (client);
}

static void client_message (struct ev_tcp *io, unsigned int length, unsigned char *header)
{
	unsigned char ch;
	uint32_t type, mlen, seq;
	int hver, mver;

	if (AUDIT_RMW_IS_MAGIC (header, length)) {
		AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, mlen, seq)

		ch = header[length];
		header[length] = 0;
		if (length > 1 && header[length-1] == '\n')
			header[length-1] = 0;
		enqueue_formatted_event (header+AUDIT_RMW_HEADER_SIZE, io->io.fd, seq);
		header[length] = ch;
	} else {
		header[length] = 0;
		if (length > 1 && header[length-1] == '\n')
			header[length-1] = 0;
		enqueue_formatted_event (header, 0, 0);
	}
}

static void auditd_tcp_client_handler( struct ev_loop *loop, struct ev_io *_io, int revents )
{
	struct ev_tcp *io = (struct ev_tcp *) _io;
	int i, r;
	int total_this_call = 0;

	/* The socket is non-blocking, but we have a limited buffer
	   size.  In the event that we get a packet that's bigger than
	   our buffer, we need to read it in multiple parts.  Thus, we
	   keep reading/parsing/processing until we run out of ready
	   data.  */
read_more:
	r = read (io->io.fd,
		  io->buffer + io->bufptr,
		  MAX_AUDIT_MESSAGE_LENGTH - io->bufptr);

	if (r < 0 && errno == EAGAIN)
		r = 0;

	/* We need to keep track of the difference between "no data
	 * because it's closed" and "no data because we've read it
	 * all".  */
	if (r == 0 && total_this_call > 0) {
		return;
	}

	/* If the connection is gracefully closed, the first read we
	   try will return zero.  If the connection times out or
	   otherwise fails, the read will return -1.  */
	if (r <= 0) {
		if (r < 0)
			audit_msg (LOG_WARNING, "client %s socket closed unexpectedly",
				   sockaddr_to_ip (&io->addr));

		/* There may have been a final message without a LF.  */
		if (io->bufptr) {
			client_message (io, io->bufptr, io->buffer);

		}

		ev_io_stop (loop, _io);
		close_client (io);
		return;
	}

	total_this_call += r;

more_messages:
	if (AUDIT_RMW_IS_MAGIC (io->buffer, io->bufptr+r)) {
		uint32_t type, len, seq;
		int hver, mver;
		unsigned char *header = (unsigned char *)io->buffer;

		io->bufptr += r;

		if (io->bufptr < AUDIT_RMW_HEADER_SIZE)
			return;

		AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, len, seq);

		i = len;
		i += AUDIT_RMW_HEADER_SIZE;

		/* See if we have enough bytes to extract the whole message.  */
		if (io->bufptr < i)
			return;
		
	} else {
		/* At this point, the buffer has IO->BUFPTR+R bytes in it.
		   The first IO->BUFPTR bytes do not have a LF in them (we've
		   already checked), we must check the R new bytes.  */

		for (i = io->bufptr; i < io->bufptr + r; i ++)
			if (io->buffer [i] == '\n')
				break;

		io->bufptr += r;

		/* Check for a partial message, with no LF yet.  */
		if (i == io->bufptr)
			return;

		i ++;
	}

	/* We have an I-byte message in buffer.  */
	client_message (io, i, io->buffer);

	/* Now copy any remaining bytes to the beginning of the
	   buffer.  */
	memmove (io->buffer, io->buffer + i, io->bufptr);
	io->bufptr -= i;

	/* See if this packet had more than one message in it. */
	if (io->bufptr > 0) {
		r = io->bufptr;
		io->bufptr = 0;
		goto more_messages;
	}

	/* Go back and see if there's more data to read.  */
	goto read_more;
}

static void auditd_tcp_listen_handler( struct ev_loop *loop, struct ev_io *_io, int revents )
{
	int one=1;
	int afd;
	socklen_t aaddrlen;
	struct sockaddr_in aaddr;
	struct ev_tcp *client;
	unsigned char *uaddr;

	/* Accept the connection and see where it's coming from.  */
	aaddrlen = sizeof(aaddr);
	afd = accept (listen_socket, (struct sockaddr *)&aaddr, &aaddrlen);
	if (afd == -1) {
        	audit_msg(LOG_ERR, "Unable to accept TCP connection");
		return;
	}

	uaddr = (unsigned char *)&aaddr.sin_addr;

	/* Verify it's coming from an authorized port.  We assume the firewall will
	   block attempts from unauthorized machines.  */
	if (min_port > ntohs (aaddr.sin_port) || ntohs (aaddr.sin_port) > max_port) {
        	audit_msg(LOG_ERR, "TCP connection from %s rejected", sockaddr_to_ip (&aaddr));
		close (afd);
		return;
	}

	setsockopt(afd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof (int));
	setsockopt(afd, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof (int));
	setsockopt(afd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof (int));
	fcntl(afd, F_SETFL, O_NONBLOCK | O_NDELAY);
	set_close_on_exec (afd);

	client = (struct ev_tcp *) malloc (sizeof (struct ev_tcp));
	if (client == NULL) {
        	audit_msg(LOG_CRIT, "Unable to allocate TCP client data");
		close (afd);
		return;
	}

	memset (client, 0, sizeof (struct ev_tcp));

	ev_io_init (&(client->io), auditd_tcp_client_handler, afd, EV_READ | EV_ERROR);
	ev_io_start (loop, &(client->io));

	memcpy (&client->addr, &aaddr, sizeof (struct sockaddr_in));

	/* Keep a linked list of active clients.  */
	client->next = client_chain;
	if (client->next)
		client->next->prev = client;
	client_chain = client;
}

int auditd_tcp_listen_init ( struct ev_loop *loop, struct daemon_conf *config )
{
	struct sockaddr_in address;
	int one = 1;

	/* If the port is not set, that means we aren't going to
	  listen for connections.  */
	if (config->tcp_listen_port == 0)
		return 0;

	listen_socket = socket (AF_INET, SOCK_STREAM, 0);
	if (listen_socket == 0) {
        	audit_msg(LOG_ERR, "Cannot create tcp listener socket");
		return 1;
	}

	set_close_on_exec (listen_socket);
	setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof (int));

	memset (&address, 0, sizeof(address));
	address.sin_family = htons(AF_INET);
	address.sin_port = htons(config->tcp_listen_port);
	address.sin_addr.s_addr = htonl(INADDR_ANY);

	/* This avoids problems if auditd needs to be restarted.  */
	setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof (int));

	if ( bind ( listen_socket, (struct sockaddr *)&address, sizeof(address)) ) {
        	audit_msg(LOG_ERR,
			"Cannot bind tcp listener socket to port %ld",
			config->tcp_listen_port);
		close(listen_socket);
		return 1;
	}

	listen(listen_socket, config->tcp_listen_queue);

	audit_msg(LOG_DEBUG, "Listening on TCP port %ld",
		config->tcp_listen_port);

	ev_io_init (&tcp_listen_watcher, auditd_tcp_listen_handler, listen_socket, EV_READ);
	ev_io_start (loop, &tcp_listen_watcher);

	min_port = config->tcp_client_min_port;
	max_port = config->tcp_client_max_port;

	return 0;
}

void auditd_tcp_listen_uninit ( struct ev_loop *loop )
{
	ev_io_stop ( loop, &tcp_listen_watcher );
	close ( listen_socket );

	while (client_chain) {
		close_client (client_chain);
	}
}
