/* auditd-listen.c -- 
 * Copyright 2008,2009,2011 Red Hat Inc., Durham, North Carolina.
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
#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#endif
#ifdef USE_GSSAPI
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <krb5.h>
#endif
#include "libaudit.h"
#include "auditd-event.h"
#include "auditd-config.h"
#include "private.h"

#include "ev.h"

extern volatile int stop;
extern int send_audit_event(int type, const char *str);
#define DEFAULT_BUF_SZ  192

typedef struct ev_tcp {
	struct ev_io io;
	struct sockaddr_in addr;
	struct ev_tcp *next, *prev;
	unsigned int bufptr;
	int client_active;
#ifdef USE_GSSAPI
	/* This holds the negotiated security context for this client.  */
	gss_ctx_id_t gss_context;
	char *remote_name;
	int remote_name_len;
#endif
	unsigned char buffer [MAX_AUDIT_MESSAGE_LENGTH + 17];
} ev_tcp;

static int listen_socket;
static struct ev_io tcp_listen_watcher;
static struct ev_periodic periodic_watcher;
static int min_port, max_port, max_per_addr;
static int use_libwrap = 1;
#ifdef USE_GSSAPI
/* This is used to hold our own private key.  */
static gss_cred_id_t server_creds;
static char *my_service_name, *my_gss_realm;
static int use_gss = 0;
static char msgbuf[MAX_AUDIT_MESSAGE_LENGTH + 1];
#endif

static struct ev_tcp *client_chain = NULL;

static char *sockaddr_to_ipv4(struct sockaddr_in *addr)
{
	unsigned char *uaddr = (unsigned char *)&(addr->sin_addr);
	static char buf[40];

	snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		uaddr[0], uaddr[1], uaddr[2], uaddr[3]);
	return buf;
}

static char *sockaddr_to_addr4(struct sockaddr_in *addr)
{
	unsigned char *uaddr = (unsigned char *)&(addr->sin_addr);
	static char buf[40];

	snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
		uaddr[0], uaddr[1], uaddr[2], uaddr[3],
		ntohs (addr->sin_port));
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

static void release_client(struct ev_tcp *client)
{
	char emsg[DEFAULT_BUF_SZ];

	snprintf(emsg, sizeof(emsg), "addr=%s port=%d res=success",
		sockaddr_to_ipv4(&client->addr), ntohs (client->addr.sin_port));
	send_audit_event(AUDIT_DAEMON_CLOSE, emsg); 
#ifdef USE_GSSAPI
	if (client->remote_name)
		free (client->remote_name);
#endif
	shutdown(client->io.fd, SHUT_RDWR);
	close(client->io.fd);
	if (client_chain == client)
		client_chain = client->next;
	if (client->next)
		client->next->prev = client->prev;
	if (client->prev)
		client->prev->next = client->next;
}

static void close_client(struct ev_tcp *client)
{
	release_client (client);
	free (client);
}

static int ar_write (int sock, const void *buf, int len)
{
	int rc = 0, w;
	while (len > 0) {
		do {
			w = write(sock, buf, len);
		} while (w < 0 && errno == EINTR);
		if (w < 0)
			return w;
		if (w == 0)
			break;
		rc += w;
		len -= w;
		buf = (const void *)((const char *)buf + w);
	}
	return rc;
}

#ifdef USE_GSSAPI
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
		len -= r;
		buf = (void *)((char *)buf + r);
	}
	return rc;
}


/* Communications under GSS is done by token exchanges.  Each "token"
   may contain a message, perhaps signed, perhaps encrypted.  The
   messages within are what we're interested in, but the network sees
   the tokens.  The protocol we use for transferring tokens is to send
   the length first, four bytes MSB first, then the token data.  We
   return nonzero on error.  */
static int recv_token (int s, gss_buffer_t tok)
{
	int ret;
	unsigned char lenbuf[4];
	unsigned int len;

	ret = ar_read(s, (char *) lenbuf, 4);
	if (ret < 0) {
		audit_msg(LOG_ERR, "GSS-API error reading token length");
		return -1;
	} else if (!ret) {
		return 0;
	} else if (ret != 4) {
		audit_msg(LOG_ERR, "GSS-API error reading token length");
		return -1;
	}

	len = ((lenbuf[0] << 24)
	       | (lenbuf[1] << 16)
	       | (lenbuf[2] << 8)
	       | lenbuf[3]);
	if (len > MAX_AUDIT_MESSAGE_LENGTH) {
		audit_msg(LOG_ERR,
			"GSS-API error: event length excedes MAX_AUDIT_LENGTH");
		return -1;
	}
	tok->length = len;

	tok->value = (char *) malloc(tok->length ? tok->length : 1);
	if (tok->length && tok->value == NULL) {
		audit_msg(LOG_ERR, "Out of memory allocating token data");
		return -1;
	}

	ret = ar_read(s, (char *) tok->value, tok->length);
	if (ret < 0) {
		audit_msg(LOG_ERR, "GSS-API error reading token data");
		free(tok->value);
		return -1;
	} else if (ret != (int) tok->length) {
		audit_msg(LOG_ERR, "GSS-API error reading token data");
		free(tok->value);
		return -1;
	}

	return 1;
}

/* Same here.  */
int send_token(int s, gss_buffer_t tok)
{
	int     ret;
	unsigned char lenbuf[4];
	unsigned int len;

	if (tok->length > 0xffffffffUL)
		return -1;
	len = tok->length;
	lenbuf[0] = (len >> 24) & 0xff;
	lenbuf[1] = (len >> 16) & 0xff;
	lenbuf[2] = (len >> 8) & 0xff;
	lenbuf[3] = len & 0xff;

	ret = ar_write(s, (char *) lenbuf, 4);
	if (ret < 0) {
		audit_msg(LOG_ERR, "GSS-API error sending token length");
		return -1;
	} else if (ret != 4) {
		audit_msg(LOG_ERR, "GSS-API error sending token length");
		return -1;
	}

	ret = ar_write(s, tok->value, tok->length);
	if (ret < 0) {
		audit_msg(LOG_ERR, "GSS-API error sending token data");
		return -1;
	} else if (ret != (int) tok->length) {
		audit_msg(LOG_ERR, "GSS-API error sending token data");
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

		audit_msg (LOG_ERR, "GSS error: %s: %s",
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

#define KCHECK(x,f) if (x) { \
		const char *kstr = krb5_get_error_message(kcontext, x); \
		audit_msg(LOG_ERR, "krb5 error: %s in %s\n", kstr, f); \
		krb5_free_error_message(kcontext, kstr); \
		return -1; }

/* These are our private credentials, which come from a key file on
   our server.  They are aquired once, at program start.  */
static int server_acquire_creds(const char *service_name,
		gss_cred_id_t *server_creds)
{
	gss_buffer_desc name_buf;
	gss_name_t server_name;
	OM_uint32 major_status, minor_status;

	krb5_context kcontext = NULL;
	int krberr;

	my_service_name = strdup (service_name);
	name_buf.value = (char *)service_name;
	name_buf.length = strlen(name_buf.value) + 1;
	major_status = gss_import_name(&minor_status, &name_buf,
				       (gss_OID) gss_nt_service_name,
					&server_name);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("importing name", major_status, minor_status);
		return -1;
	}

	major_status = gss_acquire_cred(&minor_status,
					server_name, GSS_C_INDEFINITE,
					GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
					server_creds, NULL, NULL);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("acquiring credentials",
				major_status, minor_status);
		return -1;
	}

	(void) gss_release_name(&minor_status, &server_name);

	krberr = krb5_init_context (&kcontext);
	KCHECK (krberr, "krb5_init_context");
	krberr = krb5_get_default_realm (kcontext, &my_gss_realm);
	KCHECK (krberr, "krb5_get_default_realm");

	audit_msg(LOG_DEBUG, "GSS creds for %s acquired", service_name);

	return 0;
}

/* This is where we negotiate a security context with the client.  In
   the case of Kerberos, this is where the key exchange happens.
   FIXME: While everything else is strictly nonblocking, this
   negotiation blocks.  */
static int negotiate_credentials (ev_tcp *io)
{
	gss_buffer_desc send_tok, recv_tok;
	gss_name_t client;
	OM_uint32 maj_stat, min_stat, acc_sec_min_stat;
	gss_ctx_id_t *context;
	OM_uint32 sess_flags;
	char *slashptr, *atptr;

	context = & io->gss_context;
	*context = GSS_C_NO_CONTEXT;

	maj_stat = GSS_S_CONTINUE_NEEDED;
	do {
		/* STEP 1 - get a token from the client.  */

		if (recv_token(io->io.fd, &recv_tok) <= 0) {
			audit_msg(LOG_ERR,
			"TCP session from %s will be closed, error ignored",
				  sockaddr_to_addr4(&io->addr));
			return -1;
		}
		if (recv_tok.length == 0)
			continue;

		/* STEP 2 - let GSS process that token.  */

		maj_stat = gss_accept_sec_context(&acc_sec_min_stat,
					context, server_creds,
					&recv_tok,
					GSS_C_NO_CHANNEL_BINDINGS, &client,
					NULL, &send_tok, &sess_flags,
					NULL, NULL);
		if (recv_tok.value) {
			free(recv_tok.value);
			recv_tok.value = NULL;
		}
		if (maj_stat != GSS_S_COMPLETE
		    && maj_stat != GSS_S_CONTINUE_NEEDED) {
			gss_release_buffer(&min_stat, &send_tok);
			if (*context != GSS_C_NO_CONTEXT)
				gss_delete_sec_context(&min_stat, context,
					GSS_C_NO_BUFFER);
			gss_failure("accepting context", maj_stat,
				    acc_sec_min_stat);
			return -1;
		}

		/* STEP 3 - send any tokens to the client that GSS may
		   ask us to send.  */

		if (send_tok.length != 0) {
			if (send_token(io->io.fd, &send_tok) < 0) {
				gss_release_buffer(&min_stat, &send_tok);
				audit_msg(LOG_ERR,
			"TCP session from %s will be closed, error ignored",
					  sockaddr_to_addr4(&io->addr));
				if (*context != GSS_C_NO_CONTEXT)
					gss_delete_sec_context(&min_stat,
						context, GSS_C_NO_BUFFER);
				return -1;
			}
			gss_release_buffer(&min_stat, &send_tok);
		}
	} while (maj_stat == GSS_S_CONTINUE_NEEDED);

	maj_stat = gss_display_name(&min_stat, client, &recv_tok, NULL);
	gss_release_name(&min_stat, &client);

	if (maj_stat != GSS_S_COMPLETE) {
		gss_failure("displaying name", maj_stat, min_stat);
		return -1;
	}

	audit_msg(LOG_INFO, "GSS-API Accepted connection from: %s",
		  (char *)recv_tok.value);
	io->remote_name = strdup (recv_tok.value);
	io->remote_name_len = strlen (recv_tok.value);
	gss_release_buffer(&min_stat, &recv_tok);

	slashptr = strchr (io->remote_name, '/');
	atptr = strchr (io->remote_name, '@');

	if (!slashptr || !atptr) {
		audit_msg(LOG_ERR, "Invalid GSS name from remote client: %s",
			  io->remote_name);
		return -1;
	}

	*slashptr = 0;
	if (strcmp (io->remote_name, my_service_name)) {
		audit_msg(LOG_ERR, "Unauthorized GSS client name: %s (not %s)",
			  io->remote_name, my_service_name);
		return -1;
	}
	*slashptr = '/';

	if (strcmp (atptr+1, my_gss_realm)) {
		audit_msg(LOG_ERR, "Unauthorized GSS client realm: %s (not %s)",
			  atptr+1, my_gss_realm);
		return -1;
	}

	return 0;
}
#endif /* USE_GSSAPI */

/* This is called from auditd-event after the message has been logged.
   The header is already filled in.  */
static void client_ack (void *ack_data, const unsigned char *header,
	const char *msg)
{
	ev_tcp *io = (ev_tcp *)ack_data;
#ifdef USE_GSSAPI
	if (use_gss) {
		OM_uint32 major_status, minor_status;
		gss_buffer_desc utok, etok;
		int rc, mlen;

		mlen = strlen (msg);
		utok.length = AUDIT_RMW_HEADER_SIZE + mlen;
		utok.value = malloc (utok.length + 1);

		memcpy (utok.value, header, AUDIT_RMW_HEADER_SIZE);
		memcpy (utok.value+AUDIT_RMW_HEADER_SIZE, msg, mlen);

		/* Wrapping the message creates a token for the
		   client.  Then we just have to worry about sending
		   the token.  */

		major_status = gss_wrap (&minor_status,
					 io->gss_context,
					 1,
					 GSS_C_QOP_DEFAULT,
					 &utok,
					 NULL,
					 &etok);
		if (major_status != GSS_S_COMPLETE) {
			gss_failure("encrypting message", major_status,
					minor_status);
			free (utok.value);
			return;
		}
		// FIXME: What were we going to do with rc?
		rc = send_token (io->io.fd, &etok);
		free (utok.value);
		(void) gss_release_buffer(&minor_status, &etok);

		return;
	}
#endif
	// Send the header and a text error message if it exists
	ar_write (io->io.fd, header, AUDIT_RMW_HEADER_SIZE);
	if (msg[0])
		ar_write (io->io.fd, msg, strlen(msg));
}

static void client_message (struct ev_tcp *io, unsigned int length,
	unsigned char *header)
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
		if (type == AUDIT_RMW_TYPE_HEARTBEAT) {
			unsigned char ack[AUDIT_RMW_HEADER_SIZE];
			AUDIT_RMW_PACK_HEADER (ack, 0, AUDIT_RMW_TYPE_ACK,
				0, seq);
			client_ack (io, ack, "");
		} else 
			enqueue_formatted_event(header+AUDIT_RMW_HEADER_SIZE,
				client_ack, io, seq);
		header[length] = ch;
	} else {
		header[length] = 0;
		if (length > 1 && header[length-1] == '\n')
			header[length-1] = 0;
		enqueue_formatted_event (header, NULL, NULL, 0);
	}
}

static void auditd_tcp_client_handler( struct ev_loop *loop,
			struct ev_io *_io, int revents )
{
	struct ev_tcp *io = (struct ev_tcp *) _io;
	int i, r;
	int total_this_call = 0;

	io->client_active = 1;

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
			audit_msg (LOG_WARNING,
				"client %s socket closed unexpectedly",
				sockaddr_to_addr4(&io->addr));

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
#ifdef USE_GSSAPI
	/* If we're using GSS at all, everything will be encrypted,
	   one record per token.  */
	if (use_gss) {
		gss_buffer_desc utok, etok;
		io->bufptr += r;
		uint32_t len;
		OM_uint32 major_status, minor_status;

		/* We need at least four bytes to test the length.  If
		   we have more than four bytes, we can tell if we
		   have a whole token (or more).  */

		if (io->bufptr < 4)
			return;

		len = (  ((uint32_t)(io->buffer[0] & 0xFF) << 24)
		       | ((uint32_t)(io->buffer[1] & 0xFF) << 16)
		       | ((uint32_t)(io->buffer[2] & 0xFF) << 8)
		       |  (uint32_t)(io->buffer[3] & 0xFF));

		/* Make sure we got something big enough and not too big */
		if (io->bufptr < 4 + len || len > MAX_AUDIT_MESSAGE_LENGTH)
			return;
		i = len + 4;

		etok.length = len;
		etok.value = io->buffer + 4;

		/* Unwrapping the token gives us the original message,
		   which we know is already a single record.  */
		major_status = gss_unwrap (&minor_status, io->gss_context,
				&etok, &utok, NULL, NULL);

		if (major_status != GSS_S_COMPLETE) {
			gss_failure("decrypting message", major_status,
				minor_status);
		} else {
			/* client_message() wants to NUL terminate it,
			   so copy it to a bigger buffer.  Plus, we
			   want to add our own tag.  */
			memcpy (msgbuf, utok.value, utok.length);
			while (utok.length > 0 && msgbuf[utok.length-1] == '\n')
				utok.length --;
			snprintf (msgbuf + utok.length,
				MAX_AUDIT_MESSAGE_LENGTH - utok.length,
				" krb5=%s", io->remote_name);
			utok.length += 6 + io->remote_name_len;
			client_message (io, utok.length, msgbuf);
			gss_release_buffer(&minor_status, &utok);
		}
	} else
#endif
	if (AUDIT_RMW_IS_MAGIC (io->buffer, (io->bufptr+r))) {
		uint32_t type, len, seq;
		int hver, mver;
		unsigned char *header = (unsigned char *)io->buffer;

		io->bufptr += r;

		if (io->bufptr < AUDIT_RMW_HEADER_SIZE)
			return;

		AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, len, seq);

		/* Make sure len is not too big */
		if (len > MAX_AUDIT_MESSAGE_LENGTH)
			return;

		i = len;
		i += AUDIT_RMW_HEADER_SIZE;

		/* See if we have enough bytes to extract the whole message.  */
		if (io->bufptr < i)
			return;
		
		/* We have an I-byte message in buffer. Send ACK */
		client_message (io, i, io->buffer);

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

		i++;

		/* We have an I-byte message in buffer. Send ACK */
		client_message (io, i, io->buffer);
	}

	/* Now copy any remaining bytes to the beginning of the
	   buffer.  */
	memmove(io->buffer, io->buffer + i, io->bufptr - i);
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

#ifndef HAVE_LIBWRAP
#define auditd_tcpd_check(s) ({ 0; })
#else
int allow_severity = LOG_INFO, deny_severity = LOG_NOTICE;
static int auditd_tcpd_check(int sock)
{
	struct request_info request;

	request_init(&request, RQ_DAEMON, "auditd", RQ_FILE, sock, 0);
	fromhost(&request);
	if (! hosts_access(&request))
		return 1;
	return 0;
}
#endif

/*
 * This function counts the number of concurrent connections and returns
 * a 1 if there are too many and a 0 otherwise. It assumes the incoming
 * connection has not been added to the linked list yet.
 */
static int check_num_connections(struct sockaddr_in *aaddr)
{
	int num = 0;
	struct ev_tcp *client = client_chain;

	while (client) {
		if (memcmp(&aaddr->sin_addr, &client->addr.sin_addr, 
					sizeof(struct in_addr)) == 0) {
			num++;
			if (num >= max_per_addr)
				return 1;
		}
		client = client->next;
	}
	return 0;
}

static void auditd_tcp_listen_handler( struct ev_loop *loop,
	struct ev_io *_io, int revents )
{
	int one=1;
	int afd;
	socklen_t aaddrlen;
	struct sockaddr_in aaddr;
	struct ev_tcp *client;
	char emsg[DEFAULT_BUF_SZ];

	/* Accept the connection and see where it's coming from.  */
	aaddrlen = sizeof(aaddr);
	afd = accept (listen_socket, (struct sockaddr *)&aaddr, &aaddrlen);
	if (afd == -1) {
        	audit_msg(LOG_ERR, "Unable to accept TCP connection");
		return;
	}

	if (use_libwrap) {
		if (auditd_tcpd_check(afd)) {
			shutdown(afd, SHUT_RDWR);
			close(afd);
	        	audit_msg(LOG_ERR, "TCP connection from %s rejected",
					sockaddr_to_addr4(&aaddr));
			snprintf(emsg, sizeof(emsg),
				"op=wrap addr=%s port=%d res=no",
				sockaddr_to_ipv4(&aaddr),
				ntohs (aaddr.sin_port));
			send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
			return;
		}
	}

	/* Verify it's coming from an authorized port.  We assume the firewall
	 * will block attempts from unauthorized machines.  */
	if (min_port > ntohs (aaddr.sin_port) ||
					ntohs (aaddr.sin_port) > max_port) {
        	audit_msg(LOG_ERR, "TCP connection from %s rejected",
				sockaddr_to_addr4(&aaddr));
		snprintf(emsg, sizeof(emsg),
			"op=port addr=%s port=%d res=no",
			sockaddr_to_ipv4(&aaddr),
			ntohs (aaddr.sin_port));
		send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
		shutdown(afd, SHUT_RDWR);
		close(afd);
		return;
	}

	/* Make sure we don't have too many connections */
	if (check_num_connections(&aaddr)) {
        	audit_msg(LOG_ERR, "Too many connections from %s - rejected",
				sockaddr_to_addr4(&aaddr));
		snprintf(emsg, sizeof(emsg),
			"op=dup addr=%s port=%d res=no",
			sockaddr_to_ipv4(&aaddr),
			ntohs (aaddr.sin_port));
		send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
		shutdown(afd, SHUT_RDWR);
		close(afd);
		return;
	}

	/* Connection is accepted...start setting it up */
	setsockopt(afd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof (int));
	setsockopt(afd, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof (int));
	setsockopt(afd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof (int));
	set_close_on_exec (afd);

	/* Make the client data structure */
	client = (struct ev_tcp *) malloc (sizeof (struct ev_tcp));
	if (client == NULL) {
        	audit_msg(LOG_CRIT, "Unable to allocate TCP client data");
		snprintf(emsg, sizeof(emsg),
			"op=alloc addr=%s port=%d res=no",
			sockaddr_to_ipv4(&aaddr),
			ntohs (aaddr.sin_port));
		send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
		shutdown(afd, SHUT_RDWR);
		close(afd);
		return;
	}

	memset (client, 0, sizeof (struct ev_tcp));
	client->client_active = 1;

	// Was watching for EV_ERROR, but libev 3.48 took it away
	ev_io_init (&(client->io), auditd_tcp_client_handler, afd, EV_READ);

	memcpy (&client->addr, &aaddr, sizeof (struct sockaddr_in));

#ifdef USE_GSSAPI
	if (use_gss && negotiate_credentials (client)) {
		shutdown(afd, SHUT_RDWR);
		close(afd);
		free(client);
		return;
	}
#endif

	fcntl(afd, F_SETFL, O_NONBLOCK | O_NDELAY);
	ev_io_start (loop, &(client->io));

	/* Add the new connection to a linked list of active clients.  */
	client->next = client_chain;
	if (client->next)
		client->next->prev = client;
	client_chain = client;

	/* And finally log that we accepted the connection */
	snprintf(emsg, sizeof(emsg),
		"addr=%s port=%d res=success", sockaddr_to_ipv4(&aaddr),
		ntohs (aaddr.sin_port));
	send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
}

static void auditd_set_ports(int minp, int maxp, int max_p_addr)
{
	min_port = minp;
	max_port = maxp;
	max_per_addr = max_p_addr;
}

static void periodic_handler(struct ev_loop *loop, struct ev_periodic *per,
			int revents )
{
	struct daemon_conf *config = (struct daemon_conf *) per->data;
	struct ev_tcp *ev, *next = NULL;
	int active;

	if (!config->tcp_client_max_idle)
		return;

	for (ev = client_chain; ev; ev = next) {
		active = ev->client_active;
		ev->client_active = 0;
		if (active)
			continue;

		audit_msg(LOG_NOTICE,
			"client %s idle too long - closing connection\n",
			sockaddr_to_addr4(&(ev->addr)));
		ev_io_stop (loop, &ev->io);
		release_client(ev);
		next = ev->next;
		free(ev);
	}
}

int auditd_tcp_listen_init ( struct ev_loop *loop, struct daemon_conf *config )
{
	struct sockaddr_in address;
	int one = 1;

	ev_periodic_init (&periodic_watcher, periodic_handler,
			  0, config->tcp_client_max_idle, NULL);
	periodic_watcher.data = config;
	if (config->tcp_client_max_idle)
		ev_periodic_start (loop, &periodic_watcher);

	/* If the port is not set, that means we aren't going to
	  listen for connections.  */
	if (config->tcp_listen_port == 0)
		return 0;

	listen_socket = socket (AF_INET, SOCK_STREAM, 0);
	if (listen_socket < 0) {
        	audit_msg(LOG_ERR, "Cannot create tcp listener socket");
		return 1;
	}

	set_close_on_exec (listen_socket);
	setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,
			(char *)&one, sizeof (int));

	memset (&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(config->tcp_listen_port);
	address.sin_addr.s_addr = htonl(INADDR_ANY);

	/* This avoids problems if auditd needs to be restarted.  */
	setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,
			(char *)&one, sizeof (int));

	if (bind(listen_socket, (struct sockaddr *)&address, sizeof(address))){
        	audit_msg(LOG_ERR,
			"Cannot bind tcp listener socket to port %ld",
			config->tcp_listen_port);
		close(listen_socket);
		return 1;
	}

	listen(listen_socket, config->tcp_listen_queue);

	audit_msg(LOG_DEBUG, "Listening on TCP port %ld",
		config->tcp_listen_port);

	ev_io_init (&tcp_listen_watcher, auditd_tcp_listen_handler,
			listen_socket, EV_READ);
	ev_io_start (loop, &tcp_listen_watcher);

	use_libwrap = config->use_libwrap;
	auditd_set_ports(config->tcp_client_min_port,
			config->tcp_client_max_port,
			config->tcp_max_per_addr);

#ifdef USE_GSSAPI
	if (config->enable_krb5) {
		const char *princ = config->krb5_principal;
		const char *key_file;
		struct stat st;

		if (!princ)
			princ = "auditd";
		use_gss = 1;
		/* This may fail, but we don't care.  */
		unsetenv ("KRB5_KTNAME");
		if (config->krb5_key_file)
			key_file = config->krb5_key_file;
		else
			key_file = "/etc/audit/audit.key";
		setenv ("KRB5_KTNAME", key_file, 1);

		if (stat (key_file, &st) == 0) {
			if ((st.st_mode & 07777) != 0400) {
				audit_msg (LOG_ERR,
			 "%s is not mode 0400 (it's %#o) - compromised key?",
					   key_file, st.st_mode & 07777);
				return -1;
			}
			if (st.st_uid != 0) {
				audit_msg (LOG_ERR,
			 "%s is not owned by root (it's %d) - compromised key?",
					   key_file, st.st_uid);
				return -1;
			}
		}

		server_acquire_creds(princ, &server_creds);
	}
#endif

	return 0;
}

void auditd_tcp_listen_uninit ( struct ev_loop *loop,
				struct daemon_conf *config )
{
#ifdef USE_GSSAPI
	OM_uint32 status;
#endif

	ev_io_stop ( loop, &tcp_listen_watcher );
	close ( listen_socket );

#ifdef USE_GSSAPI
	if (use_gss) {
		use_gss = 0;
		gss_release_cred(&status, &server_creds);
	}
#endif

	while (client_chain) {
		unsigned char ack[AUDIT_RMW_HEADER_SIZE];

		AUDIT_RMW_PACK_HEADER (ack, 0, AUDIT_RMW_TYPE_ENDING, 0, 0);
		client_ack (client_chain, ack, "");
		ev_io_stop (loop, &client_chain->io);
		close_client (client_chain);
	}

	if (config->tcp_client_max_idle)
		ev_periodic_stop (loop, &periodic_watcher);
}

static void periodic_reconfigure(struct daemon_conf *config)
{
	struct ev_loop *loop = ev_default_loop (EVFLAG_AUTO);
	if (config->tcp_client_max_idle) {
		ev_periodic_set (&periodic_watcher, ev_now (loop),
				 config->tcp_client_max_idle, NULL);
		ev_periodic_start (loop, &periodic_watcher);
	} else {
		ev_periodic_stop (loop, &periodic_watcher);
	}
}

void auditd_tcp_listen_reconfigure ( struct daemon_conf *nconf,
				     struct daemon_conf *oconf )
{
	/* Look at network things that do not need restarting */
	if (oconf->tcp_client_min_port != nconf->tcp_client_min_port ||
		    oconf->tcp_client_max_port != nconf->tcp_client_max_port ||
		    oconf->tcp_max_per_addr != nconf->tcp_max_per_addr) {
		oconf->tcp_client_min_port = nconf->tcp_client_min_port;
		oconf->tcp_client_max_port = nconf->tcp_client_max_port;
		oconf->tcp_max_per_addr = nconf->tcp_max_per_addr;
		auditd_set_ports(oconf->tcp_client_min_port,
				oconf->tcp_client_max_port,
				oconf->tcp_max_per_addr);
	}
	if (oconf->tcp_client_max_idle != nconf->tcp_client_max_idle) {
		oconf->tcp_client_max_idle = nconf->tcp_client_max_idle;
		periodic_reconfigure(oconf);
	}
	if (oconf->tcp_listen_port != nconf->tcp_listen_port ||
			oconf->tcp_listen_queue != nconf->tcp_listen_queue) {
		oconf->tcp_listen_port = nconf->tcp_listen_port;
		oconf->tcp_listen_queue = nconf->tcp_listen_queue;
		// FIXME: need to restart the network stuff
	}
}
