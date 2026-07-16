/* auditd-listen.c -- 
 * Copyright 2008,2009,2011,2016,2018 Red Hat Inc.
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
 *   Steve Grubb <sgrubb@redhat.com>
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
#ifdef HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "autls.h"
#endif
#include "libaudit.h"
#include "auditd-event.h"
#include "auditd-config.h"
#include "private.h"
#include "common.h"

#include "ev.h"

extern int send_audit_event(int type, const char *str);
#define DEFAULT_BUF_SZ  192
#ifdef HAVE_TLS
#define MAX_ACK_MSG_SIZE 256
#endif

#ifdef HAVE_TLS
_Static_assert(AUTLS_PROFILE_COMPATIBLE == TLS_PROFILE_COMPATIBLE &&
	       AUTLS_PROFILE_SYSTEM == TLS_PROFILE_SYSTEM &&
	       AUTLS_PROFILE_PQC == TLS_PROFILE_PQC,
	       "autls profile constants out of sync with config enums");
#endif

typedef struct ev_tcp {
	struct ev_io io;
	struct sockaddr_storage addr;
	struct ev_tcp *next, *prev;
	unsigned int bufptr;
	int client_active;
#ifdef USE_GSSAPI
	/* This holds the negotiated security context for this client.  */
	gss_ctx_id_t gss_context;
	char *remote_name;
	int remote_name_len;
#endif
#ifdef HAVE_TLS
	SSL *ssl;
	struct ev_timer handshake_timer;
	struct daemon_conf *config;
	int in_handshake_chain;
	int tls_profile_at_accept;
	char *accepted_identity;
	// SSL_ERROR_WANT_* requires retrying the identical write. Keep bounded
	// ACK in client state so it cant be lost on allocation failure.
	unsigned char pending_ack[AUDIT_RMW_HEADER_SIZE + MAX_ACK_MSG_SIZE];
	int pending_ack_len;
#endif
	unsigned char buffer [MAX_AUDIT_MESSAGE_LENGTH + 17];
} ev_tcp;

#define N_SOCKS	4
static int listen_socket[N_SOCKS];
static int nlsocks;
static struct ev_io tcp_listen_watcher;
static struct ev_periodic periodic_watcher;
static unsigned min_port, max_port, max_per_addr;
static int use_libwrap = 1;
static int transport = T_TCP;
static char msgbuf[MAX_AUDIT_MESSAGE_LENGTH + 1];
static struct ev_tcp *client_chain = NULL;
#ifdef USE_GSSAPI
/* This is our global credentials */
static gss_cred_id_t server_creds; // This is used to hold our own private key
static char *my_service_name, *my_gss_realm;
#define USE_GSS (transport == T_KRB5)
#endif
#ifdef HAVE_TLS
static SSL_CTX *tls_server_ctx = NULL;
#define USE_TLS (transport == T_TLS)
static struct ev_tcp *handshake_chain = NULL;
static unsigned int handshake_count = 0;
#define MAX_HANDSHAKE_PENDING 32
static struct autls_acl_table *acl_table = NULL;
static unsigned char *server_psk_key = NULL;
static size_t server_psk_key_len = 0;
static char *expected_psk_identity = NULL;
static int ssl_ex_idx_identity = -1;
static int ssl_ex_idx_reason = -1;
#endif

#if defined(HAVE_TLS) && defined(AUDITD_LISTEN_TEST)
/*
 * auditd_tls_test_set_transport - set listener transport for unit tests
 * @value: transport value to install
 *
 * Returns: None.
 */
void auditd_tls_test_set_transport(int value)
{
	transport = value;
}

/*
 * auditd_tls_test_listener_count - return active listener count for tests
 *
 * Returns: Number of listener slots currently in use.
 */
int auditd_tls_test_listener_count(void)
{
	return nlsocks;
}

/*
 * auditd_tls_test_set_acl_table - install a test ACL table
 * @table: ACL table to install; ownership transfers to the listener
 *
 * Returns: None.
 */
void auditd_tls_test_set_acl_table(struct autls_acl_table *table)
{
	autls_acl_free(acl_table);
	acl_table = table;
}

/*
 * auditd_tls_test_acl_check - check a test identity against live ACL state
 * @identity: identity string to check
 *
 * Returns: autls_acl_check() result, or -2 when no ACL is installed.
 */
int auditd_tls_test_acl_check(const char *identity)
{
	if (acl_table == NULL)
		return -2;
	return autls_acl_check(acl_table, (const unsigned char *)identity,
			       strlen(identity));
}

/*
 * auditd_tls_test_set_psk_state - install minimal live PSK state for tests
 * @active: non-zero to install a PSK marker
 * @identity: optional fallback PSK identity
 *
 * Returns: 0 on success, -1 on allocation failure.
 */
int auditd_tls_test_set_psk_state(int active, const char *identity)
{
	if (server_psk_key) {
		OPENSSL_cleanse(server_psk_key, server_psk_key_len);
		OPENSSL_free(server_psk_key);
	}
	server_psk_key = NULL;
	server_psk_key_len = 0;
	free(expected_psk_identity);
	expected_psk_identity = NULL;

	if (active) {
		server_psk_key = OPENSSL_malloc(1);
		if (server_psk_key == NULL)
			return -1;
		server_psk_key[0] = 0;
		server_psk_key_len = 1;
	}
	if (identity) {
		expected_psk_identity = strdup(identity);
		if (expected_psk_identity == NULL) {
			if (server_psk_key) {
				OPENSSL_cleanse(server_psk_key,
						server_psk_key_len);
				OPENSSL_free(server_psk_key);
			}
			server_psk_key = NULL;
			server_psk_key_len = 0;
			return -1;
		}
	}
	return 0;
}

/*
 * auditd_tls_test_clear - clear listener TLS state used by unit tests
 *
 * Returns: None.
 */
void auditd_tls_test_clear(void)
{
	transport = T_TCP;
	autls_acl_free(acl_table);
	acl_table = NULL;
	if (server_psk_key) {
		OPENSSL_cleanse(server_psk_key, server_psk_key_len);
		OPENSSL_free(server_psk_key);
	}
	server_psk_key = NULL;
	server_psk_key_len = 0;
	free(expected_psk_identity);
	expected_psk_identity = NULL;
}
#endif

/*
 * sockaddr_to_string_buf - format an address into a caller buffer
 * @addr: socket address
 * @buf: output buffer
 * @buflen: output buffer length
 */
static void sockaddr_to_string_buf(const struct sockaddr_storage *addr,
				   char *buf, size_t buflen)
{
	if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6) {
		snprintf(buf, buflen, "?");
		return;
	}

	if (inet_ntop(addr->ss_family, addr->ss_family == AF_INET ?
		(void *) &((struct  sockaddr_in *)addr)->sin_addr :
		(void *) &((struct sockaddr_in6 *)addr)->sin6_addr,
		buf, buflen) == NULL)
		snprintf(buf, buflen, "?");
}

static char *sockaddr_to_string(const struct sockaddr_storage *addr)
{
	static char buf[INET6_ADDRSTRLEN];

	sockaddr_to_string_buf(addr, buf, sizeof(buf));
	return buf;
}

static unsigned int sockaddr_to_port(const struct sockaddr_storage *addr)
{
	unsigned int rc;

	if (addr->ss_family == AF_INET)
		rc = ntohs(((struct  sockaddr_in *)addr)->sin_port);
	else if (addr->ss_family == AF_INET6)
		rc = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
	else
		rc = 0;

	return rc;
}

static char *sockaddr_to_addr(struct sockaddr_storage *addr)
{
	static char buf[64];

	snprintf(buf, sizeof(buf), "%52s:%u",
		sockaddr_to_string(addr),
		sockaddr_to_port(addr));
	return buf;
}

static void set_close_on_exec(int fd)
{
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		flags = 0;
	flags |= FD_CLOEXEC;
	fcntl(fd, F_SETFD, flags);
}

#ifdef HAVE_TLS
static void emit_crypto_key_destroy_record(const struct ev_tcp *client);
#endif

static void release_client(struct ev_tcp *client)
{
	char emsg[DEFAULT_BUF_SZ];

	snprintf(emsg, sizeof(emsg), "addr=%s port=%u res=success",
		sockaddr_to_string(&client->addr),
		sockaddr_to_port(&client->addr));
	send_audit_event(AUDIT_DAEMON_CLOSE, emsg); 
#ifdef HAVE_TLS
	if (client->ssl)
		emit_crypto_key_destroy_record(client);
	if (client->ssl) {
		/* Send close_notify but don't wait for peer's response;
		 * blocking poll() would stall the event loop */
		SSL_shutdown(client->ssl);
		SSL_free(client->ssl);
		client->ssl = NULL;
	}
	free(client->accepted_identity);
	client->accepted_identity = NULL;
	client->pending_ack_len = 0;
#endif
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
	release_client(client);
	free(client);
}

#ifdef HAVE_TLS
#define TLS_AUDIT_BUF_SZ 768
#define TLS_CRYPTO_AUDIT_BUF_SZ 1024

struct tls_endpoint_info {
	char raddr[INET6_ADDRSTRLEN];
	char laddr[INET6_ADDRSTRLEN];
	unsigned int rport;
	unsigned int lport;
};

/* Map crypto profile enum to string for audit records */
static const char *profile_name(int profile)
{
	switch (profile) {
	case TLS_PROFILE_COMPATIBLE: return "compatible";
	case TLS_PROFILE_SYSTEM:     return "system";
	case TLS_PROFILE_PQC:        return "pqc";
	default:                     return "unknown";
	}
}

/*
 * auditd_exe_field - return the executable field for local audit records
 *
 * send_audit_event() bypasses audit_log_user_message(), so internal auditd
 * records need to provide the standard userspace audit tail themselves. Use
 * libaudit's name/value encoder so exe follows the same quoting and
 * hex-encoding rules as audit_log_user_message().
 *
 * This is intentionally auditd's executable, not the TLS peer's. The exe
 * field identifies the local process that originated the audit record so
 * normalized searches do not have to infer the source from the record type.
 */
static const char *auditd_exe_field(void)
{
	static char *exe_field;

	if (exe_field)
		return exe_field;

	exe_field = audit_encode_nv_string("exe", AUDITD_EXE, 0);
	return exe_field ? exe_field : "exe=\"auditd\"";
}

/*
 * get_tls_endpoints - collect TLS peer and local socket endpoints
 * @client: auditd TCP client
 * @ep: output endpoint information
 */
static void get_tls_endpoints(const struct ev_tcp *client,
			      struct tls_endpoint_info *ep)
{
	struct sockaddr_storage local;
	socklen_t len = sizeof(local);

	sockaddr_to_string_buf(&client->addr, ep->raddr, sizeof(ep->raddr));
	ep->rport = sockaddr_to_port(&client->addr);

	if (getsockname(client->io.fd, (struct sockaddr *)&local, &len) == 0) {
		sockaddr_to_string_buf(&local, ep->laddr, sizeof(ep->laddr));
		ep->lport = sockaddr_to_port(&local);
	} else {
		snprintf(ep->laddr, sizeof(ep->laddr), "?");
		ep->lport = 0;
	}
}

/*
 * build_tls_audit_session - fill common crypto audit fields
 * @session: output audit session fields
 * @ep: endpoint information
 * @ssl: active SSL connection
 * @direction: audit direction value
 */
static void build_tls_audit_session(struct autls_audit_session *session,
				    const struct tls_endpoint_info *ep,
				    SSL *ssl, const char *direction)
{
	const SSL_CIPHER *cipher = ssl ? SSL_get_current_cipher(ssl) : NULL;
	const char *pfs = NULL;

#ifdef HAVE_SSL_GROUP_TO_NAME
	if (ssl) {
		int group = SSL_get_negotiated_group(ssl);
		if (group)
			pfs = SSL_group_to_name(ssl, group);
	}
#endif
	session->direction = direction;
	session->cipher = cipher ? SSL_CIPHER_get_name(cipher) : "?";
	session->ksize = cipher ? SSL_CIPHER_get_bits(cipher, NULL) : 0;
	session->pfs = pfs ? pfs : "?";
	session->spid = (long long)getpid();
	session->suid = "?";
	session->rport = ep->rport;
	session->laddr = ep->laddr;
	session->lport = ep->lport;
}

/*
 * emit_crypto_session_record - emit one collector CRYPTO_SESSION record
 * @client: auditd TCP client
 * @ssl: active SSL connection
 * @direction: from-client or from-server
 * @result: audit result string
 *
 * Returns 0 on success, -1 on formatting or internal audit failure.
 */
static int emit_crypto_session_record(const struct ev_tcp *client,
				      SSL *ssl, const char *direction,
				      const char *result)
{
	struct tls_endpoint_info ep;
	struct autls_audit_session session;
	char body[TLS_CRYPTO_AUDIT_BUF_SZ];
	char emsg[TLS_CRYPTO_AUDIT_BUF_SZ];
	int rc;

	get_tls_endpoints(client, &ep);
	build_tls_audit_session(&session, &ep, ssl, direction);

	if (autls_format_crypto_session(body, sizeof(body), &session))
		return -1;
	rc = snprintf(emsg, sizeof(emsg),
		"%s %s hostname=? addr=%s terminal=? res=%s",
		body, auditd_exe_field(), ep.raddr, result);
	if (rc < 0 || (size_t)rc >= sizeof(emsg))
		return -1;
	return send_audit_event(AUDIT_CRYPTO_SESSION, emsg);
}

/*
 * emit_crypto_session_records - emit both TLS CRYPTO_SESSION directions
 * @client: auditd TCP client
 * @ssl: active SSL connection
 * @result: audit result string
 *
 * Returns 0 only if both directional records were created.
 */
static int emit_crypto_session_records(const struct ev_tcp *client,
				       SSL *ssl, const char *result)
{
	int rc = 0;

	if (emit_crypto_session_record(client, ssl, "from-client", result))
		rc = -1;
	else if (emit_crypto_session_record(client, ssl, "from-server", result))
		rc = -1;
	if (rc)
		audit_msg(LOG_ERR,
			"Unable to emit TLS crypto session audit record");
	return rc;
}

/*
 * emit_crypto_key_destroy_record - emit collector CRYPTO_KEY_USER destroy
 * @client: auditd TCP client
 */
static void emit_crypto_key_destroy_record(const struct ev_tcp *client)
{
	struct tls_endpoint_info ep;
	struct autls_audit_session session;
	char body[TLS_CRYPTO_AUDIT_BUF_SZ];
	char emsg[TLS_CRYPTO_AUDIT_BUF_SZ];
	int rc;

	get_tls_endpoints(client, &ep);
	build_tls_audit_session(&session, &ep, client->ssl, "both");

	if (autls_format_crypto_key_destroy(body, sizeof(body), &session))
		goto err;
	rc = snprintf(emsg, sizeof(emsg),
		"%s %s hostname=? addr=%s terminal=? res=success",
		body, auditd_exe_field(), ep.raddr);
	if (rc < 0 || (size_t)rc >= sizeof(emsg))
		goto err;
	if (send_audit_event(AUDIT_CRYPTO_KEY_USER, emsg) == 0)
		return;
err:
	audit_msg(LOG_ERR,
		"Unable to emit TLS crypto key destruction audit record");
}

/*
 * emit_tls_audit_record - format and emit a structured TLS audit record
 * @addr: peer address
 * @ssl: SSL connection (may be NULL for pre-handshake failures)
 * @profile: crypto profile enum value for the audit record
 * @identity: accepted or attempted identity (may be NULL)
 * @reason: stable failure reason or "success"
 * @result: "success" or "no"
 */
static void emit_tls_audit_record(const struct sockaddr_storage *addr,
				  SSL *ssl, int profile,
				  const char *identity, const char *reason,
				  const char *result)
{
	char emsg[TLS_AUDIT_BUF_SZ];
	const char *tlsver = "none";
	const char *cipher = "none";
	const char *group = "unknown";

	if (ssl) {
		tlsver = SSL_get_version(ssl);
		cipher = SSL_get_cipher(ssl);
#ifdef HAVE_SSL_GROUP_TO_NAME
		{
			const char *g = SSL_group_to_name(ssl,
				SSL_get_negotiated_group(ssl));
			if (g)
				group = g;
		}
#endif
	}

	snprintf(emsg, sizeof(emsg),
		"op=tls-accept res=%s role=collector addr=%s port=%u "
		"id=%.128s profile=%s reason=%s auth=psk "
		"tls_version=%s cipher=%s group=%s",
		result,
		sockaddr_to_string(addr), sockaddr_to_port(addr),
		identity ? identity : "?",
		profile_name(profile),
		reason, tlsver, cipher, group);
	send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
}

/*
 * tls_error_cb - OpenSSL error queue drain callback
 *
 * Logs each queued OpenSSL error via audit_msg so that TLS handshake
 * failures produce actionable diagnostics on the server side.
 * Returns 1 to continue draining.
 */
static int tls_error_cb(const char *str, size_t len, void *u)
{
	audit_msg(LOG_ERR, "TLS error: %.*s", (int)len, str);
	return 1;
}

/*
 * unlink_handshake_client - remove a client from the pending TLS list
 * @client: TLS client state
 *
 * The caller owns the client lifetime.  This only updates the handshake
 * accounting so cleanup paths can decide independently which audit records
 * are appropriate for the connection state.
 */
static void unlink_handshake_client(struct ev_tcp *client)
{
	if (!client->in_handshake_chain)
		return;

	if (handshake_chain == client)
		handshake_chain = client->next;
	if (client->next)
		client->next->prev = client->prev;
	if (client->prev)
		client->prev->next = client->next;
	handshake_count--;
	client->in_handshake_chain = 0;
	client->next = NULL;
	client->prev = NULL;
}

/*
 * drop_tls_unaccepted_client - close a TLS client before session acceptance
 * @loop: libev event loop
 * @client: TLS client state
 *
 * Used after a TLS handshake succeeds but the collector cannot create the
 * required crypto audit records.  The client has not been announced with
 * AUDIT_DAEMON_ACCEPT, so this cleanup intentionally avoids the matching
 * close and key-destroy records.
 */
static void drop_tls_unaccepted_client(struct ev_loop *loop,
				       struct ev_tcp *client)
{
	ev_io_stop(loop, &client->io);
	ev_timer_stop(loop, &client->handshake_timer);
	unlink_handshake_client(client);

	if (client->ssl) {
		SSL_free(client->ssl);
		client->ssl = NULL;
	}
	shutdown(client->io.fd, SHUT_RDWR);
	close(client->io.fd);
	free(client->accepted_identity);
	client->pending_ack_len = 0;
	free(client);
}

static void abort_handshake(struct ev_loop *loop,
		struct ev_tcp *client, const char *op)
{
	char *ex_identity = NULL;
	const char *ex_reason = NULL;

	ev_io_stop(loop, &client->io);
	ev_timer_stop(loop, &client->handshake_timer);

	/* Retrieve ex-data before SSL_free destroys the SSL object */
	if (client->ssl) {
		if (ssl_ex_idx_identity >= 0) {
			ex_identity = SSL_get_ex_data(client->ssl,
						ssl_ex_idx_identity);
			SSL_set_ex_data(client->ssl,
					ssl_ex_idx_identity, NULL);
		}
		if (ssl_ex_idx_reason >= 0)
			ex_reason = SSL_get_ex_data(client->ssl,
						ssl_ex_idx_reason);
	}

	emit_tls_audit_record(&client->addr, client->ssl,
			      client->tls_profile_at_accept, ex_identity,
			      ex_reason ? ex_reason : op, "no");
	/*
	 * Do not emit AUDIT_CRYPTO_SESSION for failed collector handshakes.
	 * These failures can be driven by unauthenticated network peers, so
	 * logging one crypto audit record per failed attempt would let a
	 * remote client flood audit storage before it proves authorization.
	 * Successful TLS establishment below is the crypto session audit
	 * boundary; failed handshakes keep their operational
	 * AUDIT_DAEMON_ACCEPT diagnostics.
	 */

	if (client->ssl) {
		ERR_print_errors_cb(tls_error_cb, NULL);
		SSL_free(client->ssl);
		client->ssl = NULL;
	}
	shutdown(client->io.fd, SHUT_RDWR);
	close(client->io.fd);

	unlink_handshake_client(client);

	free(ex_identity);
	free(client->accepted_identity);
	free(client);
}
#endif

static int ar_write(int sock, const void *buf, int len)
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
static int ar_read(int sock, void *buf, int len)
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
static int recv_token(int s, gss_buffer_t tok)
{
	int ret;
	unsigned char lenbuf[4];
	uint32_t len;

	ret = ar_read(s, (char *)lenbuf, 4);
	if (ret < 0) {
		audit_msg(LOG_ERR, "GSS-API error reading token length");
		return -1;
	} else if (!ret) {
		return 0;
	} else if (ret != 4) {
		audit_msg(LOG_ERR, "GSS-API error reading token length");
		return -1;
	}

	/* Cast before shifting so a high-bit wire byte never shifts an int. */
	len = (((uint32_t)lenbuf[0] << 24)
	       | ((uint32_t)lenbuf[1] << 16)
	       | ((uint32_t)lenbuf[2] << 8)
	       | (uint32_t)lenbuf[3]);
	if (len > MAX_AUDIT_MESSAGE_LENGTH) {
		audit_msg(LOG_ERR,
			"GSS-API error: event length exceeds MAX_AUDIT_LENGTH");
		return -1;
	}
	tok->length = len;

	tok->value = (char *)malloc(tok->length ? tok->length : 1);
	if (tok->length && tok->value == NULL) {
		audit_msg(LOG_ERR, "Out of memory allocating token data");
		return -1;
	}

	ret = ar_read(s, (char *)tok->value, tok->length);
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
	} else if (ret != (int)tok->length) {
		audit_msg(LOG_ERR, "GSS-API error sending token data");
		return -1;
	}

	return 0;
}


static void gss_failure_2(const char *msg, int status, int type)
{
	OM_uint32 message_context = 0;
	OM_uint32 min_status = 0;
	gss_buffer_desc status_string;

	do {
		gss_display_status(&min_status,
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

static void gss_failure(const char *msg, int major_status, int minor_status)
{
	gss_failure_2(msg, major_status, GSS_C_GSS_CODE);
	if (minor_status)
		gss_failure_2(msg, minor_status, GSS_C_MECH_CODE);
}

#define KCHECK(x,f, k) if (x) { \
		const char *kstr = krb5_get_error_message(kcontext, x); \
		audit_msg(LOG_ERR, "krb5 error: %s in %s\n", kstr, f); \
		krb5_free_error_message(kcontext, kstr); \
		krb5_free_context(k); k = NULL; \
		return -1; }

/* These are our private credentials, which come from a key file on
   our server.  They are acquired once, at program start.  */
static krb5_context kcontext = NULL;
static int server_acquire_creds(const char *service_name,
		gss_cred_id_t *lserver_creds)
{
	gss_buffer_desc name_buf;
	gss_name_t server_name;
	OM_uint32 major_status, minor_status;

	int krberr;

	my_service_name = strdup(service_name);
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
					lserver_creds, NULL, NULL);
	if (major_status != GSS_S_COMPLETE) {
		gss_failure("acquiring credentials",
				major_status, minor_status);
		(void) gss_release_name(&minor_status, &server_name);
		return -1;
	}

	(void) gss_release_name(&minor_status, &server_name);

	krberr = krb5_init_context(&kcontext);
	KCHECK (krberr, "krb5_init_context", kcontext);
	krberr = krb5_get_default_realm(kcontext, &my_gss_realm);
	KCHECK (krberr, "krb5_get_default_realm", kcontext);

	audit_msg(LOG_DEBUG, "GSS creds for %s acquired", service_name);

	return 0;
}

/* This is where we negotiate a security context with the client.  In
   the case of Kerberos, this is where the key exchange happens.
   FIXME: While everything else is strictly nonblocking, this
   negotiation blocks.  */
static int negotiate_credentials(ev_tcp *io)
{
	gss_buffer_desc send_tok, recv_tok;
	gss_name_t client;
	OM_uint32 maj_stat, min_stat, acc_sec_min_stat;
	gss_ctx_id_t *context;
	OM_uint32 sess_flags;
	char *slashptr, *atptr;

	context = & io->gss_context;
	*context = GSS_C_NO_CONTEXT;
	io->remote_name = NULL;

	maj_stat = GSS_S_CONTINUE_NEEDED;
	do {
		/* STEP 1 - get a token from the client.  */

		if (recv_token(io->io.fd, &recv_tok) <= 0) {
			audit_msg(LOG_ERR,
			"TCP session from %s will be closed, error ignored",
				  sockaddr_to_addr(&io->addr));
			return -1;
		}
		if (recv_tok.length == 0) {
			free(recv_tok.value);
			recv_tok.value = NULL;
			continue;
		}

		/* STEP 2 - let GSS process that token.  */

		maj_stat = gss_accept_sec_context(&acc_sec_min_stat,
					context, server_creds,
					&recv_tok,
					GSS_C_NO_CHANNEL_BINDINGS, &client,
					NULL, &send_tok, &sess_flags,
					NULL, NULL);
		if (recv_tok.value)
			gss_release_buffer(&min_stat, &recv_tok);

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
					  sockaddr_to_addr(&io->addr));
				if (*context != GSS_C_NO_CONTEXT)
					gss_delete_sec_context(&min_stat,
						context, GSS_C_NO_BUFFER);
				gss_release_name(&min_stat, &client);
				return -1;
			}
		}
		gss_release_buffer(&min_stat, &send_tok);
	} while (maj_stat == GSS_S_CONTINUE_NEEDED);

	maj_stat = gss_display_name(&min_stat, client, &recv_tok, NULL);
	gss_release_name(&min_stat, &client);

	if (maj_stat != GSS_S_COMPLETE) {
		gss_failure("displaying name", maj_stat, min_stat);
		return -1;
	}

	if (asprintf(&io->remote_name, "%.*s", (int)recv_tok.length,
		    (char *)recv_tok.value) < 0) {
		io->remote_name = strdup("?");
		io->remote_name_len = 1;
	} else
		io->remote_name_len = recv_tok.length;

	audit_msg(LOG_INFO, "GSS-API Accepted connection from: %s", 
		  io->remote_name);
	gss_release_buffer(&min_stat, &recv_tok);

	if (io->remote_name) {
		slashptr = strchr(io->remote_name, '/');
		atptr = strchr(io->remote_name, '@');
	} else
		slashptr = NULL;

	if (!slashptr || !atptr) {
		audit_msg(LOG_ERR, "Invalid GSS name from remote client: %s",
			  io->remote_name);
		return -1;
	}

	*slashptr = 0;
	if (strcmp(io->remote_name, my_service_name)) {
		audit_msg(LOG_ERR, "Unauthorized GSS client name: %s (not %s)",
			  io->remote_name, my_service_name);
		return -1;
	}
	*slashptr = '/';

	if (strcmp(atptr+1, my_gss_realm)) {
		audit_msg(LOG_ERR, "Unauthorized GSS client realm: %s (not %s)",
			  atptr+1, my_gss_realm);
		return -1;
	}

	return 0;
}
#endif /* USE_GSSAPI */

/* This is called from auditd-event after the message has been logged.
   The header is already filled in.  */
static void client_ack(void *ack_data, const unsigned char *header,
	const char *msg)
{
	ev_tcp *io = (ev_tcp *)ack_data;
#ifdef HAVE_TLS
	if (USE_TLS && io->ssl) {
		unsigned char buf[AUDIT_RMW_HEADER_SIZE + MAX_ACK_MSG_SIZE];
		int total, ret, err;

		/* Drop stale pending ACK — client will see the latest */
		io->pending_ack_len = 0;

		memcpy(buf, header, AUDIT_RMW_HEADER_SIZE);
		total = AUDIT_RMW_HEADER_SIZE;
		if (msg[0]) {
			int mlen = strlen(msg);
			if (mlen > MAX_ACK_MSG_SIZE)
				mlen = MAX_ACK_MSG_SIZE;
			_AUDIT_RMW_PUTN16(buf, 10, mlen);
			memcpy(buf + AUDIT_RMW_HEADER_SIZE, msg, mlen);
			total += mlen;
		}

		ret = SSL_write(io->ssl, buf, total);
		if (ret == total)
			return;

		err = SSL_get_error(io->ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE ||
		    err == SSL_ERROR_WANT_READ) {
			memcpy(io->pending_ack, buf, total);
			io->pending_ack_len = total;
			ev_io_stop(EV_DEFAULT, &io->io);
			if (err == SSL_ERROR_WANT_WRITE)
				ev_io_modify(&io->io, EV_WRITE);
			else
				ev_io_modify(&io->io, EV_READ);
			ev_io_start(EV_DEFAULT, &io->io);
			return;
		}

		audit_msg(LOG_ERR, "TLS send ack to %s failed",
			sockaddr_to_addr(&io->addr));
		shutdown(io->io.fd, SHUT_RDWR);
		return;
	}
#endif
#ifdef USE_GSSAPI
	if (USE_GSS) {
		OM_uint32 major_status, minor_status;
		gss_buffer_desc utok, etok;
		int mlen;

		mlen = strlen(msg);
		utok.length = AUDIT_RMW_HEADER_SIZE + mlen;
		utok.value = malloc(utok.length + 1);
		if (utok.value == NULL) {
			audit_msg(LOG_ERR, "GSS-API ACK to %s lost: "
				"out of memory", sockaddr_to_addr(&io->addr));
			return;
		}

		memcpy(utok.value, header, AUDIT_RMW_HEADER_SIZE);
		memcpy(utok.value+AUDIT_RMW_HEADER_SIZE, msg, mlen);

		/* Wrapping the message creates a token for the
		   client.  Then we just have to worry about sending
		   the token.  */

		major_status = gss_wrap(&minor_status,
					 io->gss_context,
					 1,
					 GSS_C_QOP_DEFAULT,
					 &utok,
					 NULL,
					 &etok);
		if (major_status != GSS_S_COMPLETE) {
			gss_failure("encrypting message", major_status,
					minor_status);
			free(utok.value);
			return;
		}

		if (send_token(io->io.fd, &etok) < 0) {
			audit_msg(LOG_ERR,
				"GSS-API error sending token to %s",
				sockaddr_to_addr(&io->addr));
			free(utok.value);
			(void) gss_release_buffer(&minor_status, &etok);
			return;
		}
		free(utok.value);
		(void) gss_release_buffer(&minor_status, &etok);

		return;
	}
#endif
	// Send the header and a text error message if it exists
	ar_write(io->io.fd, header, AUDIT_RMW_HEADER_SIZE);
	if (msg[0])
		ar_write(io->io.fd, msg, strlen(msg));
}

static void client_message (struct ev_tcp *io, unsigned int length,
	unsigned char *header)
{
	unsigned char ch;
	uint32_t type, mlen, seq;
	int hver, mver;

	if (AUDIT_RMW_IS_MAGIC (header, length)) {
		AUDIT_RMW_UNPACK_HEADER (header, hver, mver, type, mlen, seq)

		size_t term_idx;

		if (length >= MAX_AUDIT_MESSAGE_LENGTH)
			term_idx = MAX_AUDIT_MESSAGE_LENGTH - 1;
		else
			term_idx = length;

		ch = header[term_idx];
		header[term_idx] = 0;
		if (term_idx > 1 && header[term_idx-1] == '\n')
			header[term_idx-1] = 0;
		if (type == AUDIT_RMW_TYPE_HEARTBEAT) {
			unsigned char ack[AUDIT_RMW_HEADER_SIZE];
			AUDIT_RMW_PACK_HEADER (ack, 0, AUDIT_RMW_TYPE_ACK,
				0, seq);
			client_ack(io, ack, "");
		} else {
			struct auditd_event *e = create_event(
					header+AUDIT_RMW_HEADER_SIZE,
					client_ack, io, seq);
			if (e)
				distribute_event(e);
		}
		header[term_idx] = ch;
	}
}

static void auditd_tcp_client_handler(struct ev_loop *loop,
			struct ev_io *_io, int revents)
{
	struct ev_tcp *io = (struct ev_tcp *)_io;
	int i, r;
	int total_this_call = 0;

	io->client_active = 1;

	/* The socket is non-blocking, but we have a limited buffer
	   size.  In the event that we get a packet that's bigger than
	   our buffer, we need to read it in multiple parts.  Thus, we
	   keep reading/parsing/processing until we run out of ready
	   data.  */
read_more:
#ifdef HAVE_TLS
	if (USE_TLS && io->ssl) {
		/* Drain any pending ACK write before reading */
		if (io->pending_ack_len) {
			int ret = SSL_write(io->ssl, io->pending_ack,
					    io->pending_ack_len);
			if (ret == io->pending_ack_len) {
				io->pending_ack_len = 0;

				/* Buffered data may be a partial record and return
				 * before the read path can re-arm the watcher. */
				if (_io->events & EV_WRITE) {
					ev_io_stop(loop, _io);
					ev_io_modify(_io, EV_READ);
					ev_io_start(loop, _io);
				}

				/* Process leftover data from a prior
				 * batch before reading from SSL */
				if (io->bufptr > 0) {
					r = io->bufptr;
					io->bufptr = 0;
					goto more_messages;
				}
			} else {
				int err = SSL_get_error(io->ssl, ret);
				if (err == SSL_ERROR_WANT_WRITE ||
				    err == SSL_ERROR_WANT_READ) {
					ev_io_stop(loop, _io);
					if (err == SSL_ERROR_WANT_WRITE)
						ev_io_modify(_io, EV_WRITE);
					else
						ev_io_modify(_io, EV_READ);
					ev_io_start(loop, _io);
					return;
				}
				audit_msg(LOG_ERR,
					"TLS pending ack to %s failed",
					sockaddr_to_addr(&io->addr));
				ev_io_stop(loop, _io);
				close_client(io);
				return;
			}
		}

		/* Re-arm for reading after draining pending write */
		if (_io->events & EV_WRITE) {
			ev_io_stop(loop, _io);
			ev_io_modify(_io, EV_READ);
			ev_io_start(loop, _io);
		}

		r = SSL_read(io->ssl,
			io->buffer + io->bufptr,
			MAX_AUDIT_MESSAGE_LENGTH - io->bufptr);
		if (r <= 0) {
			int ssl_err = SSL_get_error(io->ssl, r);
			if (ssl_err == SSL_ERROR_WANT_READ) {
				if (_io->events & EV_WRITE) {
					ev_io_stop(loop, _io);
					ev_io_modify(_io, EV_READ);
					ev_io_start(loop, _io);
				}
				return;
			}
			if (ssl_err == SSL_ERROR_WANT_WRITE) {
				ev_io_stop(loop, _io);
				ev_io_modify(_io, EV_WRITE);
				ev_io_start(loop, _io);
				return;
			}
			/* real error or shutdown falls through */
		}
		/* Restore EV_READ if we were armed for EV_WRITE
		 * due to a previous WANT_WRITE */
		if (r > 0 && (_io->events & EV_WRITE)) {
			ev_io_stop(loop, _io);
			ev_io_modify(_io, EV_READ);
			ev_io_start(loop, _io);
		}
	} else
#endif
	{
		r = read(io->io.fd,
			io->buffer + io->bufptr,
			MAX_AUDIT_MESSAGE_LENGTH - io->bufptr);

		if (r < 0 && errno == EAGAIN)
			r = 0;
	}

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
			audit_msg(LOG_WARNING,
				"client %s socket closed unexpectedly",
				sockaddr_to_addr(&io->addr));

		/* There may have been a final message without a LF.  */
		if (io->bufptr) {
			client_message(io, io->bufptr, io->buffer);

		}

		ev_io_stop(loop, _io);
		close_client(io);
		return;
	}

	total_this_call += r;

more_messages:
#ifdef USE_GSSAPI
	/* If we're using GSS at all, everything will be encrypted,
	   one record per token.  */
	if (USE_GSS) {
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
		major_status = gss_unwrap(&minor_status, io->gss_context,
				&etok, &utok, NULL, NULL);

		if (major_status != GSS_S_COMPLETE) {
			gss_failure("decrypting message", major_status,
				minor_status);
		} else {
			/* client_message() wants to NUL terminate it,
			   so copy it to a bigger buffer.  Plus, we
			   want to add our own tag.  */
			memcpy(msgbuf, utok.value, utok.length);
			while (utok.length > 0 && msgbuf[utok.length-1] == '\n')
				utok.length --;
			snprintf(msgbuf + utok.length,
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
		client_message(io, i, io->buffer);

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
		client_message(io, i, io->buffer);
	}

	/* Now copy any remaining bytes to the beginning of the
	   buffer.  */
	memmove(io->buffer, io->buffer + i, io->bufptr - i);
	io->bufptr -= i;

	/* See if this packet had more than one message in it. */
	if (io->bufptr > 0) {
#ifdef HAVE_TLS
		if (USE_TLS && io->pending_ack_len)
			return;
#endif
		r = io->bufptr;
		io->bufptr = 0;
		goto more_messages;
	}

	/* Go back and see if there's more data to read.  */
	goto read_more;
}

#ifdef HAVE_LIBWRAP
int allow_severity = LOG_INFO, deny_severity = LOG_NOTICE;
static int auditd_tcpd_check(int sock)
{
	struct request_info request;

	request_init(&request, RQ_DAEMON, "auditd", RQ_FILE, sock, 0);
	fromhost(&request);
	if (!hosts_access(&request))
		return 1;
	return 0;
}
#endif

/*
 * This function counts the number of concurrent connections and returns
 * a 1 if there are too many and a 0 otherwise. It assumes the incoming
 * connection has not been added to the linked list yet.
 */
static int check_num_connections(const struct sockaddr_storage *aaddr)
{
	int num = 0;
	struct ev_tcp *client = client_chain;

	while (client) {
		int rc;
		struct sockaddr_storage *cl_addr = &client->addr;

		if (aaddr->ss_family == AF_INET)
			rc = memcmp(&((struct sockaddr_in *)aaddr)->sin_addr,
				&((struct sockaddr_in *)cl_addr)->sin_addr,
				sizeof(struct in_addr));
		else
			rc = memcmp(&((struct sockaddr_in6 *)aaddr)->sin6_addr,
				&((struct sockaddr_in6 *)cl_addr)->sin6_addr,
				sizeof(struct in6_addr));
		if (rc == 0) {
			num++;
			if (num >= max_per_addr)
				return 1;
		}
		client = client->next;
	}
#ifdef HAVE_TLS
	client = handshake_chain;
	while (client) {
		struct sockaddr_storage *cl_addr = &client->addr;

		if (aaddr->ss_family == cl_addr->ss_family) {
			int rc;
			if (aaddr->ss_family == AF_INET)
				rc = memcmp(
					&((struct sockaddr_in *)aaddr)->sin_addr,
					&((struct sockaddr_in *)cl_addr)->sin_addr,
					sizeof(struct in_addr));
			else
				rc = memcmp(
					&((struct sockaddr_in6 *)aaddr)->sin6_addr,
					&((struct sockaddr_in6 *)cl_addr)->sin6_addr,
					sizeof(struct in6_addr));
			if (rc == 0) {
				num++;
				if (num >= max_per_addr)
					return 1;
			}
		}
		client = client->next;
	}
#endif
	return 0;
}

void write_connection_state(FILE *f)
{
	unsigned int num = 0, act = 0;
	struct ev_tcp *client = client_chain;

	fprintf(f, "listening for network connections = %s\n",
		nlsocks ? "yes" : "no");
	if (nlsocks) {
		while (client) {
			if (client->client_active)
				act++;
			num++;
			client = client->next;
		}
		fprintf(f, "active connections = %u\n", act);
		fprintf(f, "total connections = %u\n", num);
	}
}

#ifdef HAVE_TLS
/*
 * tls_handshake_timeout_cb - abort a TLS handshake that exceeded its deadline
 * @loop: libev event loop
 * @w: timer watcher (w->data points to the client ev_tcp)
 * @revents: libev event flags (unused)
 *
 * Fires after the handshake timeout (5 seconds). Logs the peer address
 * and tears down the pending connection via abort_handshake().
 */
static void tls_handshake_timeout_cb(struct ev_loop *loop,
		struct ev_timer *w, int revents)
{
	struct ev_tcp *client = (struct ev_tcp *)w->data;

	audit_msg(LOG_ERR, "TLS handshake timeout from %s",
		sockaddr_to_addr(&client->addr));
	abort_handshake(loop, client, "handshake-timeout");
}

/*
 * tls_handshake_handler - drive the non-blocking TLS handshake state machine
 * @loop: libev event loop
 * @_io: I/O watcher (cast to ev_tcp for client state)
 * @revents: libev event flags
 *
 * Called by libev when the handshake socket is readable or writable.
 * Calls SSL_do_handshake() and re-arms the watcher for the direction
 * OpenSSL needs. On completion, switches the callback to the normal
 * data handler. On error or timeout, tears down via abort_handshake().
 */
static void tls_handshake_handler(struct ev_loop *loop,
		struct ev_io *_io, int revents)
{
	struct ev_tcp *client = (struct ev_tcp *)_io;
	int ret, err;
	const char *kex_name;

	ret = SSL_do_handshake(client->ssl);
	if (ret == 1) {
		/* Handshake complete */
		ev_timer_stop(loop, &client->handshake_timer);

#ifdef HAVE_SSL_GROUP_TO_NAME
		kex_name = SSL_group_to_name(client->ssl,
			SSL_get_negotiated_group(client->ssl));
#else
		kex_name = NULL;
#endif
		audit_msg(LOG_INFO,
			"TLS connection from %s using %s kex=%s",
			sockaddr_to_addr(&client->addr),
			SSL_get_cipher(client->ssl),
			kex_name ? kex_name : "unknown");

		if (client->tls_profile_at_accept ==
		    TLS_PROFILE_PQC &&
		    !autls_is_pqc_group(kex_name)) {
			audit_msg(LOG_ERR,
				"PQC key exchange required but "
				"negotiated group '%s' is not PQC "
				"from %s",
				kex_name ? kex_name : "unknown",
				sockaddr_to_addr(&client->addr));
			abort_handshake(loop, client,
				"handshake-pqc");
			return;
		}

		/* Transfer accepted identity from ex-data to client */
		if (ssl_ex_idx_identity >= 0) {
			client->accepted_identity =
				SSL_get_ex_data(client->ssl,
						ssl_ex_idx_identity);
			SSL_set_ex_data(client->ssl,
					ssl_ex_idx_identity, NULL);
		}

		if (client->accepted_identity == NULL) {
			audit_msg(LOG_ERR,
				"TLS handshake from %s completed "
				"without PSK identity; rejecting",
				sockaddr_to_addr(&client->addr));
			abort_handshake(loop, client,
				"no-psk-identity");
			return;
		}

		/* Remove from handshake_chain */
		unlink_handshake_client(client);

		/*
		 * AUDIT_CRYPTO_SESSION is success-only on the collector.
		 * Failed handshakes are still logged as operational
		 * AUDIT_DAEMON_ACCEPT failures, but not as crypto session
		 * records, so unauthenticated peers cannot flood crypto audit
		 * records before authorization.  If the success records cannot
		 * be created, close only this new client and leave auditd up.
		 */
		if (emit_crypto_session_records(client, client->ssl,
						"success")) {
			audit_msg(LOG_ERR,
				"Unable to audit TLS crypto session from "
				"%s; closing new client",
				sockaddr_to_addr(&client->addr));
			drop_tls_unaccepted_client(loop, client);
			return;
		}

		/* Switch to data handler */
		ev_io_stop(loop, &client->io);
		ev_set_cb(&client->io, auditd_tcp_client_handler);
		ev_io_modify(&client->io, EV_READ);
		ev_io_start(loop, &client->io);

		/* TLS 1.3 read-ahead may have buffered application
		 * data during the handshake; kick the data handler
		 * so it drains anything already in the BIO buffer */
		if (SSL_has_pending(client->ssl))
			ev_feed_event(loop, &client->io, EV_READ);

		/* Insert into client_chain */
		client->client_active = 1;
		client->next = client_chain;
		client->prev = NULL;
		if (client->next)
			client->next->prev = client;
		client_chain = client;

		emit_tls_audit_record(&client->addr, client->ssl,
				      client->tls_profile_at_accept,
				      client->accepted_identity,
				      "success", "success");
		return;
	}

	err = SSL_get_error(client->ssl, ret);
	if (err == SSL_ERROR_WANT_READ) {
		ev_io_stop(loop, &client->io);
		ev_io_modify(&client->io, EV_READ);
		ev_io_start(loop, &client->io);
		return;
	}
	if (err == SSL_ERROR_WANT_WRITE) {
		ev_io_stop(loop, &client->io);
		ev_io_modify(&client->io, EV_WRITE);
		ev_io_start(loop, &client->io);
		return;
	}

	audit_msg(LOG_ERR, "TLS handshake from %s failed",
		sockaddr_to_addr(&client->addr));
	abort_handshake(loop, client, "handshake-error");
}
#endif

static void auditd_tcp_listen_handler( struct ev_loop *loop,
	struct ev_io *_io, int revents)
{
	int one=1;
	int afd;
	socklen_t aaddrlen;
	struct sockaddr_storage aaddr;
	struct ev_tcp *client;
	char emsg[DEFAULT_BUF_SZ];

	/* Accept the connection and see where it's coming from.  */
	aaddrlen = sizeof(aaddr);
	afd = accept(_io->fd, (struct sockaddr *)&aaddr, &aaddrlen);
	if (afd == -1) {
		audit_msg(LOG_ERR, "Unable to accept TCP connection");
		return;
	}

#ifdef HAVE_LIBWRAP
	if (use_libwrap) {
		if (auditd_tcpd_check(afd)) {
			shutdown(afd, SHUT_RDWR);
			close(afd);
			audit_msg(LOG_ERR, "TCP connection from %s rejected",
					sockaddr_to_addr(&aaddr));
			snprintf(emsg, sizeof(emsg),
				"op=wrap addr=%s port=%u res=no",
				sockaddr_to_string(&aaddr),
				sockaddr_to_port(&aaddr));
			send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
			return;
		}
	}
#endif

	/* Verify it's coming from an authorized port.  We assume the firewall
	 * will block attempts from unauthorized machines.  */
	if (min_port > sockaddr_to_port(&aaddr) ||
				sockaddr_to_port(&aaddr) > max_port) {
		audit_msg(LOG_ERR, "TCP connection from %s rejected",
				sockaddr_to_addr(&aaddr));
		snprintf(emsg, sizeof(emsg),
			"op=port addr=%s port=%u res=no",
			sockaddr_to_string(&aaddr),
			sockaddr_to_port(&aaddr));
		send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
		shutdown(afd, SHUT_RDWR);
		close(afd);
		return;
	}

	/* Make sure we don't have too many connections */
	if (check_num_connections(&aaddr)) {
		audit_msg(LOG_ERR, "Too many connections from %s - rejected",
				sockaddr_to_addr(&aaddr));
		snprintf(emsg, sizeof(emsg),
			"op=dup addr=%s port=%u res=no",
			sockaddr_to_string(&aaddr),
			sockaddr_to_port(&aaddr));
		send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
		shutdown(afd, SHUT_RDWR);
		close(afd);
		return;
	}

	/* Connection is accepted...start setting it up */
	setsockopt(afd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof (int));
	setsockopt(afd, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, sizeof (int));
	setsockopt(afd, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof (int));
	set_close_on_exec(afd);

	/* Make the client data structure */
	client = (struct ev_tcp *)malloc (sizeof (struct ev_tcp));
	if (client == NULL) {
		audit_msg(LOG_CRIT, "Unable to allocate TCP client data");
		snprintf(emsg, sizeof(emsg),
			"op=alloc addr=%s port=%u res=no",
			sockaddr_to_string(&aaddr),
			sockaddr_to_port(&aaddr));
		send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
		shutdown(afd, SHUT_RDWR);
		close(afd);
		return;
	}

	memset(client, 0, sizeof (struct ev_tcp));
	client->client_active = 1;

	// Was watching for EV_ERROR, but libev 3.48 took it away
	ev_io_init(&(client->io), auditd_tcp_client_handler, afd, EV_READ);

	memcpy(&client->addr, &aaddr, sizeof (struct sockaddr_storage));

#ifdef HAVE_TLS
	if (USE_TLS) {
		struct daemon_conf *lconfig =
			(struct daemon_conf *)_io->data;

		if (tls_server_ctx == NULL) {
			audit_msg(LOG_ERR,
				"TLS listener has no server context; rejecting %s",
				sockaddr_to_addr(&aaddr));
			snprintf(emsg, sizeof(emsg),
				"op=tls-context addr=%s port=%u res=no",
				sockaddr_to_string(&aaddr),
				sockaddr_to_port(&aaddr));
			send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
			shutdown(afd, SHUT_RDWR);
			close(afd);
			free(client);
			return;
		}

		if (handshake_count >= MAX_HANDSHAKE_PENDING) {
			audit_msg(LOG_ERR,
				"TLS handshake limit reached, "
				"rejecting %s",
				sockaddr_to_addr(&aaddr));
			snprintf(emsg, sizeof(emsg),
				"op=handshake-limit addr=%s port=%u "
				"res=no",
				sockaddr_to_string(&aaddr),
				sockaddr_to_port(&aaddr));
			send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
			shutdown(afd, SHUT_RDWR);
			close(afd);
			free(client);
			return;
		}

		fcntl(afd, F_SETFL, O_NONBLOCK | O_NDELAY);

		client->ssl = SSL_new(tls_server_ctx);
		if (client->ssl == NULL ||
		    SSL_set_fd(client->ssl, afd) != 1) {
			audit_msg(LOG_ERR,
				"TLS setup for %s failed",
				sockaddr_to_addr(&aaddr));
			if (client->ssl) {
				SSL_free(client->ssl);
				client->ssl = NULL;
			}
			shutdown(afd, SHUT_RDWR);
			close(afd);
			free(client);
			return;
		}
		SSL_set_accept_state(client->ssl);

		client->config = lconfig;
		client->tls_profile_at_accept =
			lconfig->tls_crypto_profile;
		client->client_active = 0;
		client->in_handshake_chain = 0;

		ev_io_init(&client->io, tls_handshake_handler,
			afd, EV_READ);
		ev_timer_init(&client->handshake_timer,
			tls_handshake_timeout_cb, 5.0, 0.0);
		client->handshake_timer.data = client;

		/* Track in handshake_chain */
		client->next = handshake_chain;
		client->prev = NULL;
		if (client->next)
			client->next->prev = client;
		handshake_chain = client;
		handshake_count++;
		client->in_handshake_chain = 1;

		ev_io_start(loop, &client->io);
		ev_timer_start(loop, &client->handshake_timer);
		return;
	}
#endif
#ifdef USE_GSSAPI
	if (USE_GSS && negotiate_credentials (client)) {
		shutdown(afd, SHUT_RDWR);
		close(afd);
		free(client->remote_name);
		free(client);
		return;
	}
#endif

	fcntl(afd, F_SETFL, O_NONBLOCK | O_NDELAY);
	ev_io_start(loop, &(client->io));

	/* Add the new connection to a linked list of active clients.  */
	client->next = client_chain;
	if (client->next)
		client->next->prev = client;
	client_chain = client;

	/* And finally log that we accepted the connection */
	snprintf(emsg, sizeof(emsg),
		"addr=%s port=%u res=success", sockaddr_to_string(&aaddr),
		sockaddr_to_port(&aaddr));
	send_audit_event(AUDIT_DAEMON_ACCEPT, emsg);
}

static void auditd_set_ports(unsigned minp, unsigned maxp, unsigned max_p_addr)
{
	min_port = minp;
	max_port = maxp;
	max_per_addr = max_p_addr;
}

static void periodic_handler(struct ev_loop *loop, struct ev_periodic *per,
			int revents)
{
	struct daemon_conf *config = (struct daemon_conf *) per->data;
	struct ev_tcp *ev, *next = NULL;
	int active;

	if (!config->tcp_client_max_idle)
		return;

	for (ev = client_chain; ev; ev = next) {
		next = ev->next;
		active = ev->client_active;
		ev->client_active = 0;
		if (active)
			continue;

		audit_msg(LOG_NOTICE,
			"client %s idle too long - closing connection\n",
			sockaddr_to_addr(&(ev->addr)));
		ev_io_stop(loop, &ev->io);
		release_client(ev);
		free(ev);
	}
}

#ifdef HAVE_TLS
/* Store a failure reason in SSL ex-data for audit records */
static void set_psk_failure_reason(SSL *ssl, const char *reason)
{
	if (ssl_ex_idx_reason >= 0)
		SSL_set_ex_data(ssl, ssl_ex_idx_reason, (void *)reason);
}

/* Sanitize an identity for logging (non-printable → '.') */
static void sanitize_identity(const unsigned char *id, size_t len,
			      char *buf, size_t bufsz)
{
	size_t log_len, j;

	if (bufsz == 0)
		return;
	log_len = len < bufsz - 1 ? len : bufsz - 1;

	for (j = 0; j < log_len; j++)
		buf[j] = (id[j] >= 0x20 && id[j] <= 0x7E)
			 ? (char)id[j] : '.';
	buf[log_len] = '\0';
}

/*
 * tls_psk_find_session_cb - TLS 1.3 server PSK callback
 * @ssl: SSL connection handle
 * @identity: client-supplied PSK identity
 * @identity_len: length of @identity
 * @sess: output SSL_SESSION containing the matched PSK
 *
 * Called by OpenSSL during TLS 1.3 handshake to look up the PSK for
 * a client identity. Validates the identity, checks it against the
 * ACL table (if configured) or expected_psk_identity (if not), and
 * stores the accepted identity in SSL ex-data for later retrieval.
 * Returns 1 on success, 0 on failure or identity mismatch.
 */
static int tls_psk_find_session_cb(SSL *ssl, const unsigned char *identity,
		size_t identity_len, SSL_SESSION **sess)
{
	SSL_SESSION *s;
	const SSL_CIPHER *cipher;
	char safe_id[65];

	if (server_psk_key == NULL)
		return 0;

	/* Validate identity syntax before any authorization check */
	if (autls_validate_psk_identity(identity, identity_len,
					audit_msg) != 0) {
		sanitize_identity(identity, identity_len,
				  safe_id, sizeof(safe_id));
		audit_msg(LOG_ERR,
			"TLS PSK invalid identity: '%s'%s",
			safe_id,
			identity_len > 64 ? " (truncated)" : "");
		set_psk_failure_reason(ssl, "invalid-identity");
		return 0;
	}

	/* Authorization: ACL table supersedes single identity */
	if (acl_table) {
		int rc = autls_acl_check(acl_table, identity,
					 identity_len);
		if (rc < 0) {
			sanitize_identity(identity, identity_len,
					  safe_id, sizeof(safe_id));
			audit_msg(LOG_ERR,
				"TLS PSK unknown identity: '%s'",
				safe_id);
			set_psk_failure_reason(ssl,
					       "unknown-identity");
			return 0;
		}
		if (rc == 0) {
			sanitize_identity(identity, identity_len,
					  safe_id, sizeof(safe_id));
			audit_msg(LOG_ERR,
				"TLS PSK disabled identity: '%s'",
				safe_id);
			set_psk_failure_reason(ssl,
					       "disabled-identity");
			return 0;
		}
	} else if (expected_psk_identity) {
		if (identity_len != strlen(expected_psk_identity) ||
		    CRYPTO_memcmp(identity, expected_psk_identity,
				  identity_len) != 0) {
			sanitize_identity(identity, identity_len,
					  safe_id, sizeof(safe_id));
			audit_msg(LOG_ERR,
				"TLS PSK identity mismatch: "
				"received '%s'%s", safe_id,
				identity_len > 64 ?
				" (truncated)" : "");
			set_psk_failure_reason(ssl,
					       "unknown-identity");
			return 0;
		}
	} else {
		/* No authorization configured -- fail closed */
		audit_msg(LOG_ERR,
			"TLS PSK rejected: no identity authorization "
			"configured");
		set_psk_failure_reason(ssl, "no-authorization");
		return 0;
	}

	cipher = autls_find_tls13_cipher(ssl, NULL);
	if (cipher == NULL) {
		audit_msg(LOG_ERR,
			"TLS PSK: no cipher matches PSK hash");
		set_psk_failure_reason(ssl, "no-matching-cipher");
		return 0;
	}

	s = SSL_SESSION_new();
	if (s == NULL) {
		audit_msg(LOG_ERR,
			"TLS PSK: SSL_SESSION_new failed");
		set_psk_failure_reason(ssl, "session-alloc-failed");
		return 0;
	}

	if (!SSL_SESSION_set1_master_key(s, server_psk_key,
					server_psk_key_len) ||
	    !SSL_SESSION_set_cipher(s, cipher) ||
	    !SSL_SESSION_set_protocol_version(s, TLS1_3_VERSION)) {
		audit_msg(LOG_ERR,
			"TLS PSK: SSL session setup failed");
		SSL_SESSION_free(s);
		set_psk_failure_reason(ssl, "session-setup-failed");
		return 0;
	}

	/* Store accepted identity only after session setup succeeds. Keep the old
	 * value attached until OpenSSL accepts its replacement. */
	if (ssl_ex_idx_identity >= 0) {
		char *old = SSL_get_ex_data(ssl, ssl_ex_idx_identity);
		char *id_copy = strndup((const char *)identity,
					identity_len);
		if (id_copy == NULL) {
			audit_msg(LOG_ERR,
				"Out of memory copying PSK identity");
			SSL_SESSION_free(s);
			set_psk_failure_reason(ssl, "oom-identity");
			return 0;
		}
		if (SSL_set_ex_data(ssl, ssl_ex_idx_identity, id_copy))
			free(old);
		else {
			free(id_copy);
			audit_msg(LOG_ERR,
				"Unable to store PSK identity");
			SSL_SESSION_free(s);
			set_psk_failure_reason(ssl, "exdata-identity");
			return 0;
		}
	}

	set_psk_failure_reason(ssl, NULL);
	*sess = s;
	return 1;
}

/*
 * clear_tls_server_context - release listener TLS state
 *
 * Releases context-owned and secret state after a setup failure or after all
 * clients have stopped during listener shutdown.
 * Returns: None.
 */
static void clear_tls_server_context(void)
{
	if (tls_server_ctx) {
		SSL_CTX_free(tls_server_ctx);
		tls_server_ctx = NULL;
	}
	if (server_psk_key) {
		OPENSSL_cleanse(server_psk_key, server_psk_key_len);
		OPENSSL_free(server_psk_key);
		server_psk_key = NULL;
		server_psk_key_len = 0;
	}
	free(expected_psk_identity);
	expected_psk_identity = NULL;
	autls_acl_free(acl_table);
	acl_table = NULL;
}

/*
 * init_tls_server_context - create and configure the server SSL_CTX
 * @config: daemon configuration with TLS settings
 *
 * Sets up TLS 1.3 with the configured cipher suites, key exchange
 * groups, and PSK authentication for the
 * collector listener.
 * Returns 0 on success, -1 on error.
 */
static int init_tls_server_context(struct daemon_conf *config)
{
	const char *cipher_suites, *key_exchange;

	tls_server_ctx = SSL_CTX_new(TLS_server_method());
	if (tls_server_ctx == NULL) {
		audit_msg(LOG_ERR, "Unable to create TLS server context");
		return -1;
	}

	if (!SSL_CTX_set_min_proto_version(tls_server_ctx, TLS1_3_VERSION)) {
		audit_msg(LOG_ERR, "Unable to set TLS 1.3 minimum version");
		goto err;
	}
	if (!SSL_CTX_set_max_early_data(tls_server_ctx, 0)) {
		audit_msg(LOG_ERR, "Unable to disable TLS early data");
		goto err;
	}
	if (!SSL_CTX_set_num_tickets(tls_server_ctx, 0)) {
		audit_msg(LOG_ERR, "Unable to disable TLS session tickets");
		goto err;
	}
	SSL_CTX_set_options(tls_server_ctx, SSL_OP_NO_COMPRESSION);
	SSL_CTX_set_mode(tls_server_ctx,
			 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_session_cache_mode(tls_server_ctx, SSL_SESS_CACHE_OFF);

	cipher_suites = config->tls_cipher_suites ?
		config->tls_cipher_suites :
		autls_profile_ciphers(config->tls_crypto_profile);
	if (cipher_suites) {
		if (!SSL_CTX_set_ciphersuites(tls_server_ctx,
					      cipher_suites)) {
			audit_msg(LOG_ERR,
				"Unable to set TLS cipher suites");
			goto err;
		}
	}

	if (config->tls_crypto_profile == TLS_PROFILE_PQC &&
	    config->tls_key_exchange)
		audit_msg(LOG_WARNING,
			"tls_key_exchange override set with PQC "
			"profile; connections will fail if override "
			"excludes PQC groups");

	key_exchange = config->tls_key_exchange ?
		config->tls_key_exchange :
		autls_profile_groups(config->tls_crypto_profile);
	if (key_exchange) {
		if (!SSL_CTX_set1_groups_list(tls_server_ctx,
					      key_exchange)) {
			ERR_print_errors_cb(tls_error_cb, NULL);
			if (config->tls_crypto_profile !=
			    TLS_PROFILE_COMPATIBLE ||
			    config->tls_key_exchange) {
				audit_msg(LOG_ERR,
					"Unable to set key exchange "
					"groups '%s'", key_exchange);
				goto err;
			}
			audit_msg(LOG_WARNING,
				"PQC key exchange groups not "
				"available, falling back to X25519");
			if (!SSL_CTX_set1_groups_list(tls_server_ctx,
						      "X25519")) {
				audit_msg(LOG_ERR,
					"Unable to set any key "
					"exchange groups");
				goto err;
			}
		}
	}

	/* PSK mode */
	if (config->tls_psk_file) {
		if (autls_load_psk(config->tls_psk_file,
				&server_psk_key, &server_psk_key_len,
				audit_msg) != 0)
			goto err;
		SSL_CTX_set_psk_find_session_callback(tls_server_ctx,
						tls_psk_find_session_cb);
		free(expected_psk_identity);
		expected_psk_identity = NULL;
		if (config->tls_psk_identity) {
			if (autls_validate_psk_identity(
					(const unsigned char *)
					config->tls_psk_identity,
					strlen(config->tls_psk_identity),
					audit_msg) != 0)
				goto err;
			expected_psk_identity =
				strdup(config->tls_psk_identity);
			if (!expected_psk_identity) {
				audit_msg(LOG_ERR,
					"Out of memory for PSK identity");
				goto err;
			}
		}

		/* Load client ACL if configured */
		if (config->tls_allowed_clients) {
			if (acl_table) {
				autls_acl_free(acl_table);
				acl_table = NULL;
			}
			if (autls_acl_load(config->tls_allowed_clients,
					   &acl_table, audit_msg) != 0)
				goto err;
			if (acl_table->enabled_count > 1) {
				audit_msg(LOG_ERR,
					"tls_allowed_clients has %d "
					"enabled identities but "
					"single-PSK mode allows at "
					"most 1",
					acl_table->enabled_count);
				goto err;
			}
			if (expected_psk_identity)
				audit_msg(LOG_NOTICE,
					"tls_allowed_clients is "
					"configured; tls_psk_identity "
					"is ignored for authorization");
		}

		/* Register ex-data indices (once) */
		if (ssl_ex_idx_identity < 0) {
			ssl_ex_idx_identity =
				SSL_get_ex_new_index(0, NULL,
						     NULL, NULL, NULL);
			ssl_ex_idx_reason =
				SSL_get_ex_new_index(0, NULL,
						     NULL, NULL, NULL);
			if (ssl_ex_idx_identity < 0 ||
			    ssl_ex_idx_reason < 0) {
				audit_msg(LOG_ERR,
					"Unable to allocate SSL "
					"ex-data indices");
				goto err;
			}
		}
	}

	return 0;
err:
	ERR_print_errors_cb(tls_error_cb, NULL);
	clear_tls_server_context();
	return -1;
}
#endif /* HAVE_TLS */

int auditd_tcp_listen_init(struct ev_loop *loop, struct daemon_conf *config)
{
	struct addrinfo *ai, *runp;
	struct addrinfo hints;
	char local[16];
	int one = 1, rc;
	int prefer_ipv6 = 0;

	/* If the port is not set, that means we aren't going to
	   listen for connections.  */
	if (config->tcp_listen_port == 0)
		return 0;

#ifdef HAVE_TLS
	/* Do not expose a listener until its configured TLS context is usable. */
	if (config->transport == T_TLS && init_tls_server_context(config)) {
		audit_msg(LOG_ERR, "Failed to initialize TLS server context");
		return -1;
	}
#endif

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	snprintf(local, sizeof(local), "%u", (unsigned)config->tcp_listen_port);

	rc = getaddrinfo(NULL, local, &hints, &ai);
	if (rc) {
		audit_msg(LOG_ERR, "Cannot lookup addresses");
#ifdef HAVE_TLS
		if (config->transport == T_TLS)
			clear_tls_server_context();
#endif
		return 1;
	}

	{
	int ipv4 = 0, ipv6 = 0;
	nlsocks = 0;
	runp = ai;
	while (runp && nlsocks < N_SOCKS) {
		// Let's take a pass through and see what we got.
		if (runp->ai_family == AF_INET)
			ipv4++;
		else if (runp->ai_family == AF_INET6)
			ipv6++;
		runp = runp->ai_next;
		nlsocks++;
	}

	if (nlsocks == 2 && ipv4 && ipv6)
		prefer_ipv6 = 1;
	}

	nlsocks = 0;
	runp = ai;
	while (runp && nlsocks < N_SOCKS) {
		// On linux, ipv6 sockets by default include ipv4 so
		// we only need one.
		if (runp->ai_family == AF_INET && prefer_ipv6)
			goto next_try;

		listen_socket[nlsocks] = socket(runp->ai_family,
				 runp->ai_socktype, runp->ai_protocol);
		if (listen_socket[nlsocks] < 0) {
			audit_msg(LOG_ERR, "Cannot create %s listener socket",
				runp->ai_family == AF_INET ? "IPv4" : "IPv6");
			goto next_try;
		}

		/* This avoids problems if auditd needs to be restarted.  */
		setsockopt(listen_socket[nlsocks], SOL_SOCKET, SO_REUSEADDR,
				(char *)&one, sizeof (int));

		// If we had more than 2 addresses suggested we'll
		// separate the sockets.
		if (!prefer_ipv6 && runp->ai_family == AF_INET6)
			setsockopt(listen_socket[nlsocks], IPPROTO_IPV6,
				IPV6_V6ONLY, &one, sizeof(int));

		set_close_on_exec(listen_socket[nlsocks]);

		if (bind(listen_socket[nlsocks], runp->ai_addr,
						runp->ai_addrlen)) {
			if (errno != EADDRINUSE)
				audit_msg(LOG_ERR,
				"Cannot bind listener socket to port %ld (%s)",
				config->tcp_listen_port, strerror(errno));
			close(listen_socket[nlsocks]);
			listen_socket[nlsocks] = -1;
			goto non_fatal;
		}

		if (listen(listen_socket[nlsocks], config->tcp_listen_queue)) {
			audit_msg(LOG_ERR, "Unable to listen on %ld (%s)",
				config->tcp_listen_port,
				strerror(errno));
			close(listen_socket[nlsocks]);
			listen_socket[nlsocks] = -1;
			goto next_try;
		}
		struct protoent *p = getprotobynumber(runp->ai_protocol);
		audit_msg(LOG_DEBUG, "Listening on TCP port %ld, protocol %s",
			config->tcp_listen_port,
			 p ? p->p_name: "?");
		endprotoent();

		ev_io_init(&tcp_listen_watcher, auditd_tcp_listen_handler,
				listen_socket[nlsocks], EV_READ);
		tcp_listen_watcher.data = config;
		ev_io_start(loop, &tcp_listen_watcher);
non_fatal:
		nlsocks++;
		if (nlsocks == N_SOCKS)
			break;
next_try:
		runp = runp->ai_next;
	}

	freeaddrinfo(ai);
	if (nlsocks == 0) {
#ifdef HAVE_TLS
		if (config->transport == T_TLS)
			clear_tls_server_context();
#endif
		return -1;
	}

	// Now that we have sockets, start the periodic timers
	transport = config->transport;
	ev_periodic_init(&periodic_watcher, periodic_handler,
			  0, config->tcp_client_max_idle, NULL);
	periodic_watcher.data = config;
	if (config->tcp_client_max_idle)
		ev_periodic_start(loop, &periodic_watcher);

	use_libwrap = config->use_libwrap;
	auditd_set_ports(config->tcp_client_min_port,
			config->tcp_client_max_port,
			config->tcp_max_per_addr);

#ifdef USE_GSSAPI
	if (USE_GSS) {
		const char *princ = config->krb5_principal;
		const char *key_file;
		struct stat st;

		if (!princ)
			princ = "auditd";
		/* This may fail, but we don't care.  */
		unsetenv ("KRB5_KTNAME");
		if (config->krb5_key_file)
			key_file = config->krb5_key_file;
		else
			key_file = "/etc/audit/audit.key";
		setenv ("KRB5_KTNAME", key_file, 1);

		if (stat(key_file, &st) == 0) {
			if ((st.st_mode & 07777) != 0400) {
				audit_msg (LOG_ERR,
			 "%s is not mode 0400 (it's %#o) - compromised key?",
					   key_file, st.st_mode & 07777);
				return -1;
			}
			if (st.st_uid != 0) {
				audit_msg(LOG_ERR,
			 "%s is not owned by root (it's %d) - compromised key?",
					   key_file, st.st_uid);
				return -1;
			}
		}

		if (server_acquire_creds(princ, &server_creds)) {
			free(my_service_name);
			my_service_name = NULL;
			return -1;
		}
	}
#endif

	return 0;
}

void auditd_tcp_listen_uninit(struct ev_loop *loop, struct daemon_conf *config)
{
#ifdef USE_GSSAPI
	OM_uint32 status;
#endif
	/* If the port isn't set, we didn't listen for connections. */
	if (config->tcp_listen_port == 0)
		return;


	ev_io_stop(loop, &tcp_listen_watcher);
	while (nlsocks > 0) {
		nlsocks--;
		close(listen_socket[nlsocks]);
	}

#ifdef HAVE_TLS
	while (handshake_chain)
		abort_handshake(loop, handshake_chain, "shutdown");
#endif

	while (client_chain) {
		unsigned char ack[AUDIT_RMW_HEADER_SIZE];

		AUDIT_RMW_PACK_HEADER (ack, 0, AUDIT_RMW_TYPE_ENDING, 0, 0);
		client_ack(client_chain, ack, "");
		ev_io_stop(loop, &client_chain->io);
		close_client(client_chain);
	}

#ifdef HAVE_TLS
	clear_tls_server_context();
#endif
#ifdef USE_GSSAPI
	if (USE_GSS) {
		gss_release_cred(&status, &server_creds);
		krb5_free_context(kcontext);
		kcontext = NULL;
		free(my_service_name);
		my_service_name = NULL;
	}
#endif

	if (config->tcp_client_max_idle)
		ev_periodic_stop(loop, &periodic_watcher);
	transport = T_TCP;
}

static void periodic_reconfigure(const struct daemon_conf *config)
{
	struct ev_loop *loop = ev_default_loop(EVFLAG_AUTO);
	if (config->tcp_listen_port && config->tcp_client_max_idle) {
		ev_periodic_set(&periodic_watcher, ev_now(loop),
				 config->tcp_client_max_idle, NULL);
		ev_periodic_start(loop, &periodic_watcher);
	} else {
		ev_periodic_stop(loop, &periodic_watcher);
	}
}

#ifdef HAVE_TLS
/*
 * reload_tls_client_acl - reload live TLS PSK client authorization
 * @nconf: newly parsed daemon configuration
 * @oconf: active daemon configuration
 *
 * Returns: None.
 *
 * SIGHUP must not partially publish authorization state.  Parse and
 * validate the new ACL into temporary storage first, then replace the
 * live path and table together only after all checks pass.  If the ACL
 * is the only active PSK authorization source, removing it would make
 * connection attempts fail closed and could create an avoidable denial
 * of service, so keep the old ACL until restart or a replacement ACL.
 */
static void reload_tls_client_acl(const struct daemon_conf *nconf,
				   struct daemon_conf *oconf)
{
	struct autls_acl_table *new_acl = NULL;
	int old_enabled;

	if (!USE_TLS) {
		free((void *)oconf->tls_allowed_clients);
		oconf->tls_allowed_clients = nconf->tls_allowed_clients;
		return;
	}

	if (nconf->tls_allowed_clients == NULL) {
		if (oconf->tls_allowed_clients == NULL)
			return;

		if (server_psk_key && expected_psk_identity == NULL) {
			audit_msg(LOG_ERR,
				"tls_allowed_clients removal ignored; "
				"live TLS PSK listener has no "
				"tls_psk_identity fallback");
			return;
		}

		free((void *)oconf->tls_allowed_clients);
		oconf->tls_allowed_clients = NULL;
		if (acl_table) {
			audit_msg(LOG_NOTICE,
				"tls_allowed_clients removed; "
				"clearing ACL");
			autls_acl_free(acl_table);
			acl_table = NULL;
		}
		return;
	}

	if (autls_acl_load(nconf->tls_allowed_clients, &new_acl,
			   audit_msg) != 0) {
		audit_msg(LOG_ERR,
			"Failed to reload TLS client ACL; "
			"keeping current ACL");
		free((void *)nconf->tls_allowed_clients);
		return;
	}

	if (server_psk_key && new_acl->enabled_count > 1) {
		audit_msg(LOG_ERR,
			"Reloaded ACL has %d enabled identities but "
			"single-PSK mode allows at most 1; "
			"keeping current ACL", new_acl->enabled_count);
		autls_acl_free(new_acl);
		free((void *)nconf->tls_allowed_clients);
		return;
	}

	old_enabled = acl_table ? acl_table->enabled_count : 0;
	autls_acl_free(acl_table);
	acl_table = new_acl;
	free((void *)oconf->tls_allowed_clients);
	oconf->tls_allowed_clients = nconf->tls_allowed_clients;
	audit_msg(LOG_NOTICE,
		"TLS client ACL reloaded (%d->%d enabled)",
		old_enabled, new_acl->enabled_count);
}
#endif

void auditd_tcp_listen_reconfigure(const struct daemon_conf *nconf,
				    struct daemon_conf *oconf)
{
	struct ev_loop *loop = ev_default_loop(EVFLAG_AUTO);
	use_libwrap = nconf->use_libwrap;
	
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
			oconf->tcp_listen_queue != nconf->tcp_listen_queue ||
			oconf->transport != nconf->transport) {
		int port_chg = oconf->tcp_listen_port !=
						nconf->tcp_listen_port;
		int queue_chg = oconf->tcp_listen_queue !=
						nconf->tcp_listen_queue;
		int trans_chg = oconf->transport != nconf->transport;
		if (port_chg && oconf->tcp_listen_port == 0 &&
				    nconf->tcp_listen_port != 0) {
#ifdef HAVE_TLS
			if (nconf->transport == T_TLS) {
				audit_msg(LOG_NOTICE,
					"Starting TLS listener requires "
					"restart; port change ignored");
				oconf->tcp_listen_port = nconf->tcp_listen_port;
				oconf->tcp_listen_queue = nconf->tcp_listen_queue;
				oconf->transport = nconf->transport;
			} else
#endif
			{
			audit_msg(LOG_NOTICE,
					"starting TCP listener on %lu",
					nconf->tcp_listen_port);
			oconf->tcp_listen_port = nconf->tcp_listen_port;
			oconf->tcp_listen_queue = nconf->tcp_listen_queue;
			oconf->transport = nconf->transport;
			if (auditd_tcp_listen_init(loop, oconf))
				audit_msg(LOG_ERR, "failed to start listener");
			}
		} else if (port_chg) {
			if (nconf->tcp_listen_port == 0)
				audit_msg(LOG_NOTICE,
				    "TCP listener disabled; restart required");
			else
				audit_msg(LOG_NOTICE,
				    "tcp_listen_port change requires restart");
			oconf->tcp_listen_port = nconf->tcp_listen_port;
			oconf->tcp_listen_queue = nconf->tcp_listen_queue;
		} else if (trans_chg) {
			audit_msg(LOG_NOTICE,
					 "transport change requires restart");
		} else if (queue_chg) {
			audit_msg(LOG_NOTICE,
			    "tcp_listen_queue changed - restarting listener");
			auditd_tcp_listen_uninit(loop, oconf);
			oconf->tcp_listen_queue = nconf->tcp_listen_queue;
			if (auditd_tcp_listen_init(loop, oconf))
				audit_msg(LOG_ERR,"failed to restart listener");
		}
	}

	/* Copy configured Kerberos paths for a future listener start. Live
	 * credentials are not reloaded here. */
	free((void *)oconf->krb5_principal);
	oconf->krb5_principal = nconf->krb5_principal;
	free((void *)oconf->krb5_key_file);
	oconf->krb5_key_file = nconf->krb5_key_file;

#ifdef HAVE_TLS
	/* TLS context settings are not live reloaded. Keeping old policy fields
	 * while accepting new paths would let a later queue restart build a
	 * mixed TLS context. The ACL table below is the one live exception. */
	if (oconf->transport == T_TLS || nconf->transport == T_TLS)
		audit_msg(LOG_NOTICE,
			"TLS context not reloaded; restart auditd "
			"to apply TLS/PSK config changes");
	reload_tls_client_acl(nconf, oconf);
	free((void *)nconf->tls_psk_file);
	free((void *)nconf->tls_psk_identity);
	free((void *)nconf->tls_cipher_suites);
	free((void *)nconf->tls_key_exchange);
#endif
}
