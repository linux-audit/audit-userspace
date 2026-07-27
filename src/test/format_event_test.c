/* format_event_test.c -- audit event formatting tests
 * Copyright 2025-26 Red Hat Inc.
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
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 */

#include "config.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "auditd-event.h"
#include "auditd-config.h"
#include "common.h"
#ifdef AUDITD_LISTEN_TEST
#include "auditd-listen.h"
#include "ev.h"
#ifdef HAVE_TLS
#include "autls.h"

void auditd_tls_test_set_transport(int value);
int auditd_tls_test_listener_count(void);
int auditd_tls_test_client_authenticated(const char *identity);
void auditd_tls_test_set_acl_table(struct autls_acl_table *table);
int auditd_tls_test_acl_check(const char *identity);
int auditd_tls_test_set_psk_state(int active, const char *identity);
void auditd_tls_test_clear(void);
#endif
#ifdef USE_GSSAPI
void auditd_gss_test_start_listener(struct ev_loop *loop, int fd,
				    unsigned int per_address);
void auditd_gss_test_stop_listener(struct ev_loop *loop);
unsigned int auditd_gss_test_pending_count(void);
unsigned int auditd_gss_test_pending_limit(void);
int auditd_gss_test_pending_fd(void);
void auditd_gss_test_set_timeout(ev_tstamp timeout);
int auditd_gss_test_queue_output(struct ev_loop *loop, size_t length);
void auditd_gss_test_feed_write(struct ev_loop *loop);
size_t auditd_gss_test_output_offset(void);
int auditd_gss_test_is_reading(void);
int auditd_gss_test_name_authorized(const char *name, const char *service,
				     const char *realm);
#endif
#endif

#ifdef HAVE_ATOMIC
ATOMIC_INT stop = 0;
#else
volatile ATOMIC_INT stop = 0;
#endif

void update_report_timer(unsigned int interval){}

#if defined(AUDITD_LISTEN_TEST) && defined(HAVE_TLS)
/*
 * make_test_acl - create a single-entry ACL table for listener tests
 * @identity: identity to mark enabled
 *
 * Returns: ACL table on success, NULL on allocation failure.
 */
static struct autls_acl_table *make_test_acl(const char *identity)
{
	struct autls_acl_table *table;
	struct autls_acl_entry *entry;

	table = calloc(1, sizeof(*table));
	entry = calloc(1, sizeof(*entry));
	if (table == NULL || entry == NULL) {
		free(table);
		free(entry);
		return NULL;
	}

	entry->identity = strdup(identity);
	if (entry->identity == NULL) {
		free(entry);
		free(table);
		return NULL;
	}
	entry->identity_len = strlen(identity);
	entry->enabled = 1;
	table->entries = entry;
	table->count = 1;
	table->enabled_count = 1;
	return table;
}

/*
 * test_tls_requires_accepted_psk_identity - reject non-PSK handshakes
 *
 * A successful TLS handshake may enter the active client chain only when the
 * PSK callback recorded an accepted identity.
 * Returns: None.
 */
static void test_tls_requires_accepted_psk_identity(void)
{
	assert(auditd_tls_test_client_authenticated(NULL) == 0);
	assert(auditd_tls_test_client_authenticated("audit-test") == 1);
}

/*
 * test_tls_acl_reload_preserves_old_state - reject invalid ACL reloads
 *
 * Returns: None.
 */
static void test_tls_acl_reload_preserves_old_state(void)
{
	struct daemon_conf old_conf, new_conf;
	struct autls_acl_table *table;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("/test/psk");
	old_conf.tls_allowed_clients = strdup("old-acl");
	new_conf.tls_allowed_clients = strdup("/proc/self/fd/-1");
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_allowed_clients != NULL);
	assert(new_conf.tls_allowed_clients != NULL);

	auditd_tls_test_set_transport(T_TLS);
	assert(auditd_tls_test_set_psk_state(1, NULL) == 0);
	table = make_test_acl("old-host");
	assert(table != NULL);
	auditd_tls_test_set_acl_table(table);

	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.tls_allowed_clients != NULL);
	assert(strcmp(old_conf.tls_allowed_clients, "old-acl") == 0);
	assert(auditd_tls_test_acl_check("old-host") == 1);

	free((void *)old_conf.tls_allowed_clients);
	auditd_tls_test_clear();
}

/*
 * test_tls_acl_reload_rejects_acl_only_removal - keep sole PSK auth source
 *
 * Returns: None.
 */
static void test_tls_acl_reload_rejects_acl_only_removal(void)
{
	struct daemon_conf old_conf, new_conf;
	struct autls_acl_table *table;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("/test/psk");
	old_conf.tls_allowed_clients = strdup("old-acl");
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_allowed_clients != NULL);

	auditd_tls_test_set_transport(T_TLS);
	assert(auditd_tls_test_set_psk_state(1, NULL) == 0);
	table = make_test_acl("old-host");
	assert(table != NULL);
	auditd_tls_test_set_acl_table(table);

	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.tls_allowed_clients != NULL);
	assert(strcmp(old_conf.tls_allowed_clients, "old-acl") == 0);
	assert(auditd_tls_test_acl_check("old-host") == 1);

	free((void *)old_conf.tls_allowed_clients);
	auditd_tls_test_clear();
}

/*
 * test_tls_acl_reload_allows_removal_with_identity - clear redundant ACL
 *
 * Returns: None.
 */
static void test_tls_acl_reload_allows_removal_with_identity(void)
{
	struct daemon_conf old_conf, new_conf;
	struct autls_acl_table *table;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("/test/psk");
	old_conf.tls_allowed_clients = strdup("old-acl");
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_allowed_clients != NULL);

	auditd_tls_test_set_transport(T_TLS);
	assert(auditd_tls_test_set_psk_state(1, "fallback-host") == 0);
	table = make_test_acl("old-host");
	assert(table != NULL);
	auditd_tls_test_set_acl_table(table);

	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.tls_allowed_clients == NULL);
	assert(auditd_tls_test_acl_check("old-host") == -2);

	auditd_tls_test_clear();
}

/*
 * test_tls_reconfigure_keeps_context_snapshot - retain restart-only TLS data
 *
 * Returns: None.
 */
static void test_tls_reconfigure_keeps_context_snapshot(void)
{
	struct daemon_conf old_conf, new_conf;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("old-psk");
	old_conf.tls_psk_identity = strdup("old-identity");
	old_conf.tls_cipher_suites = strdup("old-ciphers");
	old_conf.tls_key_exchange = strdup("old-groups");
	old_conf.tls_require_pqc = 1;
	old_conf.tls_crypto_profile = TLS_PROFILE_PQC;
	new_conf.tls_psk_file = strdup("new-psk");
	new_conf.tls_psk_identity = strdup("new-identity");
	new_conf.tls_cipher_suites = strdup("new-ciphers");
	new_conf.tls_key_exchange = strdup("new-groups");
	new_conf.tls_require_pqc = 0;
	new_conf.tls_crypto_profile = TLS_PROFILE_COMPATIBLE;
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_psk_identity != NULL);
	assert(old_conf.tls_cipher_suites != NULL);
	assert(old_conf.tls_key_exchange != NULL);
	assert(new_conf.tls_psk_file != NULL);
	assert(new_conf.tls_psk_identity != NULL);
	assert(new_conf.tls_cipher_suites != NULL);
	assert(new_conf.tls_key_exchange != NULL);

	auditd_tls_test_set_transport(T_TLS);
	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(strcmp(old_conf.tls_psk_file, "old-psk") == 0);
	assert(strcmp(old_conf.tls_psk_identity, "old-identity") == 0);
	assert(strcmp(old_conf.tls_cipher_suites, "old-ciphers") == 0);
	assert(strcmp(old_conf.tls_key_exchange, "old-groups") == 0);
	assert(old_conf.tls_require_pqc == 1);
	assert(old_conf.tls_crypto_profile == TLS_PROFILE_PQC);
	free((void *)old_conf.tls_psk_file);
	free((void *)old_conf.tls_psk_identity);
	free((void *)old_conf.tls_cipher_suites);
	free((void *)old_conf.tls_key_exchange);
	auditd_tls_test_clear();
}

/*
 * test_tls_init_failure_does_not_start_listener - reject invalid TLS first
 *
 * Returns: None.
 */
static void test_tls_init_failure_does_not_start_listener(void)
{
	struct daemon_conf config;
	struct ev_loop *loop;

	memset(&config, 0, sizeof(config));
	config.tcp_listen_port = 65530;
	config.tcp_listen_queue = 1;
	config.transport = T_TLS;
	config.tls_cipher_suites = "not-a-TLS-cipher";
	loop = ev_default_loop(EVFLAG_AUTO);

	assert(auditd_tcp_listen_init(loop, &config) == -1);
	assert(auditd_tls_test_listener_count() == 0);
	auditd_tls_test_clear();
}
#endif

#ifdef AUDITD_LISTEN_TEST
/*
 * test_krb5_key_file_reconfigure - transfer the reloaded Kerberos key path
 *
 * Returns: None.
 */
static void test_krb5_key_file_reconfigure(void)
{
	struct daemon_conf old_conf, new_conf;
	const char *new_key_file;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.krb5_principal = strdup("old-principal");
	old_conf.krb5_key_file = strdup("old-key-file");
	new_conf.krb5_principal = strdup("new-principal");
	new_conf.krb5_key_file = strdup("new-key-file");
	assert(old_conf.krb5_principal != NULL);
	assert(old_conf.krb5_key_file != NULL);
	assert(new_conf.krb5_principal != NULL);
	assert(new_conf.krb5_key_file != NULL);

	new_key_file = new_conf.krb5_key_file;
	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.krb5_key_file == new_key_file);
	assert(strcmp(old_conf.krb5_key_file, "new-key-file") == 0);
	new_conf.krb5_principal = NULL;
	new_conf.krb5_key_file = NULL;
	free((void *)old_conf.krb5_principal);
	free((void *)old_conf.krb5_key_file);
}

#ifdef USE_GSSAPI
static int probe_count;

/*
 * make_gss_test_listener - create a loopback TCP listener
 * @port: receives the selected local port
 *
 * Returns: Listening descriptor.
 */
static int make_gss_test_listener(uint16_t *port)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd >= 0);
	assert(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
			  sizeof(one)) == 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	assert(listen(fd, 64) == 0);
	assert(getsockname(fd, (struct sockaddr *)&addr, &addr_len) == 0);
	*port = ntohs(addr.sin_port);
	return fd;
}

/*
 * connect_gss_test_peer - connect a peer and optionally send a fragment
 * @port: loopback listener port
 * @payload: optional bytes to send before accept
 * @length: payload length
 *
 * Returns: Connected peer descriptor.
 */
static int connect_gss_test_peer(uint16_t port, const void *payload,
				 size_t length)
{
	struct sockaddr_in addr;
	ssize_t written;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd >= 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);
	assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	if (length) {
		written = write(fd, payload, length);
		assert(written == (ssize_t)length);
	}
	return fd;
}

/*
 * run_gss_loop_once - run one event-loop iteration with a latency bound
 * @loop: test event loop
 *
 * Returns: None.
 */
static void run_gss_loop_once(struct ev_loop *loop)
{
	struct timespec start, finish;
	double elapsed;

	assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	alarm(2);
	ev_run(loop, EVRUN_ONCE);
	alarm(0);
	assert(clock_gettime(CLOCK_MONOTONIC, &finish) == 0);
	elapsed = finish.tv_sec - start.tv_sec;
	elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
	assert(elapsed < 0.5);
}

/*
 * gss_probe_handler - record dispatch of an unrelated ready watcher
 * @loop: test event loop
 * @io: synthetic watcher
 * @revents: libev event flags
 *
 * Returns: None.
 */
static void gss_probe_handler(struct ev_loop *loop, struct ev_io *io,
			      int revents)
{
	unsigned char byte;

	assert(read(io->fd, &byte, sizeof(byte)) == sizeof(byte));
	probe_count++;
}

/*
 * dispatch_gss_probe - verify another ready watcher runs promptly
 * @loop: test event loop containing a pending GSS client
 *
 * Returns: None.
 */
static void dispatch_gss_probe(struct ev_loop *loop)
{
	struct ev_io watcher;
	unsigned char byte = 1;
	int pair[2];

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
	probe_count = 0;
	ev_io_init(&watcher, gss_probe_handler, pair[0], EV_READ);
	ev_io_start(loop, &watcher);
	assert(write(pair[1], &byte, sizeof(byte)) == sizeof(byte));
	run_gss_loop_once(loop);
	assert(probe_count == 1);
	ev_io_stop(loop, &watcher);
	close(pair[0]);
	close(pair[1]);
}

/*
 * run_gss_stall_case - exercise one incomplete framing state
 * @payload: bytes available from the unauthenticated peer
 * @length: payload length
 * @probe_rounds: event-loop rounds used to consume the fragment
 *
 * Returns: None.
 */
static void run_gss_stall_case(const void *payload, size_t length,
			       unsigned int probe_rounds)
{
	struct ev_loop *loop;
	uint16_t port;
	unsigned int i;
	int listener, peer, flags;

	loop = ev_loop_new(EVFLAG_AUTO);
	assert(loop != NULL);
	listener = make_gss_test_listener(&port);
	auditd_gss_test_start_listener(loop, listener, 64);
	peer = connect_gss_test_peer(port, payload, length);

	/* This accept callback was the original blocking boundary. */
	run_gss_loop_once(loop);
	assert(auditd_gss_test_pending_count() == 1);
	flags = fcntl(auditd_gss_test_pending_fd(), F_GETFL);
	assert(flags >= 0 && (flags & O_NONBLOCK));

	for (i = 0; i < probe_rounds; i++)
		dispatch_gss_probe(loop);
	assert(auditd_gss_test_pending_count() == 1);

	auditd_gss_test_stop_listener(loop);
	close(peer);
	close(listener);
	ev_loop_destroy(loop);
}

/*
 * test_gss_stalls_do_not_block_event_loop - cover incomplete GSS frames
 *
 * Returns: None.
 */
static void test_gss_stalls_do_not_block_event_loop(void)
{
	const unsigned char partial_length[3] = { 0, 0, 0 };
	const unsigned char short_body[7] = { 0, 0, 0, 8, 'a', 'b', 'c' };
	const unsigned char zero_tokens[8] = { 0 };

	run_gss_stall_case(NULL, 0, 1);
	run_gss_stall_case(partial_length, 1, 1);
	run_gss_stall_case(partial_length, 2, 1);
	run_gss_stall_case(partial_length, 3, 1);
	run_gss_stall_case(short_body, sizeof(short_body), 2);
	run_gss_stall_case(zero_tokens, sizeof(zero_tokens), 2);
}

/*
 * run_gss_timeout_case - close one stalled receive state at its deadline
 * @payload: bytes available from the unauthenticated peer
 * @length: payload length
 * @read_rounds: event-loop rounds needed to consume the fragment
 *
 * Returns: None.
 */
static void run_gss_timeout_case(const void *payload, size_t length,
				 unsigned int read_rounds)
{
	struct ev_loop *loop;
	unsigned int i;
	uint16_t port;
	int listener, peer;

	loop = ev_loop_new(EVFLAG_AUTO);
	assert(loop != NULL);
	listener = make_gss_test_listener(&port);
	auditd_gss_test_start_listener(loop, listener, 64);
	auditd_gss_test_set_timeout(0.1);
	peer = connect_gss_test_peer(port, payload, length);
	run_gss_loop_once(loop);
	assert(auditd_gss_test_pending_count() == 1);
	for (i = 0; i < read_rounds; i++) {
		run_gss_loop_once(loop);
		assert(auditd_gss_test_pending_count() == 1);
	}
	run_gss_loop_once(loop);
	assert(auditd_gss_test_pending_count() == 0);

	auditd_gss_test_stop_listener(loop);
	close(peer);
	close(listener);
	ev_loop_destroy(loop);
}

/*
 * test_gss_handshake_timeout - close every stalled receive framing state
 *
 * Returns: None.
 */
static void test_gss_handshake_timeout(void)
{
	const unsigned char partial_length[3] = { 0, 0, 0 };
	const unsigned char short_body[7] = { 0, 0, 0, 8, 'a', 'b', 'c' };
	const unsigned char zero_tokens[8] = { 0 };

	run_gss_timeout_case(NULL, 0, 0);
	run_gss_timeout_case(partial_length, 1, 1);
	run_gss_timeout_case(partial_length, 2, 1);
	run_gss_timeout_case(partial_length, 3, 1);
	run_gss_timeout_case(short_body, sizeof(short_body), 2);
	run_gss_timeout_case(zero_tokens, sizeof(zero_tokens), 2);
}

/*
 * test_gss_disconnect_cleanup - release a pending peer after socket EOF
 *
 * Returns: None.
 */
static void test_gss_disconnect_cleanup(void)
{
	struct ev_loop *loop;
	uint16_t port;
	int listener, peer;

	loop = ev_loop_new(EVFLAG_AUTO);
	assert(loop != NULL);
	listener = make_gss_test_listener(&port);
	auditd_gss_test_start_listener(loop, listener, 64);
	peer = connect_gss_test_peer(port, NULL, 0);
	run_gss_loop_once(loop);
	assert(auditd_gss_test_pending_count() == 1);

	close(peer);
	run_gss_loop_once(loop);
	assert(auditd_gss_test_pending_count() == 0);

	auditd_gss_test_stop_listener(loop);
	close(listener);
	ev_loop_destroy(loop);
}

/*
 * test_gss_pending_limits - enforce per-address and global pending limits
 *
 * Returns: None.
 */
static void test_gss_pending_limits(void)
{
	struct ev_loop *loop;
	unsigned int i, limit;
	uint16_t port;
	int listener, first, second;
	int peers[64];

	loop = ev_loop_new(EVFLAG_AUTO);
	assert(loop != NULL);
	listener = make_gss_test_listener(&port);
	auditd_gss_test_start_listener(loop, listener, 1);
	first = connect_gss_test_peer(port, NULL, 0);
	run_gss_loop_once(loop);
	second = connect_gss_test_peer(port, NULL, 0);
	run_gss_loop_once(loop);
	assert(auditd_gss_test_pending_count() == 1);
	auditd_gss_test_stop_listener(loop);
	close(first);
	close(second);
	close(listener);
	ev_loop_destroy(loop);

	loop = ev_loop_new(EVFLAG_AUTO);
	assert(loop != NULL);
	listener = make_gss_test_listener(&port);
	limit = auditd_gss_test_pending_limit();
	assert(limit + 1 < sizeof(peers) / sizeof(peers[0]));
	auditd_gss_test_start_listener(loop, listener, limit + 1);
	for (i = 0; i <= limit; i++) {
		peers[i] = connect_gss_test_peer(port, NULL, 0);
		run_gss_loop_once(loop);
	}
	assert(auditd_gss_test_pending_count() == limit);
	auditd_gss_test_stop_listener(loop);
	for (i = 0; i <= limit; i++)
		close(peers[i]);
	close(listener);
	ev_loop_destroy(loop);
}

/*
 * fill_gss_test_send_buffer - force a pending server write to return EAGAIN
 * @server: nonblocking accepted socket
 *
 * Returns: None.
 */
static void fill_gss_test_send_buffer(int server)
{
	unsigned char fill[4096];
	ssize_t rc;
	int sndbuf = 1024;

	memset(fill, 'F', sizeof(fill));
	assert(setsockopt(server, SOL_SOCKET, SO_SNDBUF, &sndbuf,
			  sizeof(sndbuf)) == 0);
	do {
		rc = write(server, fill, sizeof(fill));
	} while (rc > 0);
	assert(rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

/*
 * test_gss_blocked_response_write - retain output state across EAGAIN
 *
 * Returns: None.
 */
static void test_gss_blocked_response_write(void)
{
	struct ev_loop *loop;
	unsigned char drain[4096];
	unsigned int i;
	uint16_t port;
	ssize_t rc;
	int listener, peer, server, flags;

	loop = ev_loop_new(EVFLAG_AUTO);
	assert(loop != NULL);
	listener = make_gss_test_listener(&port);
	auditd_gss_test_start_listener(loop, listener, 64);
	peer = connect_gss_test_peer(port, NULL, 0);
	run_gss_loop_once(loop);
	server = auditd_gss_test_pending_fd();
	assert(server >= 0);
	fill_gss_test_send_buffer(server);

	assert(auditd_gss_test_queue_output(loop, 64) == 0);
	auditd_gss_test_feed_write(loop);
	ev_run(loop, EVRUN_NOWAIT);
	assert(auditd_gss_test_output_offset() == 0);
	dispatch_gss_probe(loop);

	flags = fcntl(peer, F_GETFL);
	assert(flags >= 0);
	assert(fcntl(peer, F_SETFL, flags | O_NONBLOCK) == 0);
	do {
		rc = read(peer, drain, sizeof(drain));
	} while (rc > 0);
	assert(rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));

	run_gss_loop_once(loop);
	run_gss_loop_once(loop);
	assert(auditd_gss_test_is_reading());
	auditd_gss_test_stop_listener(loop);
	close(peer);
	close(listener);
	ev_loop_destroy(loop);

	loop = ev_loop_new(EVFLAG_AUTO);
	assert(loop != NULL);
	listener = make_gss_test_listener(&port);
	auditd_gss_test_start_listener(loop, listener, 64);
	auditd_gss_test_set_timeout(0.1);
	peer = connect_gss_test_peer(port, NULL, 0);
	run_gss_loop_once(loop);
	server = auditd_gss_test_pending_fd();
	assert(server >= 0);
	fill_gss_test_send_buffer(server);

	assert(auditd_gss_test_queue_output(loop, 64) == 0);
	auditd_gss_test_feed_write(loop);
	ev_run(loop, EVRUN_NOWAIT);
	assert(auditd_gss_test_output_offset() == 0);
	for (i = 0; i < 4 && auditd_gss_test_pending_count(); i++)
		run_gss_loop_once(loop);
	assert(auditd_gss_test_pending_count() == 0);

	auditd_gss_test_stop_listener(loop);
	close(peer);
	close(listener);
	ev_loop_destroy(loop);
}

/*
 * test_gss_principal_authorization - require service/host@realm
 *
 * Returns: None.
 */
static void test_gss_principal_authorization(void)
{
	assert(auditd_gss_test_name_authorized(
		"audit/collector.example@EXAMPLE.COM",
		"audit", "EXAMPLE.COM") == 1);
	assert(auditd_gss_test_name_authorized(
		"other/collector.example@EXAMPLE.COM",
		"audit", "EXAMPLE.COM") == 0);
	assert(auditd_gss_test_name_authorized(
		"audit/collector.example@OTHER.EXAMPLE",
		"audit", "EXAMPLE.COM") == 0);
	assert(auditd_gss_test_name_authorized(
		"audit@EXAMPLE.COM", "audit", "EXAMPLE.COM") == 0);
}
#endif
#endif

int main(int argc, char *argv[])
{
	unsigned len_raw, len_enriched;
	struct daemon_conf conf;

#if defined(AUDITD_LISTEN_TEST) && defined(USE_GSSAPI)
	if (argc == 2 && strcmp(argv[1], "--gss-only") == 0) {
		test_gss_stalls_do_not_block_event_loop();
		test_gss_handshake_timeout();
		test_gss_disconnect_cleanup();
		test_gss_pending_limits();
		test_gss_blocked_response_write();
		test_gss_principal_authorization();
		return 0;
	}
#endif
	memset(&conf, 0, sizeof(conf));
	conf.daemonize = D_FOREGROUND;
	conf.log_format = LF_RAW;
	conf.node_name_format = N_NONE;
	conf.node_name = "testnode";
	conf.end_of_event_timeout = 1;

	if (init_event(&conf)) {
		fprintf(stderr, "init_event failed\n");
		return 1;
	}

	// Don't change this without adjusting offset to AUDIT_INTERP_SEPARATOR
	const char *msg = "audit(1170021493.5:100): pid=2000 uid=2 auid=-1 gid=2 ses=-1 msg=\'op=test\'\n";
	struct auditd_event *e;

	e = create_event(NULL, NULL, NULL, 0);
	if (!e)
		return 1;
	e->reply.type = AUDIT_TRUSTED_APP;
	e->reply.message = strdup(msg);
	e->reply.len = strlen(msg);
	format_event(e);
	len_raw = strlen(e->reply.message);
	printf("RAW: %s\n", e->reply.message);
	cleanup_event(e);

	conf.log_format = LF_ENRICHED;
	e = create_event(NULL, NULL, NULL, 0);
	if (!e)
		return 1;
	e->reply.type = AUDIT_TRUSTED_APP;
	e->reply.message = strdup(msg);
	e->reply.len = strlen(msg);
	format_event(e);
	len_enriched = strlen(e->reply.message);
	printf("ENRICHED: %s\n", e->reply.message);

	//shutdown_events();
	if (len_enriched <= len_raw) {
		printf("enriched length should be larger that raw length\n"
		       "    raw length = %u, enriched length = %u\n", len_raw,
			len_enriched);
		return 1;
	}
	if (e->reply.message[95] != AUDIT_INTERP_SEPARATOR) {
		puts("missing AUDIT_INTERP_SEPARATOR");
		printf("char 95: 0x%X\n", e->reply.message[95]);
		return 1;
	}
	if (!strstr(&(e->reply.message[95]), "AUID")) {
		puts("missing AUID interpretation");
		return 1;
	}
	cleanup_event(e);
#ifdef AUDITD_LISTEN_TEST
#ifdef HAVE_TLS
	test_tls_requires_accepted_psk_identity();
	test_tls_acl_reload_preserves_old_state();
	test_tls_acl_reload_rejects_acl_only_removal();
	test_tls_acl_reload_allows_removal_with_identity();
	test_tls_reconfigure_keeps_context_snapshot();
	test_tls_init_failure_does_not_start_listener();
#endif
	test_krb5_key_file_reconfigure();
#ifdef USE_GSSAPI
	test_gss_stalls_do_not_block_event_loop();
	test_gss_handshake_timeout();
	test_gss_disconnect_cleanup();
	test_gss_pending_limits();
	test_gss_blocked_response_write();
	test_gss_principal_authorization();
#endif
#endif
	return 0;
}

// Needed only for linking
int send_audit_event(int type, const char *str)
{
	return 0;
}

// Needed only for linking
void distribute_event(struct auditd_event *e)
{
}
