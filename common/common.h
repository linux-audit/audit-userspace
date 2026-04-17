/* common.h -- common utility functions used throughout
 * Copyright 2018-25 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#ifndef AUDIT_COMMON_HEADER
#define AUDIT_COMMON_HEADER

#include "config.h"
#include <limits.h> /* POSIX_HOST_NAME_MAX */
#ifdef HAVE_ATOMIC
#include <stdatomic.h>
#endif
#include <sys/types.h>
#include "dso.h"
#include "gcc-attributes.h"

/* Wrapper macros for optional atomics
 * Note: ATOMIC_INT and ATOMIC_UNSIGNED are defined in config.h */
#ifdef HAVE_ATOMIC
#  define AUDIT_ATOMIC_STORE(var, val) \
   atomic_store_explicit(&(var), (val), memory_order_relaxed)
#  define AUDIT_ATOMIC_LOAD(var) \
   atomic_load_explicit(&(var), memory_order_relaxed)
#else
#  define AUDIT_ATOMIC_STORE(var, val) do { (var) = (val); } while (0)
#  define AUDIT_ATOMIC_LOAD(var) (var)
#endif

// Used in auditd-event.c and audisp.c to size buffers for formatting
#define FORMAT_BUF_LEN (MAX_AUDIT_MESSAGE_LENGTH + _POSIX_HOST_NAME_MAX)

#ifndef HAVE_STRNDUPA
#define strndupa(s, n)                                          \
	({                                                      \
		const char *__old = (s);			\
		size_t __len = strnlen (__old, (n));            \
		char *__new = (char *) alloca(__len + 1);       \
		__new[__len] = '\0';                            \
		(char *) memcpy (__new, __old, __len);          \
	})
#endif

AUDIT_HIDDEN_START

char *audit_strsplit_r(char *s, char **savedpp);
char *audit_strsplit(char *s);
int audit_is_last_record(int type) __attribute_const__;

extern const char *SINGLE;
extern const char *HALT;
void change_runlevel(const char *level);
const char *get_progname(void);

#define MINUTES 60
#define HOURS   60*MINUTES
#define DAYS    24*HOURS
#define WEEKS   7*DAYS
#define MONTHS  30*DAYS
long time_string_to_seconds(const char *time_string,
			    const char *subsystem, int line);

/* Messages */
int write_to_console(const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)));
#else
	;
#endif

void wall_message(const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)));
#else
	;
#endif

typedef enum { MSG_STDERR, MSG_SYSLOG, MSG_QUIET } message_t;
typedef enum { DBG_NO, DBG_YES } debug_message_t;
void _set_aumessage_mode(message_t mode, debug_message_t debug);

AUDIT_HIDDEN_END

#ifdef HAVE_TLS
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <openssl/crypto.h>

typedef void (*tls_log_fn)(int, const char *, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 2, 3)))
#endif
	;

/*
 * is_pqc_group - check whether a TLS group name is post-quantum
 * @name: group name string from OpenSSL, may be NULL
 *
 * Returns 1 if @name contains a recognized PQC KEM identifier, 0 otherwise.
 * NULL input returns 0.
 */
static inline int is_pqc_group(const char *name)
{
	/* PQC group allowlist -- add new PQC KEM identifiers here
	 * as they are standardized by NIST */
	static const char * const patterns[] = {
		"MLKEM",
		NULL
	};
	int i;
	if (name == NULL)
		return 0;
	for (i = 0; patterns[i] != NULL; i++) {
		if (strstr(name, patterns[i]) != NULL)
			return 1;
	}
	return 0;
}

/*
 * tls_validate_key_file - verify a TLS key file has safe permissions
 * @path: path to the key file
 * @log_fn: logging callback for error reporting
 *
 * Checks that @path is a regular file, mode 0400, owned by root.
 * Returns 0 on success, -1 on any validation failure.
 */
static inline int tls_validate_key_file(const char *path,
		tls_log_fn log_fn)
{
	struct stat st;

	if (stat(path, &st) != 0) {
		log_fn(LOG_ERR,
			"Unable to stat TLS key file %s (%s)",
			path, strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		log_fn(LOG_ERR, "%s is not a regular file", path);
		return -1;
	}
	if ((st.st_mode & 07777) != 0400) {
		log_fn(LOG_ERR,
			"%s is not mode 0400 (it's %#o) "
			"- compromised key?",
			path, st.st_mode & 07777);
		return -1;
	}
	if (st.st_uid != 0) {
		log_fn(LOG_ERR,
			"%s is not owned by root (uid %u) "
			"- compromised key?",
			path, (unsigned)st.st_uid);
		return -1;
	}
	return 0;
}

/*
 * tls_load_psk - read a hex-encoded pre-shared key from a file
 * @path: path to the PSK file (single line of hex)
 * @key: output pointer to decoded key bytes (caller frees with OPENSSL_free)
 * @key_len: output key length in bytes
 * @log_fn: logging callback for error reporting
 *
 * Decodes the first line of @path as hex. Requires at least 32 bytes.
 * Cleanses the read buffer on all paths.
 * Returns 0 on success, -1 on error.
 */
static inline int tls_load_psk(const char *path,
		unsigned char **key, size_t *key_len,
		tls_log_fn log_fn)
{
	FILE *f;
	char line[512];
	size_t len;
	long tmp_len = 0;
	unsigned char *decoded = NULL;
	int rc = -1;

	f = fopen(path, "r");
	if (f == NULL) {
		log_fn(LOG_ERR, "Unable to open PSK file %s (%s)",
			path, strerror(errno));
		return -1;
	}

	if (fgets(line, sizeof(line), f) == NULL) {
		log_fn(LOG_ERR, "PSK file %s is empty", path);
		fclose(f);
		goto cleanup;
	}
	fclose(f);

	len = strlen(line);
	if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
		log_fn(LOG_ERR,
			"PSK file %s: key line too long (max %zu hex chars)",
			path, sizeof(line) - 2);
		goto cleanup;
	}
	while (len > 0 && (line[len-1] == '\n' ||
			    line[len-1] == '\r'))
		line[--len] = '\0';

	if (len == 0 || len % 2 != 0) {
		log_fn(LOG_ERR,
			"PSK file %s has invalid key format", path);
		goto cleanup;
	}

	decoded = OPENSSL_hexstr2buf(line, &tmp_len);
	if (decoded == NULL || tmp_len < 32) {
		log_fn(LOG_ERR,
			"PSK file %s: invalid hex or key too short "
			"(need >= 32 bytes)", path);
		if (decoded) {
			OPENSSL_cleanse(decoded, tmp_len);
			OPENSSL_free(decoded);
		}
		goto cleanup;
	}

	*key = decoded;
	*key_len = (size_t)tmp_len;
	rc = 0;

cleanup:
	OPENSSL_cleanse(line, sizeof(line));
	return rc;
}

#include <poll.h>
#include <time.h>
#include <openssl/ssl.h>

#define TLS_WRITE_TIMEOUT_MS	100
#define TLS_SHUTDOWN_TIMEOUT_MS	1000

/*
 * tls_remaining_ms - compute milliseconds remaining until a deadline
 * @deadline: absolute monotonic clock deadline
 *
 * Returns the number of milliseconds from now until @deadline, clamped
 * to INT_MAX. Returns 0 if the deadline has already passed.
 */
static inline int tls_remaining_ms(const struct timespec *deadline)
{
	struct timespec now;
	long long ms;
	clock_gettime(CLOCK_MONOTONIC, &now);
	ms = (long long)(deadline->tv_sec - now.tv_sec) * 1000 +
	     (deadline->tv_nsec - now.tv_nsec) / 1000000;
	if (ms > INT_MAX)
		return INT_MAX;
	return ms > 0 ? (int)ms : 0;
}

/*
 * tls_find_tls13_cipher - select the first configured TLS 1.3 cipher
 * @ssl: active SSL connection
 *
 * Returns the first TLS 1.3 cipher from the connection's configured
 * ciphersuite list, respecting the operator's preference order.
 * Returns NULL if no TLS 1.3 cipher is configured.
 */
static inline const SSL_CIPHER *tls_find_tls13_cipher(SSL *ssl)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	int i;

	ciphers = SSL_get_ciphers(ssl);
	if (ciphers == NULL)
		return NULL;

	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, i);
		if (SSL_CIPHER_get_protocol_id(c) >= 0x1301 &&
		    SSL_CIPHER_get_protocol_id(c) <= 0x1305)
			return c;
	}
	return NULL;
}

/*
 * tls_ssl_write - full-or-fail TLS write with cumulative deadline
 * @ssl: active SSL connection
 * @buf: data to write
 * @len: number of bytes to write
 * @timeout_ms: maximum total time in milliseconds
 *
 * Writes exactly @len bytes or fails. Handles SSL_ERROR_WANT_READ
 * and SSL_ERROR_WANT_WRITE with poll().
 * Returns total bytes written on success, -1 on error or timeout.
 */
static inline int tls_ssl_write(SSL *ssl, const void *buf, int len,
		int timeout_ms)
{
	int rc = 0, w, remaining;
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
		w = SSL_write(ssl, buf, len);
		if (w <= 0) {
			int err = SSL_get_error(ssl, w);
			if (err == SSL_ERROR_WANT_WRITE)
				pfd.events = POLLOUT;
			else if (err == SSL_ERROR_WANT_READ)
				pfd.events = POLLIN;
			else
				return -1;
			remaining = tls_remaining_ms(&deadline);
			if (remaining <= 0)
				return -1;
			if (poll(&pfd, 1, remaining) <= 0)
				return -1;
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
				return -1;
			continue;
		}
		rc += w;
		buf = (const char *)buf + w;
		len -= w;
	}
	return rc;
}

/*
 * tls_ssl_shutdown - best-effort bidirectional TLS shutdown
 * @ssl: active SSL connection
 *
 * Sends close_notify and waits up to TLS_SHUTDOWN_TIMEOUT_MS for
 * the peer's close_notify response.
 */
static inline void tls_ssl_shutdown(SSL *ssl)
{
	int ret;
	struct pollfd pfd;

	pfd.fd = SSL_get_fd(ssl);
	if (pfd.fd < 0)
		return;

	ret = SSL_shutdown(ssl);
	if (ret == 0) {
		/* Sent close_notify; try to receive peer's */
		pfd.events = POLLIN;
		if (poll(&pfd, 1, TLS_SHUTDOWN_TIMEOUT_MS) > 0 &&
		    !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
			SSL_shutdown(ssl);
	}
}
#endif

#endif

