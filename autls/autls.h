/* autls.h -- internal TLS helper library for audit
 * Copyright 2026 Red Hat Inc.
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
 *      Sergio Correia <scorreia@redhat.com>
 */

#ifndef AUTLS_H
#define AUTLS_H

#include <openssl/ssl.h>
#include "gcc-attributes.h"

typedef void (*autls_log_fn)(int, const char *, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 2, 3)))
#endif
	;

#define AUTLS_WRITE_TIMEOUT_MS		100
#define AUTLS_SHUTDOWN_TIMEOUT_MS	1000

/* PSK identity limits */
#define AUTLS_PSK_IDENTITY_MAX		255

/*
 * Crypto profile values -- must match tls_crypto_profile_t
 * in auditd-config.h and remote-config.h
 */
#define AUTLS_PROFILE_COMPATIBLE	0
#define AUTLS_PROFILE_SYSTEM		1
#define AUTLS_PROFILE_PQC		2

struct autls_audit_session {
	const char *direction;
	const char *cipher;
	int ksize;
	const char *pfs;
	long long spid;
	const char *suid;
	unsigned int rport;
	const char *laddr;
	unsigned int lport;
};

/* autls-profile.c */
int autls_is_pqc_group(const char *name)
	__attribute_pure__ __wur;
const SSL_CIPHER *autls_find_tls13_cipher(SSL *ssl, const EVP_MD *md)
	__nonnull((1)) __wur;
const char *autls_profile_ciphers(int profile)
	__attribute_pure__ __wur;
const char *autls_profile_groups(int profile)
	__attribute_pure__ __wur;
int autls_format_crypto_session(char *buf, size_t buflen,
				const struct autls_audit_session *session)
	__nonnull((1, 3)) __wur;
int autls_format_crypto_key_destroy(char *buf, size_t buflen,
				    const struct autls_audit_session *session)
	__nonnull((1, 3)) __wur;

/* autls-psk.c */
int autls_validate_key_file(const char *path, autls_log_fn log_fn)
	__nonnull((1, 2)) __wur;
int autls_load_key_file(const char *path, SSL_CTX *ctx,
			autls_log_fn log_fn)
	__nonnull((1, 2, 3)) __wur;
int autls_load_psk(const char *path, unsigned char **key, size_t *key_len,
		   autls_log_fn log_fn)
	__nonnull((1, 2, 3, 4)) __wur;
int autls_validate_psk_identity(const unsigned char *id, size_t len,
				autls_log_fn log_fn)
	__nonnull((1, 3)) __wur;

/* autls-acl.c */
struct autls_acl_entry {
	char *identity;
	size_t identity_len;
	int enabled;
	struct autls_acl_entry *next;
};

struct autls_acl_table {
	struct autls_acl_entry *entries;
	int count;
	int enabled_count;
};

int autls_acl_load(const char *path, struct autls_acl_table **table,
		   autls_log_fn log_fn)
	__nonnull((1, 2, 3)) __wur;
int autls_acl_check(const struct autls_acl_table *table,
		    const unsigned char *identity, size_t len)
	__nonnull((1, 2)) __wur;
void autls_acl_free(struct autls_acl_table *table);

/* autls-io.c */
int autls_remaining_ms(const struct timespec *deadline)
	__nonnull((1)) __wur;
int autls_ssl_connect(SSL *ssl, int timeout_ms)
	__nonnull((1)) __wur;
int autls_ssl_write(SSL *ssl, const void *buf, int len, int timeout_ms)
	__nonnull((1, 2)) __attr_access((__read_only__, 2, 3)) __wur;
void autls_ssl_shutdown(SSL *ssl)
	__nonnull((1));

#endif /* AUTLS_H */
