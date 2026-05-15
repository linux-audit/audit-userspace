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

typedef void (*autls_log_fn)(int, const char *, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 2, 3)))
#endif
	;

#define AUTLS_WRITE_TIMEOUT_MS		100
#define AUTLS_SHUTDOWN_TIMEOUT_MS	1000

/* autls-profile.c */
int autls_is_pqc_group(const char *name);
const SSL_CIPHER *autls_find_tls13_cipher(SSL *ssl, const EVP_MD *md);

/* autls-psk.c */
int autls_validate_key_file(const char *path, autls_log_fn log_fn);
int autls_load_psk(const char *path, unsigned char **key, size_t *key_len,
		   autls_log_fn log_fn);

/* autls-io.c */
int autls_remaining_ms(const struct timespec *deadline);
int autls_ssl_write(SSL *ssl, const void *buf, int len, int timeout_ms);
void autls_ssl_shutdown(SSL *ssl);

#endif /* AUTLS_H */
