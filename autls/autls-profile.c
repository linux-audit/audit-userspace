/* autls-profile.c -- TLS profile and cipher classification
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
 */

#include "config.h"
#include <string.h>
#include <openssl/ssl.h>
#include "autls.h"

/*
 * autls_is_pqc_group - check whether a TLS group name is post-quantum
 * @name: group name string from OpenSSL, may be NULL
 *
 * Returns 1 if @name contains a recognized PQC KEM identifier, 0 otherwise.
 * NULL input returns 0.
 */
int autls_is_pqc_group(const char *name)
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
 * autls_find_tls13_cipher - select a TLS 1.3 cipher matching a hash
 * @ssl: active SSL connection
 * @md: required hash algorithm, or NULL for SHA-256 default
 *
 * For TLS 1.3 external PSKs, the cipher determines the binder hash.
 * Both endpoints must use the same hash or the handshake fails.
 * RFC 8446 Section 4.2.11 specifies SHA-256 as the default for
 * externally established PSKs.
 *
 * When @md is non-NULL (client callback hint), returns a cipher
 * whose handshake digest matches @md. When @md is NULL, defaults
 * to SHA-256. Falls back to any TLS 1.3 cipher if no match.
 * Returns NULL if no TLS 1.3 cipher is configured.
 */
const SSL_CIPHER *autls_find_tls13_cipher(SSL *ssl, const EVP_MD *md)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	const SSL_CIPHER *fallback = NULL;
	const EVP_MD *target;
	int i;

	ciphers = SSL_get_ciphers(ssl);
	if (ciphers == NULL)
		return NULL;

	/* Default to SHA-256 per RFC 8446 for external PSKs */
	target = md ? md : EVP_sha256();

	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, i);
		const char *ver = SSL_CIPHER_get_version(c);
		if (!ver || strcmp(ver, "TLSv1.3") != 0)
			continue;
		if (fallback == NULL)
			fallback = c;
		if (EVP_MD_type(SSL_CIPHER_get_handshake_digest(c))
		    == EVP_MD_type(target))
			return c;
	}
	return fallback;
}
