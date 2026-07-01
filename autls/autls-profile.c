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
 * Default TLS 1.3 ciphersuite string for standard and PQC profiles.
 * SHA-256 ciphers are listed first because RFC 8446 s4.2.11 mandates
 * SHA-256 as the hash for external PSK binders; AES-256-GCM (SHA-384)
 * is unreachable in PSK mode unless a SHA-384 binder is selected.
 */
#define AUTLS_DEFAULT_CIPHERS \
	"TLS_AES_128_GCM_SHA256:" \
	"TLS_CHACHA20_POLY1305_SHA256:" \
	"TLS_AES_256_GCM_SHA384"

/* Default key exchange groups -- includes PQC hybrid with fallback */
#define AUTLS_STANDARD_GROUPS	"X25519MLKEM768:X25519"

/* PQC-only hybrid groups -- no classical fallback, no pure ML-KEM */
#define AUTLS_PQC_GROUPS \
	"X25519MLKEM768:" \
	"SecP256r1MLKEM768:" \
	"SecP384r1MLKEM1024"

/*
 * autls_profile_ciphers - return the ciphersuite string for a profile
 * @profile: one of AUTLS_PROFILE_STANDARD, AUTLS_PROFILE_FIPS,
 *           AUTLS_PROFILE_PQC
 *
 * STANDARD and PQC return the default TLS 1.3 ciphersuites.
 * FIPS returns NULL (defer to system crypto policy).
 */
const char *autls_profile_ciphers(int profile)
{
	switch (profile) {
	case AUTLS_PROFILE_STANDARD:
	case AUTLS_PROFILE_PQC:
		return AUTLS_DEFAULT_CIPHERS;
	case AUTLS_PROFILE_FIPS:
		return NULL;
	default:
		return AUTLS_DEFAULT_CIPHERS;
	}
}

/*
 * autls_profile_groups - return the key exchange groups for a profile
 * @profile: one of AUTLS_PROFILE_STANDARD, AUTLS_PROFILE_FIPS,
 *           AUTLS_PROFILE_PQC
 *
 * STANDARD returns hybrid-plus-classical groups with fallback.
 * PQC returns hybrid-only groups (no classical fallback).
 * FIPS returns NULL (defer to system crypto policy).
 */
const char *autls_profile_groups(int profile)
{
	switch (profile) {
	case AUTLS_PROFILE_STANDARD:
		return AUTLS_STANDARD_GROUPS;
	case AUTLS_PROFILE_PQC:
		return AUTLS_PQC_GROUPS;
	case AUTLS_PROFILE_FIPS:
		return NULL;
	default:
		return AUTLS_STANDARD_GROUPS;
	}
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
