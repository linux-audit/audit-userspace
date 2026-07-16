/* autls-psk.c -- PSK file loading and key file validation
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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "autls.h"

/*
 * autls_validate_psk_identity - validate a PSK identity string
 * @id: identity bytes to validate
 * @len: length of @id in bytes
 * @log_fn: logging callback for error reporting
 *
 * Checks that the identity is non-empty, within the maximum length,
 * and contains only printable ASCII characters (0x21-0x7E).
 * Returns 0 on success, -1 on validation failure.
 */
int autls_validate_psk_identity(const unsigned char *id, size_t len,
				autls_log_fn log_fn)
{
	size_t i;

	if (len == 0) {
		log_fn(LOG_ERR, "PSK identity is empty");
		return -1;
	}
	if (len > AUTLS_PSK_IDENTITY_MAX) {
		log_fn(LOG_ERR,
			"PSK identity too long (%zu bytes, max %d)",
			len, AUTLS_PSK_IDENTITY_MAX);
		return -1;
	}
	for (i = 0; i < len; i++) {
		if (id[i] < 0x21 || id[i] > 0x7E) {
			log_fn(LOG_ERR,
				"PSK identity contains invalid byte "
				"0x%02x at position %zu",
				id[i], i);
			return -1;
		}
	}
	return 0;
}

/*
 * autls_open_secret_file - safely open and validate a TLS secret file
 * @path: path to the secret file
 * @kind: human-readable file kind for log messages
 * @log_fn: logging callback for error reporting
 *
 * Opens @path with O_NONBLOCK before fstat() so attacker-replaced FIFOs
 * cannot block daemon initialization before the regular-file check.
 * Returns a validated regular-file descriptor on success, -1 on failure.
 */
static int autls_open_secret_file(const char *path, const char *kind,
				  autls_log_fn log_fn)
{
	struct stat st;
	int fd, flags;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	if (fd < 0) {
		log_fn(LOG_ERR, "Unable to open %s %s (%s)",
			kind, path, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) != 0) {
		log_fn(LOG_ERR, "Unable to stat %s %s (%s)",
			kind, path, strerror(errno));
		close(fd);
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		log_fn(LOG_ERR, "%s is not a regular file", path);
		close(fd);
		return -1;
	}
	if ((st.st_mode & 07777) != 0400) {
		log_fn(LOG_ERR,
			"%s is not mode 0400 (it's %#o) "
			"- compromised key?",
			path, st.st_mode & 07777);
		close(fd);
		return -1;
	}
	if (st.st_uid != 0) {
		log_fn(LOG_ERR,
			"%s is not owned by root (uid %u) "
			"- compromised key?",
			path, (unsigned)st.st_uid);
		close(fd);
		return -1;
	}

	flags = fcntl(fd, F_GETFL);
	if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
		log_fn(LOG_ERR,
			"Unable to restore blocking mode for %s %s (%s)",
			kind, path, strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * autls_load_psk - validate and read a hex-encoded pre-shared key
 * @path: path to the PSK file (single line of hex)
 * @key: output pointer to decoded key bytes (caller frees with OPENSSL_free)
 * @key_len: output key length in bytes
 * @log_fn: logging callback for error reporting
 *
 * Opens @path with O_NOFOLLOW to reject symlinks, then validates the
 * file descriptor with fstat() (regular file, mode 0400, root-owned)
 * before reading.  This eliminates the TOCTOU race between separate
 * validate-then-open sequences.
 * Decodes the first line as hex.  Requires at least 32 bytes.
 * Cleanses the read buffer on all paths.
 * Returns 0 on success, -1 on error.
 */
int autls_load_psk(const char *path, unsigned char **key, size_t *key_len,
		   autls_log_fn log_fn)
{
	int fd = -1;
	FILE *f = NULL;
	char line[512];
	size_t len;
	long tmp_len = 0;
	unsigned char *decoded = NULL;
	int rc = -1;

	fd = autls_open_secret_file(path, "PSK file", log_fn);
	if (fd < 0)
		return -1;

	f = fdopen(fd, "r");
	if (f == NULL) {
		log_fn(LOG_ERR, "Unable to read PSK file %s (%s)",
			path, strerror(errno));
		close(fd);
		return -1;
	}
	// fd is now owned by f; do not close(fd) separately

	if (fgets(line, sizeof(line), f) == NULL) {
		if (ferror(f))
			log_fn(LOG_ERR,
				"I/O error reading PSK file %s", path);
		else
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
