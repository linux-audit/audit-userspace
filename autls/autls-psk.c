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
#include <openssl/crypto.h>
#include "autls.h"

/*
 * autls_validate_key_file - verify a TLS key file has safe permissions
 * @path: path to the key file
 * @log_fn: logging callback for error reporting
 *
 * Checks that @path is a regular file (not a symlink), mode 0400,
 * owned by root.  Uses lstat() to reject symlinks.
 * Returns 0 on success, -1 on any validation failure.
 */
int autls_validate_key_file(const char *path, autls_log_fn log_fn)
{
	struct stat st;

	if (lstat(path, &st) != 0) {
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
	struct stat st;
	char line[512];
	size_t len;
	long tmp_len = 0;
	unsigned char *decoded = NULL;
	int rc = -1;

	fd = open(path, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		log_fn(LOG_ERR, "Unable to open PSK file %s (%s)",
			path, strerror(errno));
		return -1;
	}

	// Validate permissions on the open file descriptor
	if (fstat(fd, &st) != 0) {
		log_fn(LOG_ERR,
			"Unable to stat PSK file %s (%s)",
			path, strerror(errno));
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

	f = fdopen(fd, "r");
	if (f == NULL) {
		log_fn(LOG_ERR, "Unable to read PSK file %s (%s)",
			path, strerror(errno));
		close(fd);
		return -1;
	}
	// fd is now owned by f; do not close(fd) separately

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
