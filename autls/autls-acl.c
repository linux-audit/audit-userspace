/* autls-acl.c -- TLS client ACL file parser
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include "autls.h"

/*
 * autls_acl_load - parse a TLS client authorization file
 * @path: path to the ACL file
 * @table: output pointer to the parsed ACL table (caller frees)
 * @log_fn: logging callback for error reporting
 *
 * File format: one entry per line, fields separated by whitespace.
 *   # identity   status    notes
 *   host-1234    enabled   prod web host
 *   host-5678    disabled  retired
 *
 * Blank lines and lines starting with # are ignored.
 * Status must be "enabled" or "disabled" (case-insensitive).
 * Identity is validated via autls_validate_psk_identity().
 * Duplicate identities are rejected.
 * File must be root-owned, not group-writable, not world-writable,
 * and a regular file. Opened with O_NOFOLLOW to reject symlinks.
 *
 * Returns 0 on success, -1 on error.
 */
int autls_acl_load(const char *path, struct autls_acl_table **table,
		   autls_log_fn log_fn)
{
	int fd = -1;
	FILE *f = NULL;
	struct stat st;
	struct autls_acl_table *t = NULL;
	struct autls_acl_entry *tail = NULL;
	char line[512];
	int lineno = 0;

	*table = NULL;

	fd = open(path, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		log_fn(LOG_ERR, "Unable to open ACL file %s (%s)",
			path, strerror(errno));
		return -1;
	}

	if (fstat(fd, &st) != 0) {
		log_fn(LOG_ERR, "Unable to stat ACL file %s (%s)",
			path, strerror(errno));
		close(fd);
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		log_fn(LOG_ERR, "%s is not a regular file", path);
		close(fd);
		return -1;
	}
	if (st.st_uid != 0) {
		log_fn(LOG_ERR, "%s is not owned by root (uid %u)",
			path, (unsigned)st.st_uid);
		close(fd);
		return -1;
	}
	if (st.st_mode & 022) {
		log_fn(LOG_ERR,
			"%s is group-writable or world-writable "
			"(mode %#o)", path, st.st_mode & 07777);
		close(fd);
		return -1;
	}

	f = fdopen(fd, "r");
	if (f == NULL) {
		log_fn(LOG_ERR, "Unable to read ACL file %s (%s)",
			path, strerror(errno));
		close(fd);
		return -1;
	}

	t = calloc(1, sizeof(*t));
	if (t == NULL) {
		log_fn(LOG_ERR, "Out of memory for ACL table");
		fclose(f);
		return -1;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		char *identity, *status, *saveptr;
		struct autls_acl_entry *entry, *dup;
		size_t len;

		lineno++;

		len = strlen(line);

		/* Detect truncated lines (no newline, not at EOF) */
		if (len == sizeof(line) - 1 &&
		    line[len - 1] != '\n') {
			int ch;
			log_fn(LOG_ERR,
				"%s:%d: line too long (max %zu chars)",
				path, lineno, sizeof(line) - 2);
			/* Skip the rest of this line */
			while ((ch = fgetc(f)) != EOF && ch != '\n')
				;
			goto err;
		}

		if (len > 0 && line[len - 1] == '\n')
			line[--len] = '\0';
		if (len > 0 && line[len - 1] == '\r')
			line[--len] = '\0';

		// Skip blank lines and comments
		if (len == 0 || line[0] == '#')
			continue;

		identity = strtok_r(line, " \t", &saveptr);
		if (identity == NULL)
			continue;

		status = strtok_r(NULL, " \t", &saveptr);
		if (status == NULL) {
			log_fn(LOG_ERR,
				"%s:%d: missing status field",
				path, lineno);
			goto err;
		}

		if (autls_validate_psk_identity(
				(const unsigned char *)identity,
				strlen(identity), log_fn) != 0) {
			log_fn(LOG_ERR,
				"%s:%d: invalid identity", path, lineno);
			goto err;
		}

		size_t id_len = strlen(identity);

		/* Check for duplicates */
		for (dup = t->entries; dup; dup = dup->next) {
			if (dup->identity_len == id_len &&
			    memcmp(dup->identity, identity, id_len) == 0) {
				log_fn(LOG_ERR,
					"%s:%d: duplicate identity '%s'",
					path, lineno, identity);
				goto err;
			}
		}

		entry = calloc(1, sizeof(*entry));
		if (entry == NULL) {
			log_fn(LOG_ERR, "Out of memory for ACL entry");
			goto err;
		}
		entry->identity = strdup(identity);
		if (entry->identity == NULL) {
			log_fn(LOG_ERR, "Out of memory for identity");
			free(entry);
			goto err;
		}
		entry->identity_len = id_len;

		if (strcasecmp(status, "enabled") == 0)
			entry->enabled = 1;
		else if (strcasecmp(status, "disabled") == 0)
			entry->enabled = 0;
		else {
			log_fn(LOG_ERR,
				"%s:%d: invalid status '%s'; "
				"must be 'enabled' or 'disabled'",
				path, lineno, status);
			free(entry->identity);
			free(entry);
			goto err;
		}

		/* Append to list */
		if (tail)
			tail->next = entry;
		else
			t->entries = entry;
		tail = entry;
		t->count++;
		if (entry->enabled)
			t->enabled_count++;
	}

	if (ferror(f)) {
		log_fn(LOG_ERR, "I/O error reading ACL file %s", path);
		goto err;
	}

	fclose(f);
	*table = t;
	return 0;

err:
	fclose(f);
	autls_acl_free(t);
	return -1;
}

/*
 * autls_acl_check - look up an identity in the ACL table
 * @table: parsed ACL table
 * @identity: identity bytes to look up
 * @len: length of @identity in bytes
 *
 * Returns 1 if the identity is found and enabled,
 * 0 if found but disabled, -1 if not found.
 */
int autls_acl_check(const struct autls_acl_table *table,
		    const unsigned char *identity, size_t len)
{
	const struct autls_acl_entry *e;

	for (e = table->entries; e != NULL; e = e->next) {
		if (e->identity_len == len &&
		    CRYPTO_memcmp(e->identity, identity, len) == 0)
			return e->enabled ? 1 : 0;
	}
	return -1;
}

/*
 * autls_acl_free - free an ACL table and all its entries
 * @table: table to free, may be NULL
 */
void autls_acl_free(struct autls_acl_table *table)
{
	struct autls_acl_entry *e, *next;

	if (table == NULL)
		return;

	for (e = table->entries; e != NULL; e = next) {
		next = e->next;
		free(e->identity);
		free(e);
	}
	free(table);
}
