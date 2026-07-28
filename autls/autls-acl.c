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
 * acl_entry_free - free a single ACL entry and cleanse key material
 * @e: entry to free, must not be NULL
 */
static void acl_entry_free(struct autls_acl_entry *e)
{
	if (e->psk_key) {
		OPENSSL_cleanse(e->psk_key, e->psk_key_len);
		OPENSSL_free(e->psk_key);
	}
	free(e->key_file);
	free(e->identity);
	free(e);
}

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
 * Per-identity key mode adds a key= column with an absolute path:
 *   host-1234    enabled   key=/etc/audit/psk/host-1234.key
 *   host-5678    disabled  key=/etc/audit/psk/host-5678.key
 *
 * The key= prefix is recognized only when followed by '/' to avoid
 * collisions with free-form notes.  When any entry has a key= path,
 * all entries must have one (no mixing).
 *
 * Blank lines and lines starting with # are ignored.
 * Status must be "enabled" or "disabled" (case-insensitive).
 * Identity is validated via autls_validate_psk_identity().
 * Duplicate identities and duplicate key file paths are rejected.
 * File must be root-owned, not group-writable, not world-writable,
 * and a regular file. Opens with O_NOFOLLOW to reject symlinks and
 * O_NONBLOCK so a FIFO cannot block before the regular-file check.
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
	int key_count = 0;
	int flags;

	*table = NULL;

	/* Reject FIFOs before a blocking open can stall auditd on reload. */
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
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

	/* Regular files do not need nonblocking I/O after validation. */
	flags = fcntl(fd, F_GETFL);
	if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
		log_fn(LOG_ERR, "Unable to restore blocking mode for ACL file %s (%s)",
			path, strerror(errno));
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
		char *identity, *status, *extra, *saveptr;
		struct autls_acl_entry *entry, *dup;
		size_t len, id_len;

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

		id_len = strlen(identity);

		/* Check for duplicate identities */
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
			acl_entry_free(entry);
			goto err;
		}

		/* Check for optional per-identity key path */
		extra = strtok_r(NULL, " \t", &saveptr);
		if (extra && strncmp(extra, "key=/", 5) == 0) {
			const char *key_path = extra + 4;
			char *trailing;

			/* Reject trailing tokens after key= path */
			trailing = strtok_r(NULL, " \t", &saveptr);
			if (trailing) {
				log_fn(LOG_ERR,
					"%s:%d: unexpected token after "
					"key= path", path, lineno);
				acl_entry_free(entry);
				goto err;
			}

			/* Check for duplicate key file paths */
			for (dup = t->entries; dup; dup = dup->next) {
				if (dup->key_file &&
				    strcmp(dup->key_file, key_path) == 0) {
					log_fn(LOG_ERR,
						"%s:%d: duplicate key file "
						"path '%s'",
						path, lineno, key_path);
					acl_entry_free(entry);
					goto err;
				}
			}

			entry->key_file = strdup(key_path);
			if (entry->key_file == NULL) {
				log_fn(LOG_ERR,
					"Out of memory for key file path");
				acl_entry_free(entry);
				goto err;
			}

			if (autls_load_psk(key_path, &entry->psk_key,
					   &entry->psk_key_len,
					   log_fn) != 0) {
				log_fn(LOG_ERR,
					"%s:%d: failed to load key file "
					"'%s'", path, lineno, key_path);
				acl_entry_free(entry);
				goto err;
			}

			key_count++;
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

	/* Per-identity keys: all-or-nothing consistency check */
	if (key_count > 0 && key_count != t->count) {
		log_fn(LOG_ERR,
			"%s: %d of %d entries have per-identity keys; "
			"all entries must have key= or none",
			path, key_count, t->count);
		goto err;
	}
	if (key_count > 0) {
		struct autls_acl_entry *a, *b;

		/* Reject duplicate key content across entries */
		for (a = t->entries; a != NULL; a = a->next) {
			for (b = a->next; b != NULL; b = b->next) {
				if (a->psk_key_len == b->psk_key_len &&
				    CRYPTO_memcmp(a->psk_key, b->psk_key,
						 a->psk_key_len) == 0) {
					log_fn(LOG_ERR,
						"%s: identities '%s' and "
						"'%s' have identical key "
						"material",
						path, a->identity,
						b->identity);
					goto err;
				}
			}
		}
		t->has_per_identity_keys = 1;
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
 * autls_acl_lookup - look up an identity in the ACL table
 * @table: parsed ACL table
 * @identity: identity bytes to look up
 * @len: length of @identity in bytes
 *
 * Returns a pointer to the matching entry, or NULL if not found.
 * Uses CRYPTO_memcmp for individual comparisons to prevent
 * per-byte timing leaks; the overall lookup is not fully
 * constant-time (early return on match, length pre-check),
 * which is acceptable because PSK identities are sent in
 * cleartext in TLS 1.3.
 */
const struct autls_acl_entry *autls_acl_lookup(
		const struct autls_acl_table *table,
		const unsigned char *identity, size_t len)
{
	const struct autls_acl_entry *e;

	for (e = table->entries; e != NULL; e = e->next) {
		if (e->identity_len == len &&
		    CRYPTO_memcmp(e->identity, identity, len) == 0)
			return e;
	}
	return NULL;
}

/*
 * autls_acl_check - look up an identity and return its status
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
	const struct autls_acl_entry *e = autls_acl_lookup(table,
							   identity, len);
	if (e == NULL)
		return -1;
	return e->enabled ? 1 : 0;
}

/*
 * autls_acl_free - free an ACL table and all its entries
 * @table: table to free, may be NULL
 *
 * Cleanses per-identity key material before freeing.
 */
void autls_acl_free(struct autls_acl_table *table)
{
	struct autls_acl_entry *e, *next;

	if (table == NULL)
		return;

	for (e = table->entries; e != NULL; e = next) {
		next = e->next;
		acl_entry_free(e);
	}
	free(table);
}
