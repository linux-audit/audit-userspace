/* audit_logging_test.c -- Test audit logging helpers and formatting
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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libaudit.h"
#include "private.h"

static char sent_message[MAX_AUDIT_MESSAGE_LENGTH];
static unsigned int send_count;

/*
 * Capture the message that audit_send_user_message would send to the kernel.
 * Input variables: audit descriptor, message type, data, and data size.
 * Return codes: 1 to report a successful synthetic send.
 */
int
audit_send(int fd, int type, const void *data, unsigned int size)
{
	(void)fd;
	(void)type;

	assert(data != NULL);
	assert(size > 0);
	assert(size <= sizeof(sent_message));
	memcpy(sent_message, data, size);
	assert(sent_message[size - 1] == '\0');
	send_count++;
	return 1;
}

/*
 * Log a comm value and return its serialized audit field value.
 * Input variables: comm is the caller-supplied task command name.
 * Return codes: pointer to the captured comm value, aborts on failure.
 */
static const char *
get_logged_comm(const char *comm)
{
	static char field[MAX_AUDIT_MESSAGE_LENGTH];
	const char *begin;
	const char *end;
	size_t len;
	int rc;

	send_count = 0;
	rc = audit_log_user_comm_message(0, AUDIT_USER, "test", comm,
					 "host", "127.0.0.1", "", 1);
	assert(rc == 1);
	assert(send_count == 1);

	begin = strstr(sent_message, " comm=");
	assert(begin != NULL);
	begin += strlen(" comm=");
	end = strstr(begin, " exe=");
	assert(end != NULL);

	len = end - begin;
	assert(len < sizeof(field));
	memcpy(field, begin, len);
	field[len] = '\0';
	return field;
}

/*
 * Test audit logging encoding helpers.
 * Input variables: none. Return codes: none, aborts on failure.
 */
static void
test_audit_logging_encoding(void)
{
	char encoded[9];
	char binary[] = { 'A', '\0', '"', (char)0xFF };
	char high_bit[] = { (char)0x80 };
	char embedded_nul[] = { 'a', '\0', 'b' };
	char *nv;

	printf("Testing audit logging encoding...\n");
	assert(audit_value_needs_encoding(NULL, 1) == 0);
	assert(audit_value_needs_encoding("abc", 3) == 0);
	assert(audit_value_needs_encoding("a b", 3) == 1);
	assert(audit_value_needs_encoding("\"", 1) == 1);
	assert(audit_value_needs_encoding("\177", 1) == 1);
	assert(audit_value_needs_encoding(high_bit, sizeof(high_bit)) == 1);

	assert(audit_encode_value(encoded, binary, sizeof(binary)) == encoded);
	assert(strcmp(encoded, "410022FF") == 0);
	assert(audit_encode_value(encoded, NULL, sizeof(binary)) == encoded);
	assert(strcmp(encoded, "") == 0);
	assert(audit_encode_value(NULL, binary, sizeof(binary)) == NULL);

	nv = audit_encode_nv_string("field", "abc", 0);
	assert(nv != NULL);
	assert(strcmp(nv, "field=\"abc\"") == 0);
	free(nv);

	nv = audit_encode_nv_string("field", "a b", 0);
	assert(nv != NULL);
	assert(strcmp(nv, "field=612062") == 0);
	free(nv);

	nv = audit_encode_nv_string("field", embedded_nul,
				    sizeof(embedded_nul));
	assert(nv != NULL);
	assert(strcmp(nv, "field=610062") == 0);
	free(nv);

	nv = audit_encode_nv_string("field", NULL, 0);
	assert(nv != NULL);
	assert(strcmp(nv, "field=\"?\"") == 0);
	free(nv);
}

/*
 * Test that comm formatting truncates raw bytes before encoding.
 * Input variables: none. Return codes: none, aborts on failure.
 */
static void
test_audit_logging_comm_format(void)
{
	const char *quoted = "\"abcdefghijklmno\"";
	const char *encoded = "6162636465666768696A6B6C6D6E22";

	printf("Testing audit logging comm formatting...\n");
	assert(strcmp(get_logged_comm("abcdefghijklmno"), quoted) == 0);
	assert(strcmp(get_logged_comm("abcdefghijklmnop"), quoted) == 0);
	assert(strcmp(get_logged_comm(
		"abcdefghijklmno\" injected=yes\n"), quoted) == 0);
	assert(strcmp(get_logged_comm("abcdefghijklmn\""), encoded) == 0);
	assert(strcmp(get_logged_comm("abcdefghijklmn\"ignored"), encoded) == 0);
}

/*
 * Run the audit logging unit tests.
 * Input variables: none. Return codes: EXIT_SUCCESS when all tests pass.
 */
int
main(void)
{
	test_audit_logging_encoding();
	test_audit_logging_comm_format();
	return EXIT_SUCCESS;
}
