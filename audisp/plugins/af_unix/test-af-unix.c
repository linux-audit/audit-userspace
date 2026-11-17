/*
 * test-af-unix.c - binary stdin framing tests for audisp-af_unix
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <assert.h>

#define main audisp_af_unix_main
#include "audisp-af_unix.c"
#undef main

/* Read and compare len output bytes from fd; abort on missing/extra data. */
static void check_output(int fd, const char *expected, size_t len)
{
	char buf[QUEUE_ENTRY_SIZE];
	size_t used = 0;
	ssize_t rc;

	while (used < len) {
		rc = read(fd, buf + used, len - used);
		assert(rc > 0);
		used += rc;
	}
	assert(memcmp(buf, expected, len) == 0);
	assert(read(fd, buf, sizeof(buf)) == -1);
	assert(errno == EAGAIN || errno == EWOULDBLOCK);
}

/*
 * Feed size-byte records of protocol ver to stdin in chunk-byte fragments,
 * then check output in out_format. Returns nothing; failures abort.
 */
static void test_fragmented_input(size_t chunk, unsigned int ver,
				  format_t out_format, size_t size)
{
	struct audit_dispatcher_header hdr = {
		.ver = ver,
		.hlen = sizeof(hdr),
		.type = AUDIT_SYSCALL,
		.size = size,
	};
	char frame[MAX_AUDIT_EVENT_FRAME_SIZE];
	char expected[QUEUE_ENTRY_SIZE];
	size_t total = sizeof(hdr) + size, expected_len;
	int input[2], output[2], record;

	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, input) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, output) == 0);
	assert(dup2(input[1], STDIN_FILENO) == STDIN_FILENO);
	close(input[1]);
	inbound_protocol = -1;
	format = out_format;
	client = 1;
	stop = 0;
	conn = output[0];
	queue = q_open(DEFAULT_QUEUE_DEPTH, QUEUE_ENTRY_SIZE);
	assert(queue);

	/* A following complete record must stay aligned after fragmentation. */
	for (record = 0; record < 2; record++) {
		size_t offset = 0;

		memcpy(frame, &hdr, sizeof(hdr));
		memset(frame + sizeof(hdr), 'a' + record, size);
		if (format == F_BINARY) {
			memcpy(expected, frame, total);
			expected_len = total;
		} else {
			int len = snprintf(expected, sizeof(expected), "%s%.*s\n",
				ver == AUDISP_PROTOCOL_VER ?
				"type=SYSCALL msg=" : "", (int)size,
				frame + sizeof(hdr));

			assert(len > 0 && (size_t)len < sizeof(expected));
			expected_len = len;
		}
		while (offset < total) {
			size_t len = total - offset;

			if (!record && len > chunk)
				len = chunk;
			assert(write(input[0], frame + offset, len) ==
			       (ssize_t)len);
			offset += len;
			read_audit_record(STDIN_FILENO);
			assert(!stop);
			if (offset < total) {
				assert(q_empty(queue));
				/* Repeated EAGAIN must retain the same fragment. */
				read_audit_record(STDIN_FILENO);
				assert(!stop && q_empty(queue));
			}
		}
		assert(q_queue_length(queue) == 1);
		send_queue();
		assert(q_empty(queue));
		check_output(output[1], expected, expected_len);
	}
	close(input[0]);
	read_audit_record(STDIN_FILENO);
	assert(stop);
	close(conn);
	close(output[1]);
	q_close(queue);
}

/* Exercise both protocols and output formats; return zero on success. */
int main(void)
{
	const size_t chunks[] = { 1, 8, 16, 20, MAX_AUDIT_EVENT_FRAME_SIZE };
	unsigned int ver;
	format_t out_format;
	size_t i;
	int saved_stdin = dup(STDIN_FILENO);

	assert(saved_stdin >= 0);
	for (ver = AUDISP_PROTOCOL_VER; ver <= AUDISP_PROTOCOL_VER2; ver++) {
		for (out_format = F_BINARY; out_format <= F_STRING; out_format++) {
			for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
				test_fragmented_input(chunks[i], ver, out_format, 32);
				test_fragmented_input(chunks[i], ver, out_format, 0);
			}
			test_fragmented_input(257, ver, out_format,
					      MAX_AUDIT_MESSAGE_LENGTH);
		}
	}
	assert(dup2(saved_stdin, STDIN_FILENO) == STDIN_FILENO);
	close(saved_stdin);
	return 0;
}
