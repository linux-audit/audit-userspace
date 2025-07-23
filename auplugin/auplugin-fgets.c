/* audit-fgets.c -- a replacement for glibc's fgets
 * Copyright 2018,2022,2025 Red Hat Inc.
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
 *      Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "libaudit.h"
#include "auplugin.h"

/*
 * The theory of operation for this family of functions is that it
 * operates like the glibc fgets function except with a descriptor.
 * It reads from the descriptor into a buffer and then looks through
 * the buffer to find a string terminated with a '\n'. It terminates
 * the string with a 0 and returns it. It updates current to point
 * to where it left off. On the next read it starts there and tries to
 * find a '\n'. If it can't find one, it slides the buffer down and
 * fills as much as it can from the descriptor. If the descriptor
 * becomes invalid or there is an error reading, it makes eof true.
 * The variable eptr marks the end of the buffer. It never changes.
 */

#define BUF_SIZE 8192

struct auplugin_fgets_state {
	char internal[2*BUF_SIZE+1];
	char *buffer;
	char *current;
	char *eptr;
	char *orig;
	int eof;
	enum auplugin_mem mem_type;
	size_t buff_size;
};

static struct auplugin_fgets_state global_state;
static int global_init_done;

static void auplugin_fgets_state_init(struct auplugin_fgets_state *st)
{
	st->buffer = st->internal;
	st->internal[0] = '\0';
	st->current = st->buffer;
	st->eptr = st->buffer + (2*BUF_SIZE);
	st->orig = st->buffer;
	st->eof = 0;
	st->mem_type = MEM_SELF_MANAGED;
	st->buff_size = 2*BUF_SIZE;
}

struct auplugin_fgets_state *auplugin_fgets_init(void)
{
	struct auplugin_fgets_state *st = malloc(sizeof(*st));
	if (st)
		auplugin_fgets_state_init(st);
	return st;
}


void auplugin_fgets_destroy(struct auplugin_fgets_state *st)
{
	if (st->buffer != st->internal) {
		switch (st->mem_type) {
		case MEM_MALLOC:
			free(st->buffer);
			break;
		case MEM_MMAP:
		case MEM_MMAP_FILE:
			munmap(st->buffer, st->buff_size);
			break;
		case MEM_SELF_MANAGED:
		default:
			break;
		}
	}
	free(st);
}

int auplugin_fgets_eof_r(struct auplugin_fgets_state *st)
{
	return st->eof;
}

/* This function dumps any accumulated text. This is to remove dangling text
 * that never got consumed for the intended purpose. */
void auplugin_fgets_clear_r(struct auplugin_fgets_state *st)
{
	// For MEM_MMAP_FILE, it effectively rewinds the buffer making the
	// whole buffer available again. This is different than all others
	// because we can't just dump a file.
	if (st->mem_type == MEM_MMAP_FILE) {
		st->buffer = st->orig;
		st->current = st->eptr;
	} else {
		st->buffer[0] = 0;
		st->current = st->buffer;
	}
	st->eof = 0;
}

/* Function to check if we have more data stored
 * and ready to process. If we have a newline or enough
 * bytes we return 1 for success. Otherwise 0 meaning that
 * there is not enough to process without blocking. */
int auplugin_fgets_more_r(struct auplugin_fgets_state *st, size_t blen)
{
	size_t avail;
	char *nl;

	assert(blen != 0);
	avail = st->current - st->buffer;

	/* only scan the valid region */
	nl = memchr(st->buffer, '\n', avail);
	return (nl || avail >= blen - 1);
}

/* Function to read the next chunk of data from the given fd. If we have
 * data to return, we Read up to blen-1 chars (or through the next newline),
 * copy into buf, NUL-terminate, and return the number of chars.
 * It also returns 0 for no data. And -1 if there was an error reading
 * the fd. */
int auplugin_fgets_r(struct auplugin_fgets_state *st, char *buf, size_t blen, int fd)
{
	size_t avail = st->current - st->buffer, line_len;
	char  *line_end;
	ssize_t nread;

	assert(blen != 0);

	/* 1) Is there already a '\n' in the buffered data? */
	line_end = memchr(st->buffer, '\n', avail);

	/* 2) If not, and we still can read more, pull in more data */
	if (line_end == NULL && !st->eof && st->current != st->eptr) {
		do {
			nread = read(fd, st->current, st->eptr - st->current);
		} while (nread < 0 && errno == EINTR);

		if (nread < 0)
			return -1;

		if (nread == 0)
			st->eof = 1;
		else {
			size_t got = (size_t)nread;
			st->current[got] = '\0';
			st->current += got;
			avail += got;
		}

		/* see if a newline arrived in that chunk */
		line_end = memchr(st->buffer, '\n', avail);
	}

	/* 3) Do we now have enough to return? */
	if (line_end == NULL) {
		/* not a full line—only return early if we still expect more */
		if (!st->eof && avail < blen - 1 && st->current != st->eptr)
			return 0;

		/* else we’ll return whatever we have (either at EOF,
		 * buffer‑full, or enough for blen) */
	}

	/* 4) Compute how many chars to hand back */
	if (line_end) {
		/* include the '\n', but never exceed blen-1 */
		line_len = (line_end - st->buffer) + 1;
		if (line_len > blen - 1)
			line_len = blen - 1;

	} else
		/* no newline: return up to blen-1 or whatever’s left
		 * at EOF/full */
		line_len = (avail < blen - 1) ? avail : (blen - 1);

	/* 5) Copy out, slide the remainder down, reset pointers */
	memcpy(buf, st->buffer, line_len);
	buf[line_len] = '\0';

	size_t remainder = avail - line_len;
	/* For MEM_MMAP_FILE, can't slide it down, so move buffer beginning */
	if (st->mem_type == MEM_MMAP_FILE) {
		st->buffer += line_len;
		if (st->buffer >= st->eptr)
			st->eof = 1;
	} else {
		if (remainder > 0)
			memmove(st->buffer, st->buffer + line_len, remainder);
	}

	st->current = st->buffer + remainder;
	*st->current = '\0';

	return (int)line_len;
}

static inline void auplugin_fgets_ensure_global(void)
{
	if (!global_init_done) {
		auplugin_fgets_state_init(&global_state);
		global_init_done = 1;
	}
}

int auplugin_fgets_eof(void)
{
	auplugin_fgets_ensure_global();
	return auplugin_fgets_eof_r(&global_state);
}

void auplugin_fgets_clear(void)
{
	auplugin_fgets_ensure_global();
	auplugin_fgets_clear_r(&global_state);
}

int auplugin_fgets_more(size_t blen)
{
	auplugin_fgets_ensure_global();
	return auplugin_fgets_more_r(&global_state, blen);
}

int auplugin_fgets(char *buf, size_t blen, int fd)
{
	auplugin_fgets_ensure_global();
	return auplugin_fgets_r(&global_state, buf, blen, fd);
}

int auplugin_setvbuf_r(struct auplugin_fgets_state *st, void *buf,
			size_t buff_size, enum auplugin_mem how)
{
	if (st == NULL || buf == NULL || buff_size == 0)
		return 1;
	st->buffer = buf;
	st->orig = buf;
	if (how == MEM_MMAP_FILE)
		/* Setting st->current to the end of the supplied mmap region
		 * is done so that auplugin_fgets_r sees the buffer as already
		 * filled with buff_size bytes of data and there is no space
		 * left for additional reads. This prevents any read() calls. */
		st->current = (char *)buf + buff_size;
	else
		st->current = st->buffer;
	st->eptr = st->buffer + buff_size;
	st->eof = 0;
	st->mem_type = how;
	st->buff_size = buff_size;
	return 0;
}

int auplugin_setvbuf(void *buf, size_t buff_size, enum auplugin_mem how)
{
        auplugin_fgets_ensure_global();
        return auplugin_setvbuf_r(&global_state, buf, buff_size, how);
}

