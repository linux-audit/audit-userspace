/* audit-fgets.c -- a replacement for glibc's fgets
 * Copyright 2018,2022 Red Hat Inc.
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
#include "libaudit.h"

#define BUF_SIZE 8192
static char buffer[2*BUF_SIZE+1] = { 0 };
static char *current = buffer;
static char *const eptr = buffer+(2*BUF_SIZE);
static int eof = 0;

int audit_fgets_eof(void)
{
	return eof;
}

/* This function dumps any accumulated text. This is to remove dangling text
 * that never got consumed for the intended purpose. */
void audit_fgets_clear(void)
{
	buffer[0] = 0;
	current = buffer;
	eof = 0;
}

/* Function to check if we have more data stored
 * and ready to process. If we have a newline or enough
 * bytes we return 1 for success. Otherwise 0 meaning that
 * there is not enough to process without blocking. */
int audit_fgets_more(size_t blen)
{
	size_t avail;
	char *nl;

	assert(blen != 0);
	avail = current - buffer;

	/* only scan the valid region */
	nl = memchr(buffer, '\n', avail);
	return (nl || avail >= blen - 1);
}

/* Function to read the next chunk of data from the given fd. If we have
 * data to return, we Read up to blen-1 chars (or through the next newline),
 * copy into buf, NUL-terminate, and return the number of chars.
 * It also returns 0 for no data. And -1 if there was an error reading
 * the fd. */
int audit_fgets(char *buf, size_t blen, int fd)
{
	size_t avail = current - buffer, line_len;
	char  *line_end;
	ssize_t nread;

	assert(blen != 0);

	/* 1) Is there already a '\n' in the buffered data? */
	line_end = memchr(buffer, '\n', avail);

	/* 2) If not, and we still can read more, pull in more data */
	if (line_end == NULL && !eof && current != eptr) {
		do {
			nread = read(fd, current, eptr - current);
		} while (nread < 0 && errno == EINTR);

		if (nread < 0)
			return -1;

		if (nread == 0)
			eof = 1;
		else {
			current[nread] = '\0';
			current       += nread;
			avail         += nread;
		}

		/* see if a newline arrived in that chunk */
		line_end = memchr(buffer, '\n', avail);
	}

	/* 3) Do we now have enough to return? */
	if (line_end == NULL) {
		/* not a full line—only return early if we still expect more */
		if (!eof && avail < blen - 1 && current != eptr)
			return 0;

		/* else we’ll return whatever we have (either at EOF,
		 * buffer‑full, or enough for blen) */
	}

	/* 4) Compute how many chars to hand back */
	if (line_end) {
		/* include the '\n', but never exceed blen-1 */
		line_len = (line_end - buffer) + 1;
		if (line_len > blen - 1)
			line_len = blen - 1;

	} else
		/* no newline: return up to blen-1 or whatever’s left
		 * at EOF/full */
		line_len = (avail < blen - 1) ? avail : (blen - 1);

	/* 5) Copy out, slide the remainder down, reset pointers */
	memcpy(buf, buffer, line_len);
	buf[line_len] = '\0';

	size_t remainder = avail - line_len;
	if (remainder > 0)
		memmove(buffer, buffer + line_len, remainder);

	current = buffer + remainder;
	*current = '\0';

	return (int)line_len;
}

