/* remote-fgets.c --
 * Copyright 2011 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "remote-fgets.h"

#define BUF_SIZE 8192
static char buffer[2*BUF_SIZE+1] = { 0 };
static char *current = buffer, *eptr = buffer+(2*BUF_SIZE);
static int eof = 0;

int remote_fgets_eof(void)
{
	return eof;
}

/* Function to check if we have more data stored
 * and ready to process. If we have a newline or enough
 * bytes we return 1 for success. Otherwise 0 meaning that
 * there is not enough to process without blocking. */
int remote_fgets_more(size_t blen)
{
	char *ptr = strchr(buffer, '\n');
	if (ptr || (size_t)(current-buffer) >= blen)
		return 1;
	return 0;
}

int remote_fgets(char *buf, size_t blen, int fd)
{
	int len = 0, complete = 0;
	size_t check;
	char *ptr = NULL;

	/* See if we have more in the buffer first */
	if (current != buffer) {
		ptr = strchr(buffer, '\n');
		if (ptr)
			len = current - buffer;
		else if ((size_t)(current - buffer) >= blen)
			ptr = current-1; // have more than blen, so point to end
	}

	/* Otherwise get some new bytes */
	if (ptr == NULL && current != eptr && !eof) {
		/* Use current since we may be adding more */
		do {
			len = read(fd, current, eptr - current);
		} while (len < 0 && errno == EINTR);
		if (len < 0)
			return -1;
		if (len == 0)
			eof = 1;
		else
			current[len] = 0;

		/* Start from beginning to see if we have one */
		ptr = strchr(buffer, '\n');
	}

	/* See what we have */
	if (ptr) {
		ptr++; /* Include the newline */
		check = ptr - buffer;
		/* Make sure we are within the right size */
		if (check > blen)
			check = blen;
		complete = 1;
	} else if (current+len == eptr) {
		/* We are full but no newline */
		check = blen;
		len = eptr - buffer;
		complete = 1;
	} else if (current+len >= buffer+blen) {
		/* Not completely full, no newline, but enough to fill buf */
		len += (current - buffer);
		check = blen;
		complete = 1;
	}
	if (complete) {
		/* Move to external buf and terminate it */
		memmove(buf, buffer, check);
		buf[check] = 0;
		if ((size_t)len > check) {
			/* We have a few leftover bytes to move */
			memmove(buffer, buffer+check, len-check);
			current = buffer+(len-check);
			*current = 0;
		} else {
			/* Got the whole thing, just reset */
			current = buffer;
			buffer[0] = 0;
		}
	} else {
		/* To get here, no newline, not completely full, and less
		 * than blen. Not sure this is even possible. */
		current += len;
		check = 0;
	}
	return check;
}
