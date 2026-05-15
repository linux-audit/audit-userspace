/* autls-io.c -- TLS I/O helpers (write, shutdown, deadline)
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
#include <limits.h>
#include <poll.h>
#include <time.h>
#include <openssl/ssl.h>
#include "autls.h"

/*
 * autls_remaining_ms - compute milliseconds remaining until a deadline
 * @deadline: absolute monotonic clock deadline
 *
 * Returns the number of milliseconds from now until @deadline, clamped
 * to INT_MAX. Returns 0 if the deadline has already passed.
 */
int autls_remaining_ms(const struct timespec *deadline)
{
	struct timespec now;
	long long ms;
	clock_gettime(CLOCK_MONOTONIC, &now);
	ms = (long long)(deadline->tv_sec - now.tv_sec) * 1000 +
	     (deadline->tv_nsec - now.tv_nsec) / 1000000;
	if (ms > INT_MAX)
		return INT_MAX;
	return ms > 0 ? (int)ms : 0;
}

/*
 * autls_ssl_write - full-or-fail TLS write with cumulative deadline
 * @ssl: active SSL connection
 * @buf: data to write
 * @len: number of bytes to write
 * @timeout_ms: maximum total time in milliseconds
 *
 * Writes exactly @len bytes or fails. Handles SSL_ERROR_WANT_READ
 * and SSL_ERROR_WANT_WRITE with poll().
 * Returns total bytes written on success, -1 on error or timeout.
 */
int autls_ssl_write(SSL *ssl, const void *buf, int len, int timeout_ms)
{
	int rc = 0, w, remaining;
	struct pollfd pfd;
	struct timespec deadline;

	pfd.fd = SSL_get_fd(ssl);
	if (pfd.fd < 0)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += timeout_ms / 1000;
	deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	while (len > 0) {
		w = SSL_write(ssl, buf, len);
		if (w <= 0) {
			int err = SSL_get_error(ssl, w);
			if (err == SSL_ERROR_WANT_WRITE)
				pfd.events = POLLOUT;
			else if (err == SSL_ERROR_WANT_READ)
				pfd.events = POLLIN;
			else
				return -1;
			remaining = autls_remaining_ms(&deadline);
			if (remaining <= 0)
				return -1;
			{
				int prc;
				do {
					prc = poll(&pfd, 1, remaining);
				} while (prc < 0 && errno == EINTR);
				if (prc <= 0)
					return -1;
			}
			if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
				return -1;
			continue;
		}
		rc += w;
		buf = (const char *)buf + w;
		len -= w;
	}
	return rc;
}

/*
 * autls_ssl_shutdown - best-effort bidirectional TLS shutdown
 * @ssl: active SSL connection
 *
 * Sends close_notify and waits up to AUTLS_SHUTDOWN_TIMEOUT_MS for
 * the peer's close_notify response.
 */
void autls_ssl_shutdown(SSL *ssl)
{
	int ret;
	struct pollfd pfd;

	pfd.fd = SSL_get_fd(ssl);
	if (pfd.fd < 0)
		return;

	ret = SSL_shutdown(ssl);
	if (ret == 0) {
		/* Sent close_notify; try to receive peer's */
		pfd.events = POLLIN;
		{
			int prc;
			do {
				prc = poll(&pfd, 1, AUTLS_SHUTDOWN_TIMEOUT_MS);
			} while (prc < 0 && errno == EINTR);
			if (prc > 0 &&
			    !(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
				SSL_shutdown(ssl);
		}
	}
}
