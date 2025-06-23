/* auplugin.c -- The main interface for writin auditd plugins
 * Copyright 2025 Red Hat Inc.
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
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/select.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include "common.h"	// For ATOMICs
#include "libdisp.h"	// For event_t
//#include "queue.h"
#include "auplugin.h"

/* Local data */
#ifdef HAVE_ATOMIC
static ATOMIC_INT stop = 0;
#else
static volatile ATOMIC_INT stop = 0; /* Fallback when atomics are absent */
#endif

static int fd;
static pthread_t outbound_thread;

/* Local function prototypes */
static void *outbound_thread_loop(void *arg);
static void *outbound_thread_feed(void *arg);

int auplugin_init(int inbound_fd, unsigned queue_size)
{
	fd = inbound_fd;
//	init_queue(queue_size);

	return 0;
}

void auplugin_stop(void)
{
	AUDIT_ATOMIC_STORE(stop, 1);
}

static char rx_buf[MAX_AUDIT_EVENT_FRAME_SIZE+1];
static int common_inbound(void)
{
	fd_set read_mask;

	// Set inbound to non-blocking mode
	fcntl(fd, F_SETFL, O_NONBLOCK);
	FD_ZERO(&read_mask);
	FD_SET(fd, &read_mask);

	do {
		int ret_val;

		// Wait for next event
		do {
			 ret_val = select(1, &read_mask, NULL, NULL, NULL);
		} while (ret_val == -1 && errno == EINTR &&
			 !AUDIT_ATOMIC_LOAD(stop));

		// Inbound is readable
		if (ret_val > 0) {
		    do {
			int len;
			if ((len = auplugin_fgets(rx_buf,
				    MAX_AUDIT_EVENT_FRAME_SIZE + 1,fd)) > 0) {
				// Got one - enqueue it
				event_t *e = (event_t *)calloc(1,
					 sizeof(event_t));
				if (e) {
					strncpy(e->data, rx_buf,
						MAX_AUDIT_MESSAGE_LENGTH);
					e->data[MAX_AUDIT_MESSAGE_LENGTH-1] = 0;
					e->hdr.size = len;
					e->hdr.ver = AUDISP_PROTOCOL_VER2;
//					enqueue(e);
				}
			} else if (auplugin_fgets_eof()) {
				AUDIT_ATOMIC_STORE(stop, 1);
				syslog(LOG_INFO, "Stopping on end of file");
			}
		    } while (auplugin_fgets_more(MAX_AUDIT_EVENT_FRAME_SIZE));
		}
	} while (!AUDIT_ATOMIC_LOAD(stop));

	return 0;
}

int auplugin_event_loop(auplugin_callback_ptr callback)
{
	/* Create outbound thread */
	pthread_create(&outbound_thread, NULL, outbound_thread_loop, callback);
	pthread_detach(outbound_thread);

	return common_inbound();
}

int auplugin_event_feed(auparse_callback_ptr callback)
{
	auparse_state_t *au = auparse_init(AUSOURCE_FEED, 0);
        if (au == NULL) {
                printf("plugin is exiting due to auparse init errors");
                return -1;
        }
        auparse_set_eoe_timeout(2);
        auparse_add_callback(au, callback, au, NULL);

	/* Create outbound thread */
	pthread_create(&outbound_thread, NULL, outbound_thread_feed, au);
	pthread_detach(outbound_thread);

	return common_inbound();
}

static void common_outbound_thread_init(void)
{
        sigset_t sigs;

        /* This is a worker thread. Don't handle signals. */
        sigemptyset(&sigs);
        sigaddset(&sigs, SIGTERM);
        sigaddset(&sigs, SIGHUP);
        sigaddset(&sigs, SIGUSR1);
        sigaddset(&sigs, SIGUSR2);
        sigaddset(&sigs, SIGCHLD);
        sigaddset(&sigs, SIGCONT);
        pthread_sigmask(SIG_SETMASK, &sigs, NULL);
}

/* outbound thread - dequeue data to  */
static void *outbound_thread_loop(void *arg)
{
	common_outbound_thread_init();
	auplugin_callback_ptr callback = (auplugin_callback_ptr)arg;

        /* Start event loop */
	while (AUDIT_ATOMIC_LOAD(stop) == 0) {
		event_t *e;
		/* This is where we block until we have an event */
		// If we are blocked here, how do we age events? nudge queue?
//		e = dequeue();
		if (e == NULL) {
			if (AUDIT_ATOMIC_LOAD(stop))
				break;
		}
		if (e->hdr.ver != AUDISP_PROTOCOL_VER2) {
			// should never be anything but v2
			free(e);
			continue;
		}
		callback(e->data);
		free(e);
	}

	// This side destroys the queue since it knows when it's done
//	destroy_queue();

	return NULL;
}

/* outbound thread - dequeue data to  */
static void *outbound_thread_feed(void *arg)
{
	int len;
	auparse_state_t *au  = (auparse_state_t *)arg;
	common_outbound_thread_init();

        /* Start event loop */
	while (AUDIT_ATOMIC_LOAD(stop) == 0) {
		event_t *e;
		/* This is where we block until we have an event */
		// If we are blocked here, how do we age events? nudge queue?
//		event_t *e = dequeue();
		if (e == NULL) {
			if (AUDIT_ATOMIC_LOAD(stop))
				break;
		}
		if (e->hdr.ver != AUDISP_PROTOCOL_VER2) {
			// should never be anything but v2
			free(e);
			continue;
		}
		auparse_feed(au, e->data, e->hdr.size);
		free(e);
	}
	auparse_flush_feed(au);
	auparse_destroy(au);

	// This side destroys the queue since it knows when it's done
//	destroy_queue();

	return NULL;
}

