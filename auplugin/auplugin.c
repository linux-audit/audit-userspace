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
#include "common.h"	// For ATOMICs & VISIBILITY
#include "libdisp.h"	// For event_t
AUDIT_HIDDEN_START
#include "queue.h"
AUDIT_HIDDEN_END
#include "auplugin.h"

/*
 * The library maintains global state for its queue and worker threads.
 * Only one plugin instance is supported, so callers must not invoke
 * auplugin_init() concurrently from multiple threads.
 */

/* Local data */
#ifdef HAVE_ATOMIC
static ATOMIC_INT stop = 0;
ATOMIC_INT disp_hup = 0;	// Needed by queue
#else
static volatile ATOMIC_INT stop = 0; /* Fallback when atomics are absent */
volatile ATOMIC_INT disp_hup = 0;
#endif

static int fd;
static pthread_t outbound_thread;
static daemon_conf_t q_config;
static unsigned int timer_interval;
static auplugin_timer_callback_ptr timer_cb;
static auplugin_stats_callback_ptr stats_cb;

/* Local function prototypes */
static void *outbound_thread_loop(void *arg);
static void *outbound_thread_feed(void *arg);

/*
 * This function is intended to initialize the plugin infrastructure
 * to be used later. It returns 0 on success and -1 on failure.
 */
int auplugin_init(int inbound_fd, unsigned queue_size, int q_flags,
		  const char *path)
{
	fd = inbound_fd;
	q_config.q_depth = queue_size;
	q_config.overflow_action = O_IGNORE;
	q_config.max_restarts = 0;
	q_config.plugin_dir = NULL;

	// Set inbound descriptor to non-blocking mode
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		syslog(LOG_ERR, "fcntl failed: %m");
		return -1;
	}

	return init_queue_extended(queue_size, q_flags, path);
}

/*
 * This function is used to tell auplugin that it's time to exit.
 */
void auplugin_stop(void)
{
	AUDIT_ATOMIC_STORE(stop, 1);
}

/*
 * This function defines a comment set of tasks that the inbound event
 * handler must perform. Namely waiting for an event and then enqueuing
 * it for the outbound worker. This function does not exit until a
 * SIGTERM signal is detected. It leaves cleaning up the queue to the
 * outbound thread since it doesn't know if it's still access it.
 */
static char rx_buf[MAX_AUDIT_EVENT_FRAME_SIZE+1];
static void common_inbound(void)
{
	fd_set read_mask;

	do {
		int ret_val;
		FD_ZERO(&read_mask);
		FD_SET(fd, &read_mask);

		// Wait for next event
		do {
			 ret_val = select(fd+1, &read_mask, NULL, NULL, NULL);
		} while (ret_val == -1 && errno == EINTR &&
			 !AUDIT_ATOMIC_LOAD(stop));

		// If a real error (shouldn't happen) log it and exit
		if (ret_val < 0 && errno != EINTR) {
			syslog(LOG_ERR, "select error: %m");
			AUDIT_ATOMIC_STORE(stop, 1);
		}

		// Inbound is readable
		if (ret_val > 0) {
		    do {
			int len;
			if ((len = auplugin_fgets(rx_buf,
				    MAX_AUDIT_EVENT_FRAME_SIZE + 1, fd)) > 0) {
				// Got one - enqueue it
				event_t *e = (event_t *)calloc(1,
					 sizeof(event_t));
				if (e) {
					strncpy(e->data, rx_buf,
						MAX_AUDIT_MESSAGE_LENGTH);
					e->data[MAX_AUDIT_MESSAGE_LENGTH-1] = 0;
					e->hdr.size = len;
					e->hdr.ver = AUDISP_PROTOCOL_VER2;
					enqueue(e, &q_config);
				}
			} else if (len < 0) {
				AUDIT_ATOMIC_STORE(stop, 1);
				syslog(LOG_ERR, "auplugin_fgets failed: %m");
			} else if (auplugin_fgets_eof()) {
				AUDIT_ATOMIC_STORE(stop, 1);
				syslog(LOG_INFO, "Stopping on end of file");
			}
		    } while (auplugin_fgets_more(MAX_AUDIT_EVENT_FRAME_SIZE));
		}
	} while (!AUDIT_ATOMIC_LOAD(stop));
}

/*
 * This function is the entrypoint for event processing when you want to
 * get the event records one by one. The caller should pass a function
 * pointer to a function that has only one argument which is a const char *
 * that will contain the event record as a string. The called function
 * should NOT free it. This function does not return until SIGTERM has
 * been signalled via auplugin_stop(). There is nothing significant to
 * return to the caller.
 */
void auplugin_event_loop(auplugin_callback_ptr callback)
{
	int rc;

	/* Create outbound thread */
	rc = pthread_create(&outbound_thread, NULL,
			    outbound_thread_loop, callback);
	if (rc) {
		syslog(LOG_ERR, "pthread_create failed: %m");
		destroy_queue();
		return;
	}
	pthread_detach(outbound_thread);

	common_inbound();
}

/*
 * This function is the entrypoint for event processing when you want to
 * get the event records as a callback function to auparse. It takes care
 * of setting up auparse and feeding it from what can be dequeued. The
 * callback function will have a pointer to the auparse_state_t variable
 * that can be used to iterate across the event. The called function should
 * only use function related to iterating across a record. Calling any other
 * auparse function can have unknown consequences. This function does not
 * return until SIGTERM has been signalled via auplugin_stop(). It will
 * return 0 for success and -1 if something went wrong setting up auparse.
 */
int auplugin_event_feed(auparse_callback_ptr callback, unsigned int t_interval,
			auplugin_timer_callback_ptr t_cb)
{
	int rc;
	if (callback == NULL)
		return -1;

	auparse_state_t *au = auparse_init(AUSOURCE_FEED, 0);
        if (au == NULL) {
                printf("plugin is exiting due to auparse init errors");
                return -1;
        }
        auparse_set_eoe_timeout(2);
        auparse_add_callback(au, callback, NULL, NULL);
	timer_interval = t_interval;
	timer_cb = t_cb;

	/* Create outbound thread */
	rc = pthread_create(&outbound_thread, NULL, outbound_thread_feed, au);
	if (rc) {
		syslog(LOG_ERR, "pthread_create failed: %m");
		auparse_destroy(au);
		destroy_queue();

		return -1;
	}
	pthread_detach(outbound_thread);

	common_inbound();
	return 0;
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

/*
 * outbound thread - dequeue data to a callback function that takes a string
 */
static void *outbound_thread_loop(void *arg)
{
	common_outbound_thread_init();
	auplugin_callback_ptr callback = (auplugin_callback_ptr)arg;

        /* Start event loop */
	while (AUDIT_ATOMIC_LOAD(stop) == 0) {
		/* This is where we block until we have an event */
		// If we are blocked here, how do we age events? nudge queue?
		event_t *e = dequeue();
		if (e == NULL) {
			if (AUDIT_ATOMIC_LOAD(stop))
				break;
			continue;
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
	destroy_queue();

	return NULL;
}

/*
 * outbound thread - dequeue data to auparse_feed
 */
static void *outbound_thread_feed(void *arg)
{
	auparse_state_t *au  = (auparse_state_t *)arg;
	common_outbound_thread_init();

        /* Start event loop */
	while (AUDIT_ATOMIC_LOAD(stop) == 0) {
		/* This is where we block until we have an event */
		event_t *e;
		if (timer_interval) {
			struct timespec ts;

			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += timer_interval;
			e = dequeue_timed(&ts);
		} else
			e = dequeue();

		if (e == NULL) {
			if (timer_interval && errno == ETIMEDOUT) {
				if (timer_cb)
					timer_cb(timer_interval);
				auparse_feed_age_events(au);
				continue;
			}
			if (AUDIT_ATOMIC_LOAD(stop))
				break;
			continue;
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
	destroy_queue();

	return NULL;
}

void auplugin_register_stats_callback(auplugin_stats_callback_ptr cb)
{
	stats_cb = cb;
}

void auplugin_report_stats(void)
{
	if (stats_cb) {
		stats_cb(queue_current_depth(), queue_max_depth(),
			 queue_overflowed_p());
	}
}

unsigned int auplugin_queue_depth(void)
{
	return queue_current_depth();
}

unsigned int auplugin_queue_max_depth(void)
{
	return queue_max_depth();
}

int auplugin_queue_overflow(void)
{
	return queue_overflowed_p();
}

