/* queue.c --
 * Copyright 2007,2013,2015,2018,2022 Red Hat Inc.
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
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "queue.h"

static volatile event_t **q;
static pthread_mutex_t queue_lock;
static pthread_cond_t queue_nonempty;
static unsigned int q_next, q_last, q_depth, processing_suspended;
static unsigned int currently_used, max_used, overflowed;
static const char *SINGLE = "1";
static const char *HALT = "0";
static int queue_full_warning = 0;
extern volatile int disp_hup;
#define QUEUE_FULL_LIMIT 5

void reset_suspended(void)
{
	processing_suspended = 0;
	queue_full_warning = 0;
}

int init_queue(unsigned int size)
{
	// The global variables are initialized to zero by the
	// compiler. We can sometimes get here by a reconfigure.
	// If the queue was already initialized, q_depth will be
	// non-zero. In that case, leave everything alone. If the
	// queue was destroyed due to lack of plugins, q_depth,
	// as well as other queue variables, is set to zero so
	// they do not need reinitializing.
	if (q_depth == 0) {
		unsigned int i;

		q_depth = size;
		q = malloc(q_depth * sizeof(event_t *));
		if (q == NULL) {
			processing_suspended = 1;
			return -1;
		}

		for (i=0; i < q_depth; i++)
			q[i] = NULL;

		/* Setup IPC mechanisms */
		pthread_mutex_init(&queue_lock, NULL);
		pthread_cond_init(&queue_nonempty, NULL);
		reset_suspended();
	}
	return 0;
}

static void change_runlevel(const char *level)
{
	char *argv[3];
	int pid;
	static const char *init_pgm = "/sbin/init";

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ALERT, "Audispd failed to fork switching runlevels");
		return;
	}
	if (pid)	/* Parent */
		return;
	/* Child */
	argv[0] = (char *)init_pgm;
	argv[1] = (char *)level;
	argv[2] = NULL;
	execve(init_pgm, argv, NULL);
	syslog(LOG_ALERT, "Audispd failed to exec %s", init_pgm);
	exit(1);
}

static int do_overflow_action(struct disp_conf *config)
{
	int rc = -1;
	overflowed = 1;
        switch (config->overflow_action)
        {
                case O_IGNORE:
			rc = 0;
			break;
                case O_SYSLOG:
			if (queue_full_warning < QUEUE_FULL_LIMIT) {
				syslog(LOG_ERR,
				  "queue to plugins is full - dropping event");
				queue_full_warning++;
				if (queue_full_warning == QUEUE_FULL_LIMIT)
					syslog(LOG_ERR,
						"auditd queue full reporting "
						"limit reached - ending "
						"dropped event notifications");
			}
                        break;
                case O_SUSPEND:
                        syslog(LOG_ALERT,
                            "Auditd is suspending event passing to plugins due to overflowing its queue.");
                        processing_suspended = 1;
                        break;
                case O_SINGLE:
                        syslog(LOG_ALERT,
                                "Auditd is now changing the system to single user mode due to overflowing its queue");
                        change_runlevel(SINGLE);
                        break;
                case O_HALT:
                        syslog(LOG_ALERT,
                                "Auditd is now halting the system due to overflowing its queue");
                        change_runlevel(HALT);
                        break;
                default:
                        syslog(LOG_ALERT, "Unknown overflow action requested");
                        break;
        }
	return rc;
}

/* returns 0 on success and -1 on error */
int enqueue(event_t *e, struct disp_conf *config)
{
	unsigned int n, retry_cnt = 0;

	if (processing_suspended) {
		free(e);
		return 0;
	}

retry:
	// We allow 3 retries and then its over
	if (retry_cnt > 3) {
		free(e);

		return do_overflow_action(config);
	}
	pthread_mutex_lock(&queue_lock);

	// OK, have lock add event
	n = q_next%q_depth;
	if (q[n] == NULL) {
		q[n] = e;
		q_next = (n+1) % q_depth;
		currently_used++;
		if (currently_used > max_used)
			max_used = currently_used;
		pthread_cond_signal(&queue_nonempty);
		pthread_mutex_unlock(&queue_lock);
	} else {
		pthread_mutex_unlock(&queue_lock);
		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = 2 * 1000 * 1000; // 2 milliseconds
		nanosleep(&ts, NULL); /* Let other thread try to log it. */
		retry_cnt++;
		goto retry;
	}
	return 0;
}

event_t *dequeue(void)
{
	event_t *e;
	unsigned int n;

	// Wait until its got something in it
	pthread_mutex_lock(&queue_lock);
	if (disp_hup) {
		pthread_mutex_unlock(&queue_lock);
		return NULL;
	}
	n = q_last%q_depth;
	if (q[n] == NULL) {
		pthread_cond_wait(&queue_nonempty, &queue_lock);
		if (disp_hup) {
			pthread_mutex_unlock(&queue_lock);
			return NULL;
		}
		n = q_last%q_depth;
	}

	// OK, grab the next event
	if (q[n] != NULL) {
		e = (event_t *)q[n];
		q[n] = NULL;
		q_last = (n+1) % q_depth;
	} else
		e = NULL;

	currently_used--;
	pthread_mutex_unlock(&queue_lock);

	// Process the event
	return e;
}

void nudge_queue(void)
{
	pthread_cond_signal(&queue_nonempty);
}

void increase_queue_depth(unsigned int size)
{
	pthread_mutex_lock(&queue_lock);
	if (size > q_depth) {
		unsigned int i;
		void *tmp_q;

		tmp_q = realloc(q, size * sizeof(event_t *));
		q = tmp_q;
		for (i=q_depth; i<size; i++)
			q[i] = NULL;
		q_depth = size;
		overflowed = 0;
	}
	pthread_mutex_unlock(&queue_lock);
}

void write_queue_state(FILE *f)
{
	fprintf(f, "current plugin queue depth = %u\n", currently_used);
	fprintf(f, "max plugin queue depth used = %u\n", max_used);
	fprintf(f, "plugin queue size = %u\n", q_depth);
	fprintf(f, "plugin queue overflow detected = %s\n",
				overflowed ? "yes" : "no");
	fprintf(f, "plugin queueing suspended = %s\n",
				processing_suspended ? "yes" : "no");
}

void resume_queue(void)
{
	processing_suspended = 0;
}

void destroy_queue(void)
{
	unsigned int i;

	for (i=0; i<q_depth; i++)
		free((void *)q[i]);

	free(q);
	q_last = 0;
	q_depth = 0;
	processing_suspended = 1;
	currently_used = 0;
	max_used = 0;
	overflowed = 0;
}

