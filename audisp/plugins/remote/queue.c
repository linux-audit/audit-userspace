/* queue.c --
 * Copyright 2009 Red Hat Inc., Durham, North Carolina.
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
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "queue.h"
#include "remote-config.h"

static volatile event_t **q;
static unsigned int q_next, q_last, q_depth;
//static const char *SINGLE = "1";
//static const char *HALT = "0";


int init_queue(unsigned int size)
{
	unsigned int i;

	q_next = 0;
	q_last = 0;
	q_depth = size;
	q = malloc(q_depth * sizeof(event_t *));
	if (q == NULL)
		return -1;

	for (i=0; i<q_depth; i++) 
		q[i] = NULL;

	return 0;
}

/* static void change_runlevel(const char *level)
{
	char *argv[3];
	int pid;
	static const char *init_pgm = "/sbin/init";

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ALERT, "Audispd failed to fork switching runlevels");
		return;
	}
	if (pid)	// Parent
		return;
	// Child
	argv[0] = (char *)init_pgm;
	argv[1] = (char *)level;
	argv[2] = NULL;
	execve(init_pgm, argv, NULL);
	syslog(LOG_ALERT, "Audispd failed to exec %s", init_pgm);
	exit(1);
}

static void do_overflow_action(remote_conf_t *config)
{
        switch (config->generic_error_action) // FIXME: overflow action var
        {
                case FA_IGNORE:
			break;
                case FA_SYSLOG:
			syslog(LOG_ERR, "queue is full - dropping event");
                        break;
                case FA_SUSPEND:
                        syslog(LOG_ALERT,
                            "Audispd-remote is suspending event processing due to overflowing its queue.");
                        break;
                case FA_SINGLE:
                        syslog(LOG_ALERT,
                                "Audispd-remote is now changing the system to single user mode due to overflowing its queue");
                        change_runlevel(SINGLE);
                        break;
                case FA_HALT:
                        syslog(LOG_ALERT,
                                "Audispd-remote is now halting the system due to overflowing its queue");
                        change_runlevel(HALT);
                        break;
                default:
                        syslog(LOG_ALERT, "Unknown overflow action requested");
                        break;
        }
} */

void enqueue(event_t *e)
{
	unsigned int n;

	// OK, add event
	n = q_next%q_depth;
	if (q[n] == NULL) {
		q[n] = e;
		q_next = (n+1) % q_depth;
	} else {
// FIXME: overflow
	}
}

event_t *dequeue(int peek)
{
	event_t *e;
	unsigned int n;

	// OK, grab the next event
	n = q_last%q_depth;
	if (q[n] != NULL) {
		e = (event_t *)q[n];
		if (peek == 0) {
			q[n] = NULL;
			q_last = (n+1) % q_depth;
		}
	} else
		e = NULL;

	// Process the event
	return e;
}

/* void increase_queue_depth(unsigned int size)
{
	if (size > q_depth) {
		int i;
		void *tmp_q;

		tmp_q = realloc(q, size * sizeof(event_t *));
		q = tmp_q;
		for (i=q_depth; i<size; i++)
			q[i] = NULL;
		q_depth = size;
	}
} */

int queue_length(void)
{
	if (q_next == q_last)
		return 0;
	if (q_last > q_next)
		return (q_depth + q_next) - q_last;
	else
		return q_next - q_last;
}

void destroy_queue(void)
{
	unsigned int i;

	for (i=0; i<q_depth; i++)
		free((void *)q[i]);

	free(q);
}

