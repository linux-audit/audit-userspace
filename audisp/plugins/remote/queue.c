/* queue.c --
 * Copyright 2009, 2011 Red Hat Inc., Durham, North Carolina.
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
#include "queue.h"

static volatile event_t **q;
static unsigned int q_next, q_last, q_depth;

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

int enqueue(event_t *e)
{
	unsigned int n;

	// OK, add event
	n = q_next%q_depth;
	if (q[n] == NULL) {
		q[n] = e;
		q_next = (n+1) % q_depth;
		return 0;
	} else {
		free(e);
		return -1;
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

