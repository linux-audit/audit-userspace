/* queue.h --
 * Copyright 2007,2018,2025 Red Hat Inc.
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

#ifndef QUEUE_HEADER
#define QUEUE_HEADER

#include <stdio.h>
#include <time.h>
#include "dso.h"
#include "libdisp.h"
#include "audispd-config.h"

enum {
	Q_IN_MEMORY = 1 << 0,
	Q_IN_FILE   = 1 << 1,
	Q_CREAT     = 1 << 2,
	Q_EXCL      = 1 << 3,
	Q_SYNC      = 1 << 4,
	Q_RESIZE    = 1 << 5,
};

AUDIT_HIDDEN_START
void reset_suspended(void);
int init_queue(unsigned int size);
int init_queue_extended(unsigned int size, int flags, const char *path);
int enqueue(event_t *e, struct disp_conf *config);
event_t *dequeue(void);
event_t *dequeue_timed(const struct timespec *timeout);
void nudge_queue(void);
void increase_queue_depth(unsigned int size);
void write_queue_state(FILE *f);
void resume_queue(void);
void destroy_queue(void);
unsigned int queue_current_depth(void);
unsigned int queue_max_depth(void);
int queue_overflowed_p(void);
AUDIT_HIDDEN_END

#endif

