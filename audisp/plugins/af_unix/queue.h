/* queue.h -- a queue abstraction
 * Copyright 2009, 2011 Red Hat Inc.
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
 *      Miloslav Trma\u010d <mitr@redhat.com>
 */

#ifndef QUEUE_HEADER
#define QUEUE_HEADER

#include <sys/types.h>
#include "common.h"   // attribute decls

struct queue;

/* Close Q. */
void q_close(struct queue *q);

/* Open a queue with NUM_ENTRIES slots capable of holding buffers up to
 * ENTRY_SIZE bytes. On error, return NULL and set errno. */
struct queue *q_open(size_t num_entries, size_t entry_size)
        __attribute_malloc__ __attr_dealloc(q_close, 1) __wur;

/* Add DATA of LEN bytes to tail of Q. Return 0 on success, -1 on error and set
 * errno. */
int q_append(struct queue *q, const void *data, size_t len)
        __attr_access ((__read_only__, 2, 3));

/* Peek at head of Q, returning a pointer to DATA with LEN bytes. Return 1 if
 * an entry exists, 0 if queue is empty. On error, return -1 and set errno. */
int q_peek(struct queue *q, const unsigned char **data, size_t *len);

/* Drop head of Q and return 0. On error, return -1 and set errno. */
int q_drop_head(struct queue *q);

/* Return the number of entries in Q. */
size_t q_queue_length(const struct queue *q);

/* Return 1 if Q is empty, 0 otherwise. */
int q_empty(const struct queue *q);

#endif

