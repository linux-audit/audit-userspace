/* queue.c - a simple in-memory queue implementation
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
 *      Miloslav Trmač <mitr@redhat.com>
 */

#include "config.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"

struct q_entry {
    unsigned char *data;
    size_t len;
};

struct queue {
    size_t head;
    size_t len;
    size_t num_entries;
    size_t entry_size;
    struct q_entry *entries;
};

/* Open a queue with NUM_ENTRIES slots each capable of holding up to ENTRY_SIZE
 * bytes. On error, return NULL and set errno. */
struct queue *q_open(size_t num_entries, size_t entry_size)
{
    struct queue *q;

    if (num_entries == 0 || entry_size == 0) {
        errno = EINVAL;
        return NULL;
    }

    q = calloc(1, sizeof(*q));
    if (q == NULL)
        return NULL;

    q->entries = calloc(num_entries, sizeof(*q->entries));
    if (q->entries == NULL) {
        free(q);
        return NULL;
    }

    q->num_entries = num_entries;
    q->entry_size = entry_size;
    return q;
}

/* Close Q. */
void q_close(struct queue *q)
{
    size_t i;

    if (q == NULL)
        return;

    for (i = 0; i < q->num_entries; i++)
        free(q->entries[i].data);

    free(q->entries);
    free(q);
}

/* Add DATA of LEN bytes to tail of Q. Return 0 on success, -1 on error and set
 * errno. */
int q_append(struct queue *q, const void *data, size_t len)
{
    struct q_entry *e;
    unsigned char *copy;
    size_t idx;

    if (q->len == q->num_entries) {
        errno = ENOSPC;
        return -1;
    }
    if (len > q->entry_size) {
        errno = EINVAL;
        return -1;
    }

    copy = malloc(len);
    if (copy == NULL)
        return -1;
    memcpy(copy, data, len);

    idx = (q->head + q->len) % q->num_entries;
    e = &q->entries[idx];
    e->data = copy;
    e->len = len;
    q->len++;
    return 0;
}

/* Peek at head of Q, storing it into BUF of SIZE. Return 1 if an entry exists,
 * 0 if queue is empty. On error, return -1 and set errno. */
int q_peek(struct queue *q, void *buf, size_t size)
{
    struct q_entry *e;

    if (q->len == 0)
        return 0;

    e = &q->entries[q->head];
    if (size < e->len) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, e->data, e->len);
    return e->len;
}

/* Drop head of Q and return 0. On error, return -1 and set errno. */
int q_drop_head(struct queue *q)
{
    struct q_entry *e;

    if (q->len == 0) {
        errno = EINVAL;
        return -1;
    }

    e = &q->entries[q->head];
    free(e->data);
    e->data = NULL;
    e->len = 0;
    q->head++;
    if (q->head == q->num_entries)
        q->head = 0;
    q->len--;
    return 0;
}

/* Return the number of entries in Q. */
size_t q_queue_length(const struct queue *q)
{
    return q->len;
}

/* Return 1 if Q is empty, 0 otherwise. */
int q_empty(const struct queue *q)
{
    return q->len == 0;
}

