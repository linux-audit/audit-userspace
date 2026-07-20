/* lru_cache_test.c -- auparse LRU cache tests
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
 */

#include "config.h"
#include "lru.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Simple exercise of the LRU cache internals */

/* free_name - release a cached name */
static void free_name(void *p)
{
	free(p);
}

/*
 * main - run basic LRU cache checks
 *
 * Returns 0 on success or aborts on failure.
 */
int main(void)
{
	Queue *q = init_lru(2, free_name, "test");
	assert(q);

	/* Seed first entry by name and backfill uid */
	QNode *u1 = check_lru_name(q, "user1");
	assert(u1 && u1->name && strcmp(u1->name, "user1") == 0);
	u1->uid = 1;
	q->uid_hash->array[u1->uid % q->total] = u1;

	/* Second entry */
	QNode *u2 = check_lru_name(q, "user2");
	assert(u2 && u2->name && strcmp(u2->name, "user2") == 0);
	u2->uid = 2;
	q->uid_hash->array[u2->uid % q->total] = u2;

	/* UID lookups hit existing nodes */
	unsigned long hits = q->hits;
	assert(check_lru_uid(q, 1) == u1);
	assert(check_lru_uid(q, 2) == u2);
	assert(q->hits == hits + 2);

	/* Miss for unknown uid */
	unsigned long misses = q->misses;
	QNode *u3 = check_lru_uid(q, 3);
	assert(u3 && u3->uid == 3 && u3->name == NULL);
	assert(q->misses == misses + 1);

	destroy_lru(q);
	return 0;
}
