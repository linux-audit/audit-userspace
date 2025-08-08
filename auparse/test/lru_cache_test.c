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
