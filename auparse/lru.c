/*
 * lru.c - LRU cache implementation
 * Copyright (c) 2016-17,20 Red Hat Inc.
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
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "lru.h"

//#define DEBUG

// Local declarations
static void dequeue(Queue *queue);
static unsigned int hash_name(const char *name);
static void remove_hash_links(Queue *queue, QNode *node);
static void free_qnode(Queue *queue, QNode *node);
static void evict_lru(Queue *queue);
static QNode *new_QNode(void)
{
	QNode *temp = malloc(sizeof(QNode));
	if (temp == NULL)
		return temp;
	temp->name = NULL;
	temp->uid = (uid_t)-1;
	temp->uses = 1;
	temp->prev = temp->next = NULL;
	return temp;
}

static Hash *create_hash(unsigned int hsize);
static void destroy_hash(Hash *hash);
#ifdef DEBUG
static void dump_queue_stats(const Queue *q)
{
	syslog(LOG_DEBUG, "%s queue size: %u", q->name, q->total);
	syslog(LOG_DEBUG, "%s slots in use: %u", q->name, q->count);
	syslog(LOG_DEBUG, "%s hits: %lu", q->name, q->hits);
	syslog(LOG_DEBUG, "%s misses: %lu", q->name, q->misses);
	syslog(LOG_DEBUG, "%s evictions: %lu", q->name, q->evictions);
}
#endif

static Hash *create_hash(unsigned int hsize)
{
	unsigned int i;
	Hash *hash = malloc(sizeof(Hash));
	if (hash == NULL)
		return hash;

	hash->array = malloc(hsize * sizeof(QNode*));
	if (hash->array == NULL) {
		free(hash);
		return NULL;
	}

	for (i = 0; i < hsize; i++)
		hash->array[i] = NULL;

	return hash;
}

static void destroy_hash(Hash *hash)
{
	free(hash->array);
	free(hash);
}

/*
 * hash_name - djb2 string hash
 * @name: string to hash
 *
 * The djb2 algorithm offers a good balance between speed and
 * distribution for short account names, which makes it a reasonable
 * choice for indexing within the small LRU caches used here.
 */
static unsigned int hash_name(const char *name)
{
	unsigned int h = 5381;
	unsigned char c;
	while ((c = *(const unsigned char *)name++))
		h = ((h << 5) + h) + c;
	return h;
}

static Queue *create_queue(unsigned int qsize, const char *name)
{
	Queue *queue = malloc(sizeof(Queue));
	if (queue == NULL)
		return queue;

	// The queue is empty
	queue->count = 0;
	queue->hits = 0;
	queue->misses = 0;
	queue->evictions = 0;
	queue->front = queue->end = NULL;

	// Number of slots that can be stored in memory
	queue->total = qsize;

	queue->name = name;

	return queue;
}

static void destroy_queue(Queue *queue)
{
#ifdef DEBUG
	dump_queue_stats(queue);
#endif

	// Some static analysis scanners try to flag this as a use after
	// free accessing queue->end. This is a false positive. It is freed.
	// However, static analysis apps are incapable of seeing that in
	// remove_node, end is updated to a prior node as part of detaching
	// the current end node.
	while (queue->count)
		dequeue(queue);

	free(queue);
}

/*static unsigned int are_all_slots_full(const Queue *queue)
{
	return queue->count == queue->total;
}*/

static unsigned int queue_is_empty(const Queue *queue)
{
	return queue->end == NULL;
}

#ifdef DEBUG
static void sanity_check_queue(Queue *q, const char *id)
{
	unsigned int i;
	QNode *n;

	if (q == NULL) {
		syslog(LOG_DEBUG, "%s - q is NULL", id);
		abort();
	}

	n = q->front;
	if (n == NULL)
		return;

	// Walk bottom to top
	i = 0;
	while (n->next) {
		if (n->next->prev != n) {
			syslog(LOG_DEBUG, "%s - corruption found %u", id, i);
			abort();
		}
		if (i == q->count) {
			syslog(LOG_DEBUG, "%s - forward loop found %u", id, i);
			abort();
		}
		i++;
		n = n->next;
	}

	// Walk top to bottom
	n = q->end;
	while (n->prev) {
		if (n->prev->next != n) {
			syslog(LOG_DEBUG, "%s - Corruption found %u", id, i);
			abort();
		}
		if (i == 0) {
			syslog(LOG_DEBUG, "%s - backward loop found %u", id, i);
			abort();
		}
		i--;
		n = n->prev;
	}
}
#else
#define sanity_check_queue(a, b) do {} while(0)
#endif

static void insert_before(Queue *queue, QNode *node, QNode *new_node)
{
	sanity_check_queue(queue, "1 insert_before");
	if (queue == NULL || node == NULL || new_node == NULL)
		return;

	new_node->prev = node->prev;
	new_node->next  = node;
	if (node->prev == NULL)
		queue->front = new_node;
	else
		node->prev->next = new_node;
	node->prev = new_node;
	sanity_check_queue(queue, "2 insert_before");
}

static void insert_beginning(Queue *queue, QNode *new_node)
{
	sanity_check_queue(queue, "1 insert_beginning");
	if (queue == NULL || new_node == NULL)
		return;

	if (queue->front == NULL) {
		queue->front = new_node;
		queue->end = new_node;
		new_node->prev = NULL;
		new_node->next = NULL;
	} else
		insert_before(queue, queue->front, new_node);
	sanity_check_queue(queue, "2 insert_beginning");
}

static void remove_node(Queue *queue, const QNode *node)
{
	// If we are at the beginning
	sanity_check_queue(queue, "1 remove_node");
	if (node->prev == NULL) {
		queue->front = node->next;
		if (queue->front)
			queue->front->prev = NULL;
		goto out;
	} else {
		if (node->prev->next != node) {
#ifdef DEBUG
			syslog(LOG_ERR, "Linked list corruption detected %s",
				queue->name);
#endif
			abort();
		}
		node->prev->next = node->next;
	}

	// If we are at the end
	if (node->next == NULL) {
		queue->end = node->prev;
		if (queue->end)
			queue->end->next = NULL;
	} else {
		if (node->next->prev != node) {
#ifdef DEBUG
			syslog(LOG_ERR, "Linked List corruption detected %s",
				queue->name);
#endif
			abort();
		}
		node->next->prev = node->prev;
	}
out:
	sanity_check_queue(queue, "2 remove_node");
}

static void remove_hash_links(Queue *queue, QNode *node)
{
	unsigned int key;
	if (node->uid != (uid_t)-1) {
		key = node->uid % queue->total;
		if (queue->uid_hash->array[key] == node)
			queue->uid_hash->array[key] = NULL;
	}
	if (node->name) {
		key = hash_name(node->name) % queue->total;
		if (queue->name_hash->array[key] == node)
			queue->name_hash->array[key] = NULL;
	}
}

static void free_qnode(Queue *queue, QNode *node)
{
	remove_hash_links(queue, node);
	remove_node(queue, node);
	free(node->name);
	free(node);
	queue->count--;
}

static void evict_lru(Queue *queue)
{
	if (queue_is_empty(queue))
		return;
	free_qnode(queue, queue->end);
	queue->evictions++;
}

// Remove from the end of the queue
static void dequeue(Queue *queue)
{
	if (queue_is_empty(queue))
		return;

	free_qnode(queue, queue->end);
}


/*
 * check_lru_uid - find or create cache entry for a uid
 * @queue: cache queue to search
 * @uid:   uid to locate
 *
 * Looks up the uid in the uid_hash table. On a hit the node is moved
 * to the front of the queue and returned. On a miss a new node is
 * allocated at the front of the queue, evicting the least recently
 * used entry if necessary.
 */
QNode *check_lru_uid(Queue *queue, uid_t uid)
{
	QNode *node;
	unsigned int key;

	if (queue == NULL)
		return NULL;

	key = uid % queue->total;
	node = queue->uid_hash->array[key];

	if (node && node->uid == uid) {
		if (node != queue->front) {
			remove_node(queue, node);
			insert_beginning(queue, node);
		}
		node->uses++;
		queue->hits++;
		return node;
	}

	queue->misses++;

	if (node)
		free_qnode(queue, node);
	else if (queue->count == queue->total)
		evict_lru(queue);

	node = new_QNode();
	if (node == NULL)
		return NULL;
	node->uid = uid;
	insert_beginning(queue, node);
	queue->uid_hash->array[key] = node;
	queue->count++;
	return node;
}

/*
 * check_lru_name - find or create cache entry for a name
 * @queue: cache queue to search
 * @name:  user name to locate
 *
 * Uses the djb2 hash to index into the name_hash table. On a hit the
 * node is moved to the front of the queue and returned. On a miss a
 * new node with the provided name is allocated and inserted at the
 * front, evicting the least recently used entry if the cache is full.
 */
QNode *check_lru_name(Queue *queue, const char *name)
{
	QNode *node;
	unsigned int key;

	if (queue == NULL || name == NULL)
		return NULL;

	key = hash_name(name) % queue->total;
	node = queue->name_hash->array[key];

	if (node && node->name && strcmp(node->name, name) == 0) {
		if (node != queue->front) {
			remove_node(queue, node);
			insert_beginning(queue, node);
		}
		node->uses++;
		queue->hits++;
		return node;
	}

	queue->misses++;

	if (node)
		free_qnode(queue, node);
	else if (queue->count == queue->total)
		evict_lru(queue);

	node = new_QNode();
	if (node == NULL)
		return NULL;
	node->name = strdup(name);
	if (node->name == NULL) {
		free(node);
		return NULL;
	}
	insert_beginning(queue, node);
	queue->name_hash->array[key] = node;
	queue->count++;
	return node;
}

/*
 * init_lru - create a dual-key LRU cache
 * @qsize:   maximum number of entries in the cache
 * @cleanup: optional callback to free user data
 * @name:    identifier used in debug messages
 *
 * Allocates a queue with parallel hash tables: uid_hash is indexed by
 * simple modulo of the uid and name_hash uses the djb2 string hash.
 */
Queue *init_lru(unsigned int qsize, void (*cleanup)(void *),
		const char *name)
{
	Queue *q = create_queue(qsize, name);
	if (q == NULL)
		return q;

	q->cleanup = cleanup;
	q->uid_hash = create_hash(qsize);
	q->name_hash = create_hash(qsize);
	if (q->uid_hash == NULL || q->name_hash == NULL) {
		if (q->uid_hash)
			destroy_hash(q->uid_hash);
		if (q->name_hash)
			destroy_hash(q->name_hash);
		free(q);
		return NULL;
	}

	return q;
}

void destroy_lru(Queue *queue)
{
	Hash *uid_hash, *name_hash;

	if (queue == NULL)
		return;

	uid_hash = queue->uid_hash;
	name_hash = queue->name_hash;
	destroy_queue(queue);
	destroy_hash(uid_hash);
	destroy_hash(name_hash);
}
