#ifndef GENERIC_LLIST_H
#define GENERIC_LLIST_H

#include <stddef.h>

typedef struct lnode
{
	void *data;					/* Pointer to node data */
	size_t size;				/* Size of data buffer */
	struct lnode *next;	/* Next node pointer */
} lnode;

typedef struct llist
{
	lnode *head;	/* List head */
	lnode *cur;	/* Current node */
	unsigned int cnt;	/* Number of nodes */
} llist;

void list_create(llist *l);
void list_first(llist *l);
void list_last(llist *l);
lnode *list_next(llist *l);
static inline lnode *list_get_cur(const llist *l)
{
	return l->cur;
}
int list_append(llist *l, const void *data, size_t size,
					void *(*dup_fn)(const void *, size_t));
void list_clear(llist *l, void (*free_fn)(void *));

#endif /* GENERIC_LLIST_H */
