#ifndef GENERIC_LLIST_H
#define GENERIC_LLIST_H

#include <stddef.h>

typedef struct lnode
{
	void *data; /* Pointer to node data */
	size_t size; /* Size of data buffer */
	struct lnode *next;	/* Next node pointer */
	struct lnode *prev;	/* Previous node pointer */
} lnode;

typedef struct llist
{
	lnode *head; /* List head */
	lnode *cur;	/* Current node */
	unsigned int cnt; /* Number of nodes */
	void (*free_fn)(void *); /* Function to free node data */
} llist;

void list_create(llist *l, void (*free_fn)(void *));
void list_first(llist *l);
void list_last(llist *l);
lnode *list_next(llist *l);
static inline lnode *list_get_cur(const llist *l)
{
	return l->cur;
}
static inline void *list_get_cur_data(const llist *l)
{
	return l->cur ? l->cur->data : NULL;
}
int list_append(llist *l, const void *data, size_t size);
void list_remove_node(llist *l, lnode *node);
void list_delete_cur(llist *l);
int list_update_cur(llist *l, void (*update_fn)(void *));
lnode *list_find(llist *l, const void *data,
				 int (*cmp_fn)(const void *, const void *));
void list_clear(llist *l);

#endif /* GENERIC_LLIST_H */
