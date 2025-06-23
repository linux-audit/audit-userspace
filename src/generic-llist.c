#include "generic-llist.h"

#include <stdlib.h>
#include <string.h>

static void *default_dup(const void *data, size_t size)
{
	void *n;

	if (data == NULL)
		return NULL;
	n = malloc(size);
	if (n)
		memcpy(n, data, size);
	return n;
}

void list_create(llist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void list_first(llist *l)
{
	l->cur = l->head;
}

void list_last(llist *l)
{
	lnode *node;

	if (l->head == NULL)
		return;

	node = l->head;
	while (node->next)
		node = node->next;
	l->cur = node;
}

lnode *list_next(llist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

int list_append(llist *l, const void *data, size_t size,
				  void *(*dup_fn)(const void *, size_t))
{
	lnode *newnode;

	newnode = malloc(sizeof(*newnode));
	if (newnode == NULL)
		return 1;

	if (data) {
		void *tmp;

		if (dup_fn == NULL)
			tmp = default_dup(data, size);
		else
			tmp = dup_fn(data, size);
		if (tmp == NULL)
		{
			free(newnode);
			return 1;
		}
		newnode->data = tmp;
	} else {
		newnode->data = NULL;
	}

	newnode->size = size;
	newnode->next = NULL;

	if (l->head == NULL)
		l->head = newnode;
	else
		l->cur->next = newnode;

	l->cur = newnode;
	l->cnt++;

	return 0;
}

void list_clear(llist *l, void (*free_fn)(void *))
{
	lnode *nextnode, *current;

	current = l->head;
	while (current) {
		nextnode = current->next;
		if (free_fn)
			free_fn(current->data);
		else
			free(current->data);
		free(current);
		current = nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}
