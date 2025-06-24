#include "generic-llist.h"

#include <stdlib.h>
#include <string.h>

void list_create(llist *l, void (*free_fn)(void *))
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	l->free_fn = free_fn;
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

int list_append(llist *l, const void *data, size_t size)
{
	lnode *newnode;

	newnode = malloc(sizeof(*newnode));
	if (newnode == NULL)
		return 1;

	newnode->data = (void *)data;
	newnode->size = size;
	newnode->next = NULL;
	newnode->prev = l->cur;

	if (l->head == NULL) {
		l->head = newnode;
	}
	else {
		l->cur->next = newnode;
	}

	l->cur = newnode;
	l->cnt++;

	return 0;
}

void list_remove_node(llist *l, lnode *node)
{
	if (l == NULL || node == NULL)
		return;

	if (node->prev)
		node->prev->next = node->next;
	else
		l->head = node->next;

	if (node->next)
		node->next->prev = node->prev;

	if (l->cur == node)
		l->cur = node->prev ? node->prev : node->next;

	l->free_fn(node->data);
	free(node);
	l->cnt--;
}

void list_clear(llist *l)
{
	lnode *current, *next;

	current = l->head;
	while (current) {
		next = current->next;
		list_remove_node(l, current);
		current = next;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void list_delete_cur(llist *l)
{
	if (l == NULL || l->cur == NULL)
		return;

	list_remove_node(l, l->cur);
}

int list_update_cur(llist *l, void (*update_fn)(void *))
{
	if (l == NULL || l->cur == NULL || update_fn == NULL)
		return 1;

	update_fn(l->cur->data);

	return 0;
}

lnode *list_find(llist *l, const void *data,
				 int (*cmp_fn)(const void *, const void *))
{
	lnode *node = l->head;

	while (node) {
		if (cmp_fn(node->data, data) == 0) {
			l->cur = node;
			return node;
		}
		node = node->next;
	}

	return NULL;
}
