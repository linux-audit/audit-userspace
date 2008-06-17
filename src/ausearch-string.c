/*
* ausearch-string.c - Minimal linked list library for strings
* Copyright (c) 2005 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved. 
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "ausearch-string.h"


void slist_create(slist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void slist_last(slist *l)
{
        register snode* window;
	
	if (l->head == NULL)
		return;

        window = l->head;
	while (window->next)
		window = window->next;
	l->cur = window;
}

snode *slist_next(slist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

snode *slist_prev(slist *l)
{
	if (l->cur == NULL)
		return NULL;

	if (l->cur->item <= 0)
		return NULL;

	slist_find_item(l, l->cur->item-1);
	return l->cur;
}

void slist_append(slist *l, snode *node)
{
	snode* newnode;

	newnode = malloc(sizeof(snode));

	if (node->str)
		newnode->str = node->str;
	else
		newnode->str = NULL;

	if (node->key)
		newnode->key = node->key;
	else
		newnode->key = NULL;

	newnode->item = l->cnt; 
	newnode->hits = node->hits;
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else	// Otherwise add pointer to newnode
		l->cur->next = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

/* void slist_add_key(slist *l, const char *key)
{
	if (l && l->cur) {
		free(l->cur->key);
		l->cur->key = strdup(key);
	}
} */

int slist_find_item(slist *l, unsigned int i)
{
        register snode* window;
                                                                                
	if (l->cur && (l->cur->item <= i))
		window = l->cur;	/* Try to use where we are */
	else
        	window = l->head;	/* Can't, start over */

	while (window) {
		if (window->item == i) {
			l->cur = window;
			return 1;
		}
		else
			window = window->next;
	}
	return 0;
}

void slist_clear(slist* l)
{
	snode* nextnode;
	register snode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->str);
		free(current->key);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

/* This function dominates the timing of aureport. Needs to be more efficient */
int slist_add_if_uniq(slist *l, const char *str)
{
	snode sn;
        register snode* window;

       	window = l->head;
	while (window) {
		if (strcmp(str, window->str) == 0) {
			window->hits++;
			return 0;
		}
		else
			window = window->next;
	}

	/* No matches, append to the end */
	sn.str = strdup(str);
	sn.key = NULL;
	sn.hits = 1;
	slist_append(l, &sn);
	return 1;
}

void slist_sort_by_hits(slist *l)
{
	register snode* cur, *prev = NULL;

	if (l->cnt <= 1)
		return;

	cur = l->head;

	/* Make sure l->cur points to end */
	if (l->cur->next != NULL) {
		prev = l->cur->next;
		while (prev->next)
			prev = prev->next;
		l->cur = prev;
	}

	while (cur && cur->next) {
		/* If the next node is bigger */
		if (cur->hits < cur->next->hits) {
			// detach node
			if (l->head == cur)
				l->head = cur->next;
			if (prev)
				prev->next = cur->next;
			else
				prev = cur->next;

			// append
			slist_append(l, cur);
			free(cur);

			// start over
			cur = l->head;
			prev = NULL;
			continue;
		}
		prev = cur;
		cur = cur->next;
	}
}

