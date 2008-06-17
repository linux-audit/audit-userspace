/*
* ausearch-int.c - Minimal linked list library for integers
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
#include "ausearch-int.h"

void ilist_create(ilist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void ilist_last(ilist *l)
{
        register int_node* window;
	
	if (l->head == NULL)
		return;

        window = l->head;
	while (window->next)
		window = window->next;
	l->cur = window;
}

int_node *ilist_next(ilist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

int_node *ilist_prev(ilist *l)
{
	if (l->cur == NULL)
		return NULL;

	if (l->cur->item <= 0)
		return NULL;

	ilist_find_item(l, l->cur->item-1);
	return l->cur;
}

void ilist_append(ilist *l, int num, unsigned int hits, int aux)
{
	int_node* newnode;

	newnode = malloc(sizeof(int_node));

	newnode->num = num;
	newnode->hits = hits;
	newnode->aux1 = aux;
	newnode->item = l->cnt; 
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

int ilist_find_item(ilist *l, unsigned int i)
{
        register int_node* window;
                                                                                
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

void ilist_clear(ilist* l)
{
	int_node* nextnode;
	register int_node* current;

	if (l == NULL)
		return;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

int ilist_add_if_uniq(ilist *l, int num, int aux)
{
	register int_node* cur;

	cur = l->head;
	while (cur) {
		if (cur->num == num) {
			cur->hits++;
			return 0;
		}
		else
			cur = cur->next;
	}

	/* No matches, append to the end */
	ilist_append(l, num, 1, aux);
	return 1;
}

void ilist_sort_by_hits(ilist *l)
{
	register int_node* cur, *prev = NULL;

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
			ilist_append(l, cur->num, cur->hits, cur->aux1);
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

