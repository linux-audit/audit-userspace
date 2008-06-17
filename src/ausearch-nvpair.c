/*
* ausearch-nvpair.c - Minimal linked list library for name-value pairs
* Copyright (c) 2006-07 Red Hat Inc., Durham, North Carolina.
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
#include "ausearch-nvpair.h"


void nvlist_create(nvlist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void nvlist_last(nvlist *l)
{
        register nvnode* window;
	
	if (l->head == NULL)
		return;

        window = l->head;
	while (window->next)
		window = window->next;
	l->cur = window;
}

nvnode *nvlist_next(nvlist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

nvnode *nvlist_prev(nvlist *l)
{
	if (l->cur == NULL)
		return NULL;

	if (l->cur->item <= 0)
		return NULL;

	nvlist_find_item(l, l->cur->item-1);
	return l->cur;
}

void nvlist_append(nvlist *l, nvnode *node)
{
	nvnode* newnode = malloc(sizeof(nvnode));

	newnode->name = node->name;
	newnode->val = node->val;
	newnode->item = l->cnt; 
	newnode->hits = node->hits;
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else {	// Otherwise add pointer to newnode
		if (l->cnt == (l->cur->item+1)) {
			l->cur->next = newnode;
		}
		else {
			nvlist_last(l);
			l->cur->next = newnode;
		}
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

int nvlist_find_item(nvlist *l, unsigned int i)
{
        register nvnode* window;
                                                                                
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

int nvlist_find_val(nvlist *l, long val)
{
        register nvnode* window = l->head;

	while (window) {
		if (window->val == val) {
			l->cur = window;
			return 1;
		}
		else
			window = window->next;
	}
	return 0;
}

void nvlist_clear(nvlist* l)
{
	nvnode* nextnode;
	register nvnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->name);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

