/*
* normalize-llist.c - Minimal linked list library
* Copyright (c) 2016-17 Red Hat Inc., Durham, North Carolina.
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

#include <stdlib.h>
#include "normalize-llist.h"

void cllist_create(cllist *l, void (*cleanup)(void *))
{
	l->head = NULL;
	l->cur = NULL;
	l->cleanup = cleanup;
	l->cnt = 0;
}

void cllist_clear(cllist *l)
{
	data_node *nextnode;
	register data_node *current;

	if (l == NULL)
		return;

	current = l->head;
	while (current) {
		nextnode = current->next;
		if (l->cleanup)
			l->cleanup(current->data);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

data_node *cllist_next(cllist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void cllist_append(cllist *l, uint32_t num, void *data)
{
	data_node *newnode;

	newnode = malloc(sizeof(data_node));

	newnode->num = num;
	newnode->data = data;
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

