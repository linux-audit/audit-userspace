/*
* nvpair.c - Minimal linked list library for name-value pairs
* Copyright (c) 2007-08 Red Hat Inc., Durham, North Carolina.
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
#include "nvpair.h"


void nvpair_create(nvpair *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

void nvpair_append(nvpair *l, nvpnode *node)
{
	nvpnode* newnode = malloc(sizeof(nvpnode));

	newnode->name = node->name;
	newnode->val = node->val;
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = newnode;
	else {	// Otherwise add pointer to newnode
		while (l->cur->next)
			l->cur = l->cur->next;
		l->cur->next = newnode;
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

int nvpair_find_val(nvpair *l, long val)
{
        register nvpnode* window = l->head;

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

void nvpair_clear(nvpair *l)
{
	nvpnode* nextnode;
	register nvpnode* current;

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

