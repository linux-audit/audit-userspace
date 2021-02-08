/*
* nvpair.c - Minimal linked list library for arg-jobue pairs
* Copyright (c) 2019 Steve Grubb.
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
* Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
* Boston, MA 02110-1335, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdlib.h>
#include "nvpair.h"


void nvpair_list_create(nvlist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->prev = NULL;
	l->cnt = 0;
}

/*nvnode *nvlist_next(nvlist *l)
{
	if (l->cur == NULL) {
		l->prev = NULL;
		return NULL;
	}
	l->prev = l->cur;
	l->cur = l->cur->next;
	return l->cur;
}*/

void nvpair_list_append(nvlist *l, nvnode *node)
{
	nvnode* newnode = malloc(sizeof(nvnode));

	newnode->arg = node->arg;
	newnode->job = node->job;
	newnode->expiration = node->expiration;
	newnode->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL) {
		l->head = newnode;
		l->prev = NULL;
	} else { // Add pointer to newnode and make sure we are at the end
		while (l->cur->next) {
			l->prev = l->cur;
			l->cur = l->cur->next;
		}
		l->cur->next = newnode;
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

int nvpair_list_find_job(nvlist *l, time_t t)
{
        nvnode* node = l->head;
	l->prev = NULL;

	while (node) {
		if (node->expiration < t) {
			l->cur = node;
			return 1;
		}
		else {
			l->prev = node;
			node = node->next;
		}
	}
	return 0;
}

void nvpair_list_delete_cur(nvlist *l)
{
	if (l->cur == NULL)
		return;
	
	if (l->cur == l->head) {
		l->head = l->cur->next;
		l->prev = NULL;
	} else if (l->prev)
		l->prev->next = l->cur->next;

	free(l->cur->arg);
	free(l->cur);
	l->cnt--;
}

void nvpair_list_clear(nvlist* l)
{
	nvnode* nextnode;
	nvnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->arg);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->prev = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

