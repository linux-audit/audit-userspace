/*
* aulast-llist.c - Minimal linked list library
* Copyright (c) 2008 Red Hat Inc., Durham, North Carolina.
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
#include <string.h>
#include "aulast-llist.h"

void list_create(llist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

lnode *list_next(llist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

static void list_append(llist *l, lnode *node)
{
	node->item = l->cnt; 
	node->next = NULL;

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = node;
	else {
		// Make sure we are at the end
		while (l->cur->next)
			l->cur = l->cur->next;

		l->cur->next = node;
	}

	// make newnode current
	l->cur = node;
	l->cnt++;
}

void list_clear(llist* l)
{
	lnode* nextnode;
	register lnode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free((void *)current->host);
		free((void *)current->term);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
}

int list_create_session(llist *l, uid_t auid, int session)
{
	lnode *n = malloc(sizeof(lnode));
	if (n == NULL)
		return 0;
	n->session = session;
	n->start = 0;
	n->end = 0;
	n->auid = auid;
	n->result = -1;
	n->host = NULL;
	n->term = NULL;
	n->status = LOG_IN;
	list_append(l, n);
	return 1;
}

int list_update_start(llist* l, time_t start, const char *host,
	const char *term, int res)
{
        register lnode* cur;
	if (l == NULL)
		return 0;

	cur=list_get_cur(l);
	cur->start = start;
	cur->status = SESSION_START;
	if (host)
		cur->host = strdup(host);
	if (term)
		cur->term = strdup(term);
	cur->result = res;
	return 1;
}

int list_update_logout(llist* l, time_t t)
{
        register lnode* cur;
	if (l == NULL)
		return 0;

	cur=list_get_cur(l);
	cur->end = t;
	cur->status = LOG_OUT;
	return 1;
}

lnode *list_delete_cur(llist *l)
{
        register lnode *cur, *prev;
                                                                                
       	prev = cur = l->head;	/* start at the beginning */
	while (cur) {
		if (cur == l->cur) {
			if (cur == prev && cur == l->head) {
				l->head = cur->next;
				l->cur = cur->next;
				free((void *)cur->host);
				free((void *)cur->term);
				free(cur);
			} else {
				prev->next = cur->next;
				free((void *)cur->host);
				free((void *)cur->term);
				free(cur);
				l->cur = prev;
			}
			return prev;
		} else {
			prev = cur;
			cur = cur->next;
		}
	}
	return NULL;
}

lnode *list_find_auid(llist *l, uid_t auid, unsigned int session)
{
        register lnode* cur;
                                                                                
       	cur = l->head;	/* start at the beginning */
	while (cur) {
		if (cur->auid == auid && cur->session == session) {
			l->cur = cur;
			return cur;
		} else
			cur = cur->next;
	}
	return NULL;
}

