/*
* nvlist.c - Minimal linked list library for name-value pairs
* Copyright (c) 2006-07,2016,2021 Red Hat Inc.
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
#include <string.h>
#include "nvlist.h"
#include "interpret.h"
#include "auparse-idata.h"


void nvlist_create(nvlist *l)
{
	if (l) {
        l->first = NULL;
		l->cur = NULL;
		l->cnt = 0;
		l->record = NULL;
		l->end = NULL;
	}
}

nvnode *nvlist_next(nvlist *l)
{
	if (l->cur && l->cur->next) {
		l->cur = l->cur->next;
		return l->cur;
	}
	return NULL;
}

// 0 on success and 1 on error
int nvlist_append(nvlist *l, nvnode *node)
{
	if (node->name == NULL)
		return 1;

	// FIXME: check new pointer here and in other modules...
	nvnode *newnode = malloc(sizeof(nvnode));
	newnode->name = node->name;
	newnode->val = node->val;
	newnode->interp_val = NULL;
	newnode->item = l->cnt;
	newnode->next = NULL;

	// make sure we append to the end
	if (l->first) {
		if (l->cur) {
			while (l->cur->next)
				l->cur = l->cur->next;
			l->cur->next = newnode;
		}
	} else
		l->first = newnode;

	// make newnode current
	l->cur = newnode;
	l->cnt++;
	return 0;
}

/*
 * Its less code to make a fixup than a new append.
 */
void nvlist_interp_fixup(nvlist *l)
{
	nvnode* node = l->cur;
	if (node) {
		node->interp_val = node->val;
		node->val = NULL;
	}
}

nvnode *nvlist_goto_rec(nvlist *l, unsigned int i)
{
	nvnode *node = l->first;

	if (!node)
		return NULL;

	int n = 0;
	do {
		if (n == i) {
			l->cur = node;
			return node;
		}
		node = node->next;
		n++;
	} while (node);

	return NULL;
}

/*
 * This function will start at current node and scan for a name
 */
int nvlist_find_name(nvlist *l, const char *name)
{
	register nvnode *node = l->cur;

	if (!node)
		return 0;

	do {
		if (node->name && strcmp(node->name, name) == 0) {
			l->cur = node;
			return 1;
		}
		node = node->next;
	} while (node);
	return 0;
}

extern int interp_adjust_type(int rtype, const char *name, const char *val);
int nvlist_get_cur_type(rnode *r)
{
	nvlist *l = &r->nv;
	nvnode *node = l->cur;
    if (node)
        return auparse_interp_adjust_type(r->type, node->name, node->val);
    else
        return AUPARSE_TYPE_UNCLASSIFIED;
}

const char *nvlist_interp_cur_val(rnode *r, auparse_esc_t escape_mode)
{
	nvlist *l = &r->nv;
	nvnode *node = l->cur;
	if (!node)
		return NULL;
	if (node->interp_val)
		return node->interp_val;
	return do_interpret(r, escape_mode);
}

// This function determines if a chunk of memory is part of the parsed up
// record. If it is, do not free it since it gets free'd at the very end.
// NOTE: This function causes invalid-pointer-pair errors with ASAN
static inline int not_in_rec_buf(nvlist *l, const char *ptr)
{
	if (ptr >= l->record && ptr < l->end)
		return 0;
	return 1;
}

// free_interp does not apply to thing coming from interpretation_list
void nvlist_clear(nvlist *l, int free_interp)
{
	register nvnode *current = l->first;

	while (current) {
		if (free_interp) {
			free(current->interp_val);
			// A couple items are not in parsed up list.
			// These all come from the aup_list_append path.
			if (not_in_rec_buf(l, current->name)) {
				// seperms & key values are strdup'ed
				if (not_in_rec_buf(l, current->val))
					free(current->val);
				free(current->name);
			}
		}
		nvnode *next = current->next;
		free(current);
		current = next;
	}
	free((void *)l->record);
	l->record = NULL;
	l->end = NULL;
	l->first = NULL;
	l->cur = NULL;
	l->cnt = 0;
}
