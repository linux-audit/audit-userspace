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

static inline void alloc_array(nvlist *l)
{
		l->array = calloc(NFIELDS, sizeof(nvnode));
		l->size = NFIELDS;
}

void nvlist_create(nvlist *l)
{
	if (l) {
		alloc_array(l);
		l->cur = 0;
		l->cnt = 0;
		l->record = NULL;
		l->end = NULL;
	}
}

nvnode *nvlist_next(nvlist *l)
{
	// Since cur will be incremented, check for 1 less that total
	if (l->cnt && l->cur < (l->cnt - 1)) {
		l->cur++;
		return &l->array[l->cur];
	}
	return NULL;
}

// 0 on success and 1 on error
int nvlist_append(nvlist *l, const nvnode *node)
{
	if (node->name == NULL)
		return 1;

	if (l->array == NULL)
		alloc_array(l);

	if (l->cnt == l->size) {
		l->array = realloc(l->array, l->size * sizeof(nvnode) * 2);
		memset(l->array + l->size, 0, sizeof(nvnode) * l->size);
		l->size = l->size * 2;
	}

	nvnode *newnode = &l->array[l->cnt];
	newnode->name = node->name;
	newnode->val = node->val;
	newnode->interp_val = NULL;
	newnode->item = l->cnt;

	// make newnode current
	l->cur = l->cnt;
	l->cnt++;
	return 0;
}

/*
 * Its less code to make a fixup than a new append.
 */
void nvlist_interp_fixup(const nvlist *l)
{
	nvnode* node = &l->array[l->cur];
	node->interp_val = node->val;
	node->val = NULL;
}

nvnode *nvlist_goto_rec(nvlist *l, unsigned int i)
{
	if (i < l->cnt) {
		l->cur = i;
		return &l->array[l->cur];
	}
	return NULL;
}

/*
 * This function will start at current index and scan for a name
 */
int nvlist_find_name(nvlist *l, const char *name)
{
	unsigned int i = l->cur;
	register nvnode *node;

	if (l->cnt == 0)
		return 0;

	do {
		node = &l->array[i];
		if (node->name && strcmp(node->name, name) == 0) {
			l->cur = i;
			return 1;
		}
		i++;
	} while (i < l->cnt);
	return 0;
}

extern int interp_adjust_type(int rtype, const char *name, const char *val);
int nvlist_get_cur_type(rnode *r)
{
	nvlist *l = &r->nv;
	nvnode *node = &l->array[l->cur];
	return auparse_interp_adjust_type(r->type, node->name, node->val);
}

const char *nvlist_interp_cur_val(rnode *r, auparse_esc_t escape_mode)
{
	nvlist *l = &r->nv;
	if (l->cnt == 0)
		return NULL;
	nvnode *node = &l->array[l->cur];
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
	unsigned int i = 0;
	register nvnode *current;

	while (i < l->cnt) {
		current = &l->array[i];
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
		i++;
	}

	free((void *)l->record);

	free(l->array);
	l->array = NULL;
	l->size = 0;

	l->record = NULL;
	l->end = NULL;
	l->cur = 0;
	l->cnt = 0;
}
