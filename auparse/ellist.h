/*
* ellist.h - Header file for ellist.c
* Copyright (c) 2006-07 Red Hat Inc., Durham, North Carolina.
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

#ifndef ELLIST_HEADER
#define ELLIST_HEADER

#include "config.h"
#include "private.h"
#include "auparse-defs.h"
#include <sys/types.h>
#include "nvlist.h"

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
	rnode *head;		// List head
	rnode *cur;		// Pointer to current node
	unsigned int cnt;	// How many items in this list

	// Data we add as 1 per event
	au_event_t e;		// event - time & serial number
} event_list_t;

void aup_list_create(event_list_t *l) hidden;
void aup_list_clear(event_list_t* l) hidden;
static inline unsigned int aup_list_get_cnt(event_list_t *l) { return l->cnt; }
static inline void aup_list_first(event_list_t *l) { l->cur = l->head; }
static inline rnode *aup_list_get_cur(event_list_t *l) { return l->cur; }
rnode *aup_list_next(event_list_t *l) hidden;
int aup_list_append(event_list_t *l, char *record, int list_idx, unsigned int line_number) hidden;
//int aup_list_get_event(event_list_t* l, au_event_t *e) hidden;
int aup_list_set_event(event_list_t* l, au_event_t *e) hidden;

/* Given a message type, find the matching node */
rnode *aup_list_find_rec(event_list_t *l, int i) hidden;

/* Seek to a specific record number */
rnode *aup_list_goto_rec(event_list_t *l, int i) hidden;

/* Given two message types, find the first matching node */
rnode *aup_list_find_rec_range(event_list_t *l, int low, int high) hidden;

int aup_list_first_field(event_list_t *l) hidden;

#endif

