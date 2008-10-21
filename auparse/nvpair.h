/*
* nvpair.h - Header file for nvpair.c
* Copyright (c) 2007-08 Red Hat Inc., Durham, North Carolina.
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

#ifndef NVPAIR_HEADER
#define NVPAIR_HEADER

#include "config.h"
#include "private.h"
#include <sys/types.h>

/* This is the node of the linked list. Any data elements that are
 * per item goes here. */
typedef struct _nvpnode{
  char *name;			// The name string
  long val;			// The value field
  struct _nvpnode* next;	// Next nvpair node pointer
} nvpnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  nvpnode *head;	// List head
  nvpnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} nvpair;

void nvpair_create(nvpair *l) hidden;
static inline void nvpair_first(nvpair *l) { l->cur = l->head; }
static inline nvpnode *nvpair_get_cur(nvpair *l) { return l->cur; }
void nvpair_append(nvpair *l, nvpnode *node) hidden;
void nvpair_clear(nvpair *l) hidden;
int nvpair_find_val(nvpair *l, long val) hidden;


#endif

