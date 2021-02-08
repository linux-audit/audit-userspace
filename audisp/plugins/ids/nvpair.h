/*
* nvpair.h - Header file for ausearch-nvpair.c
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

#ifndef AUNVPAIR_HEADER
#define AUNVPAIR_HEADER

#include <sys/types.h>
#include <time.h>
#include "timer-services.h"

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _nvnode{
  jobs_t job;		// The job to run
  char *arg;		// The argument string
  time_t expiration;	// The time when the job can be run
  struct _nvnode *next;	// Next nvpair node pointer
} nvnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  nvnode *head;		// List head
  nvnode *cur;		// Pointer to current node
  nvnode *prev;		// Pointer to previous node
  unsigned int cnt;	// How many items in this list
} nvlist;

void nvpair_list_create(nvlist *l);
static inline void nvlist_first(nvlist *l) { l->cur = l->head; }
//nvnode *nvlist_next(nvlist *l);
static inline nvnode *nvpair_list_get_cur(nvlist *l) { return l->cur; }
void nvpair_list_append(nvlist *l, nvnode *node);
void nvpair_list_delete_cur(nvlist *l);
void nvpair_list_clear(nvlist* l);

/* Given a time, find a job to run. */
int nvpair_list_find_job(nvlist *l, time_t t);

#endif

