/*
* aulast-llist.h - Header file for aulastlog-llist.c
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

#ifndef AULASTLIST_HEADER
#define AULASTLIST_HEADER

#include <sys/types.h>


typedef enum { LOG_IN, SESSION_START, LOG_OUT, DOWN, CRASH, GONE } status_t; 

/* This is the node of the linked list. message & item are the only elements
 * at this time. Any data elements that are per item goes here. */
typedef struct _lnode{
  unsigned int session; // The kernel login session id
  time_t start;		// first time uid logged in
  time_t end;		// last time uid logged in
  uid_t auid;           // user ID
  const char *term;	// terminal name
  const char *host;	// host where logging in from
  int result;		// login results
  status_t status;	// Current status of this session
  unsigned int item;	// Which item of the same event
  struct _lnode* next;	// Next node pointer
} lnode;

/* This is the linked list head. Only data elements that are 1 per
 * event goes here. */
typedef struct {
  lnode *head;		// List head
  lnode *cur;		// Pointer to current node
  unsigned int cnt;	// How many items in this list
} llist;

void list_create(llist *l);
static inline void list_first(llist *l) { l->cur = l->head; }
lnode *list_next(llist *l);
static inline lnode *list_get_cur(llist *l) { return l->cur; }
static inline unsigned int list_get_cnt(llist *l) { return l->cnt; }
void list_clear(llist* l);
int list_create_session(llist* l, uid_t auid, int session);
int list_update_start(llist* l, time_t start, const char *host,
		const char *term, int res);
int list_update_logout(llist* l, time_t t);
lnode *list_delete_cur(llist *l);

/* Given a uid, find that record. */
lnode *list_find_auid(llist *l, uid_t auid, unsigned int session);

#endif

