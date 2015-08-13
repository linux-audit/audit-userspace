/*
* ausearch-lol.c - linked list of linked lists library
* Copyright (c) 2008,2010,2014 Red Hat Inc., Durham, North Carolina.
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

#include "ausearch-lol.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "ausearch-common.h"
#include "private.h"

#define ARRAY_LIMIT 80
static int ready = 0;

void lol_create(lol *lo)
{
	int size = ARRAY_LIMIT * sizeof(lolnode);

	lo->maxi = -1;
	lo->limit = ARRAY_LIMIT;
	lo->array = (lolnode *)malloc(size);
	memset(lo->array, 0, size);
}

void lol_clear(lol *lo)
{
	int i;

	for (i=0; i<=lo->maxi; i++) {
		if (lo->array[i].status) {
			list_clear(lo->array[i].l);
			free(lo->array[i].l);
		}
	}
	free(lo->array);
	lo->array = NULL;
	lo->maxi = -1;
}

static void lol_append(lol *lo, llist *l)
{
	int i;
	size_t new_size;
	lolnode *ptr;

	for(i=0; i<lo->limit; i++) {
		lolnode *cur = &lo->array[i];
		if (cur->status == L_EMPTY) {
			cur->l = l;
			cur->status = L_BUILDING;
			if (i > lo->maxi)
				lo->maxi = i;
			return;
		}
	}
	// Overran the array...lets make it bigger
	new_size = sizeof(lolnode) * (lo->limit + ARRAY_LIMIT);
	ptr = realloc(lo->array, new_size);
	if (ptr) {
		lo->array = ptr;
		memset(&lo->array[lo->limit], 0, sizeof(lolnode) * ARRAY_LIMIT);
		lo->array[i].l = l;
		lo->array[i].status = L_BUILDING;
		lo->maxi = i;
		lo->limit += ARRAY_LIMIT;
	}
}

static int str2event(char *s, event *e)
{
	char *ptr;

	errno = 0;
	ptr = strchr(s+10, ':');
	if (ptr) {
		e->serial = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->serial = 0;
	ptr = strchr(s, '.');
	if (ptr) {
		e->milli = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->milli = 0;
	e->sec = strtoul(s, NULL, 10);
	if (errno)
		return -1;
	return 0;
}

static int inline events_are_equal(event *e1, event *e2)
{
	if (!(e1->serial == e2->serial && e1->milli == e2->milli &&
					e1->sec == e2->sec))
		return 0;
	if (e1->node && e2->node) {
		if (strcmp(e1->node, e2->node))
			return 0;
	} else if (e1->node || e2->node)
		return 0;
	return 1;
}

/*
 * This function will look at the line and pick out pieces of it.
 */
static int extract_timestamp(const char *b, event *e)
{
	char *ptr, *tmp, *tnode, *ttype;

	e->node = NULL;
	if (*b == 'n')
		tmp = strndupa(b, 340);
	else
		tmp = strndupa(b, 80);
	ptr = audit_strsplit(tmp);
	if (ptr) {
		// Check to see if this is the node info
		if (*ptr == 'n') {
			tnode = ptr+5;
			ptr = audit_strsplit(NULL);
		} else
			tnode = NULL;

		// at this point we have type=
		ttype = ptr+5;

		// Now should be pointing to msg=
		ptr = audit_strsplit(NULL);
		if (ptr) {
			if (*(ptr+9) == '(')
				ptr+=9;
			else
				ptr = strchr(ptr, '(');
			if (ptr) {
			// now we should be pointed at the timestamp
				char *eptr;
				ptr++;
				eptr = strchr(ptr, ')');
				if (eptr)
					*eptr = 0;
				if (str2event(ptr, e)) {
					fprintf(stderr,
					  "Error extracting time stamp (%s)\n",
						ptr);
					return 0;
				} else if ((start_time && e->sec < start_time)
					|| (end_time && e->sec > end_time))
					return 0;
				else {
					if (tnode)
						e->node = strdup(tnode);
					e->type = audit_name_to_msg_type(ttype);
				}
				return 1;
			}
			// else we have a bad line
		}
		// else we have a bad line
	}
	// else we have a bad line
	return 0;
}

// This function will check events to see if they are complete 
// FIXME: Can we think of other ways to determine if the event is done?
static void check_events(lol *lo, time_t sec)
{
	int i;

	for(i=0;i<=lo->maxi; i++) {
		lolnode *cur = &lo->array[i];
		if (cur->status == L_BUILDING) {
			// If 2 seconds have elapsed, we are done
			if (cur->l->e.sec + 2 < sec) { 
				cur->status = L_COMPLETE;
				ready++;
			} else if (cur->l->e.type < AUDIT_FIRST_EVENT ||
				    cur->l->e.type >= AUDIT_FIRST_ANOM_MSG) {
				// If known to be 1 record event, we are done
				cur->status = L_COMPLETE;
				ready++;
			} 
		}
	}
}

// This function adds a new record to an existing linked list
// or creates a new one if its a new event
int lol_add_record(lol *lo, char *buff)
{
	int i;
	lnode n;
	event e;
	char *ptr;
	llist *l;

	// Short circuit if event is not of interest
	if (extract_timestamp(buff, &e) == 0)
		return 0;

	ptr = strrchr(buff, 0x0a);
	if (ptr) {
		*ptr = 0;
		n.mlen = ptr - buff;
	} else
		n.mlen = MAX_AUDIT_MESSAGE_LENGTH;
	n.message=strdup(buff);
	n.type = e.type;

	// Now see where this belongs
	for (i=0; i<=lo->maxi; i++) {
		if (lo->array[i].status == L_BUILDING) {
			l = lo->array[i].l;
			if (events_are_equal(&l->e, &e)) {
				free((char *)e.node);
				list_append(l, &n);
				return 1;
			}
		}
	}
	// Create new event and fill it in
	l = malloc(sizeof(llist));
	list_create(l);
	l->e.milli = e.milli;
	l->e.sec = e.sec;
	l->e.serial = e.serial;
	l->e.node = e.node;
	l->e.type = e.type;
	list_append(l, &n);
	lol_append(lo, l);
	check_events(lo,  e.sec);
	return 1;
}

// This function will mark all events as "done"
void terminate_all_events(lol *lo)
{
	int i;

	for (i=0; i<=lo->maxi; i++) {
		lolnode *cur = &lo->array[i];
		if (cur->status == L_BUILDING) {
			cur->status = L_COMPLETE;
			ready++;
		}
	}
//printf("maxi = %d\n",lo->maxi);
}

/* Search the list for any event that is ready to go. The caller
 * takes custody of the memory */
llist* get_ready_event(lol *lo)
{
	int i;

	if (ready == 0)
		return NULL;

	for (i=0; i<=lo->maxi; i++) {
		lolnode *cur = &lo->array[i];
		if (cur->status == L_COMPLETE) {
			cur->status = L_EMPTY;
			ready--;
			return cur->l;
		}
	}

	return NULL;
}

