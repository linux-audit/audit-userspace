/*
* ausearch-lol.c - linked list of linked lists library
* Copyright (c) 2008,2010,2014,2016,2019,2021 Red Hat Inc.
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

#include "ausearch-lol.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "ausearch-common.h"
#include "auditd-config.h"
#include "common.h"

#define ARRAY_LIMIT 80
static int ready = 0;
event very_first_event;

// End of Event timeout value (in seconds). This can be over-riden via configuration or command line argument.
static time_t eoe_timeout = EOE_TIMEOUT;


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
	e->sec = strtoul(s, NULL, 10);
	if (errno || e->sec > (LONG_MAX - eoe_timeout -1))
		return -1;
	ptr = strchr(s, '.');
	if (ptr) {
		ptr++;
		e->milli = strtoul(ptr, NULL, 10);
		if (errno || e->milli > 999)
			return -1;
		s = ptr;
	} else
		e->milli = 0;

	ptr = strchr(s, ':');
	if (ptr) {
		ptr++;
		e->serial = strtoul(ptr, NULL, 10);
		if (errno)
			return -1;
	} else
		e->serial = 0;
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

// Returns -1 if e1 < e2, 0 if equal, and 1 if e1 > e2
static int compare_event_time(event *e1, event *e2)
{
	if (e1->sec != e2->sec) {
		if (e1->sec > e2->sec)
			return 1;
		return -1;
	}
	if (e1->milli != e2->milli) {
		if (e1->milli > e2->milli)
			return 1;
		return -1;
	}
	if (e1->serial != e2->serial) {
		if (e1->serial > e2->serial)
			return 1;
		return -1;
	}
	return 0;
}

#ifndef HAVE_STRNDUPA
static inline char *strndupa(const char *old, size_t n)
{
	size_t len = strnlen(old, n);
	char *tmp = alloca(len + 1);
	tmp[len] = 0;
	return memcpy(tmp, old, len);
}
#endif

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
		// strlen is for fuzzers that make invalid lines
		if (ptr && strnlen(ptr, 20) > 18) {
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
					|| (end_time && e->sec > end_time)) {
					if (very_first_event.sec == 0) {
						very_first_event.sec = e->sec;
						very_first_event.milli = e->milli;
					}
					return 0;
				} else {
					// If no start time, any event is 1st
					if (very_first_event.sec == 0 &&
							start_time == 0) {
						very_first_event.sec = e->sec;
						very_first_event.milli = e->milli;
					}
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
			// If eoe_timeout seconds have elapsed, we are done
			if (cur->l->e.sec + eoe_timeout <= sec) {
				cur->status = L_COMPLETE;
				ready++;
			} else if (audit_is_last_record(cur->l->e.type)) {
				// If known to be 1 record event, we are done
				cur->status = L_COMPLETE;
				ready++;
			}
		}
	}
}

// This function will check events to see if they are complete but not compare against a given time
static void check_events_without_time(lol *lo)
{
	int i;

	for(i=0;i<=lo->maxi; i++) {
		lolnode *cur = &lo->array[i];
		if (cur->status == L_BUILDING) {
			/* We now iterate over the event's records but without affecting the node's current
			 * pointer (cur->l->cur). That is, we don't call the list-* routines
			 * We could jump to the last record in the list which is normally a PROCTITLE, but this
			 * may not be guaranteed, so we check all record types
			 */
			lnode *ln = cur->l->head;
			while (ln) {
				if (audit_is_last_record(ln->type)) {
					cur->status = L_COMPLETE;
					ready++;
					break;
				}
				ln = ln->next;
			}
		}
	}
}

// This function adds a new record to an existing linked list
// or creates a new one if its a new event
int lol_add_record(lol *lo, char *buff)
{
	int i, fmt;
	lnode n;
	event e;
	char *ptr;
	llist *l;

	// Short circuit if event is not of interest
	if (extract_timestamp(buff, &e) == 0)
		return 0;

	n.a0 = 0L;
	n.a1 = 0L;
	n.type = e.type;
	n.message = strdup(buff);
	ptr = strchr(n.message, AUDIT_INTERP_SEPARATOR);
	if (ptr) {
		n.mlen = ptr - n.message;
		if (n.mlen > MAX_AUDIT_MESSAGE_LENGTH)
			n.mlen = MAX_AUDIT_MESSAGE_LENGTH;
		*ptr = 0;
		n.interp = ptr + 1;
		// since we are most of the way down the string, scan from there
		ptr = strrchr(n.interp, 0x0a);
		if (ptr) {
			*ptr = 0;
			n.tlen = ptr - n.message;
			if (n.tlen > MAX_AUDIT_MESSAGE_LENGTH)
				n.tlen = MAX_AUDIT_MESSAGE_LENGTH;
		} else
			n.tlen = n.mlen;
		fmt = LF_ENRICHED;
	} else {
		ptr = strrchr(n.message, 0x0a);
		if (ptr) {
			*ptr = 0;
			n.mlen = ptr - n.message;
			if (n.mlen > MAX_AUDIT_MESSAGE_LENGTH)
				n.mlen = MAX_AUDIT_MESSAGE_LENGTH;
		} else
			n.mlen = strlen(n.message);
		n.interp = NULL;
		n.tlen = n.mlen;
		fmt = LF_RAW;
	}

	// Now see where this belongs
	for (i=0; i<=lo->maxi; i++) {
		if (lo->array[i].status == L_BUILDING) {
			l = lo->array[i].l;
			if (events_are_equal(&l->e, &e)) {
				free((char *)e.node);
				list_append(l, &n);
				if (fmt > l->fmt)
					l->fmt = fmt;
				return 1;
			}
		}
	}

	// Eat standalone EOE, main event was already marked complete
	if (e.type == AUDIT_EOE) {
		free((char *)e.node);
		free(n.message);
		return 0;
	}

	// Create new event and fill it in
	l = malloc(sizeof(llist));
	list_create(l);
	l->e.milli = e.milli;
	l->e.sec = e.sec;
	l->e.serial = e.serial;
	l->e.node = e.node;
	l->e.type = e.type;
	l->fmt = fmt;
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
}

// This function will mark all events as complete if it can.
void complete_all_events(lol *lo)
{

	check_events_without_time(lo);
}

/* Search the list for any event that is ready to go. The caller
 * takes custody of the memory */
llist* get_ready_event(lol *lo)
{
	int i;
	lolnode *lowest = NULL;

	if (ready == 0)
		return NULL;

	for (i=0; i<=lo->maxi; i++) {
		// Look for the event with the lowest time stamp
		lolnode *cur = &lo->array[i];
		if (cur->status == L_EMPTY)
			continue;
		if (lowest == NULL)
			lowest = cur;
		else if (compare_event_time(&(lowest->l->e), &(cur->l->e)) == 1)
			lowest = cur;
	}

	if (lowest && lowest->status == L_COMPLETE) {
		lowest->status = L_EMPTY;
		ready--;
		// Try to consolidate the array so that we iterate
		// over a smaller portion next time
		if (lowest == &lo->array[lo->maxi]) {
			lolnode *ptr = lowest;
			while (ptr->status == L_EMPTY && lo->maxi > 0) {
				lo->maxi--;
				ptr = &lo->array[lo->maxi];
			}
		}
		return lowest->l;
	}

	return NULL;
}

/*
 * lol_set_eoe_timeout - set the end of event timeout to given value
 *
 * Args
 * 	new_eoe_tmo - value
 * Rtn
 * 	void
 */
void lol_set_eoe_timeout(time_t new_eoe_tmo)
{
	eoe_timeout = new_eoe_tmo;
}

time_t lol_get_eoe_timeout(void)
{
	return eoe_timeout;
}

