/* internal.h -- 
 * Copyright 2006-07,2013-14 Red Hat Inc., Durham, North Carolina.
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
 *	Steve Grubb <sgrubb@redhat.com>
 */
#ifndef AUPARSE_INTERNAL_HEADER
#define AUPARSE_INTERNAL_HEADER

#include "auparse-defs.h"
#include "ellist.h"
#include "auditd-config.h"
#include "data_buf.h"
#include "dso.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This is what state the parser is in */
typedef enum { EVENT_EMPTY, EVENT_ACCUMULATING, EVENT_EMITTED } auparser_state_t;

/* This is the name/value pair used by search tables */
struct nv_pair {
	int        value;
	const char *name;
};

struct opaque
{
	ausource_t source;		// Source type
	char **source_list;		// Array of buffers, or array of
					//	 file names
	int list_idx;			// The index into the source list
	FILE *in;			// If source is file, this is the fd
	unsigned int line_number;	// line number of current file, zero
					//	 if invalid
	char *next_buf;			// The current buffer being broken down
	unsigned int off;		// The current offset into next_buf
	char *cur_buf;			// The current buffer being parsed
	int line_pushed;		// True if retrieve_next_line() 
					//	returns same input
	event_list_t le;		// Linked list of record in same event
	struct expr *expr;		// Search expression or NULL
	char *find_field;		// Used to store field name when
					//	 searching
	austop_t search_where;		// Where to put the cursors on a match
	auparser_state_t parse_state;	// parsing state
	DataBuf databuf;		// input data

	// function to call to notify user of parsing changes
	void (*callback)(struct opaque *au, auparse_cb_event_t cb_event_type, void *user_data);

	void *callback_user_data;	// user data supplied to callback

	// function to call when user_data is destroyed
	void (*callback_user_data_destroy)(void *user_data);
};

// auditd-config.c
void clear_config(struct daemon_conf *config) hidden;
int load_config(struct daemon_conf *config, log_test_t lt) hidden;
void free_config(struct daemon_conf *config) hidden;

#ifdef __cplusplus
}
#endif

#endif

