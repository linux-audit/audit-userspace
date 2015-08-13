/* auparse.h --
 * Copyright 2006-08,2012,2014,2015 Red Hat Inc., Durham, North Carolina.
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
 *      Steve Grubb <sgrubb@redhat.com>
 */

#ifndef AUPARSE_HEADER
#define AUPARSE_HEADER

#include "auparse-defs.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Library type definitions */

/* opaque data type used for maintaining library state */
typedef struct opaque auparse_state_t;

typedef void (*user_destroy)(void *user_data);
typedef void (*auparse_callback_ptr)(auparse_state_t *au,
			auparse_cb_event_t cb_event_type, void *user_data);

/* General functions that affect operation of the library */
auparse_state_t *auparse_init(ausource_t source, const void *b);
int auparse_feed(auparse_state_t *au, const char *data, size_t data_len);
int auparse_flush_feed(auparse_state_t *au);
int auparse_feed_has_data(const auparse_state_t *au);
void auparse_add_callback(auparse_state_t *au, auparse_callback_ptr callback,
			void *user_data, user_destroy user_destroy_func);
void auparse_set_escape_mode(auparse_esc_t mode);
int auparse_reset(auparse_state_t *au);
void auparse_destroy(auparse_state_t *au);

/* Functions that are part of the search interface */
int ausearch_add_expression(auparse_state_t *au, const char *expression,
			    char **error, ausearch_rule_t how);
int ausearch_add_item(auparse_state_t *au, const char *field, const char *op,
			const char *value, ausearch_rule_t how);
int ausearch_add_interpreted_item(auparse_state_t *au, const char *field,
			const char *op, const char *value, ausearch_rule_t how);
int ausearch_add_timestamp_item(auparse_state_t *au, const char *op, time_t sec,
				unsigned milli, ausearch_rule_t how);
int ausearch_add_timestamp_item_ex(auparse_state_t *au, const char *op,
	time_t sec, unsigned milli, unsigned serial, ausearch_rule_t how);
int ausearch_add_regex(auparse_state_t *au, const char *expr);
int ausearch_set_stop(auparse_state_t *au, austop_t where);
void ausearch_clear(auparse_state_t *au);

/* Functions that traverse events */
int ausearch_next_event(auparse_state_t *au);
int auparse_next_event(auparse_state_t *au);

/* Accessors to event data */
const au_event_t *auparse_get_timestamp(auparse_state_t *au);
time_t auparse_get_time(auparse_state_t *au);
unsigned int auparse_get_milli(auparse_state_t *au);
unsigned long auparse_get_serial(auparse_state_t *au);
const char *auparse_get_node(auparse_state_t *au);
int auparse_node_compare(au_event_t *e1, au_event_t *e2);
int auparse_timestamp_compare(au_event_t *e1, au_event_t *e2);
unsigned int auparse_get_num_records(auparse_state_t *au);

/* Functions that traverse records in the same event */
int auparse_first_record(auparse_state_t *au);
int auparse_next_record(auparse_state_t *au);
int auparse_goto_record_num(auparse_state_t *au, unsigned int num);

/* Accessors to record data */
int auparse_get_type(auparse_state_t *au);
const char *auparse_get_type_name(auparse_state_t *au);
unsigned int auparse_get_line_number(auparse_state_t *au);
const char *auparse_get_filename(auparse_state_t *au);
int auparse_first_field(auparse_state_t *au);
int auparse_next_field(auparse_state_t *au);
unsigned int auparse_get_num_fields(auparse_state_t *au);
const char *auparse_get_record_text(auparse_state_t *au);
const char *auparse_find_field(auparse_state_t *au, const char *name);
const char *auparse_find_field_next(auparse_state_t *au);

/* Accessors to field data */
const char *auparse_get_field_name(auparse_state_t *au);
const char *auparse_get_field_str(auparse_state_t *au);
int auparse_get_field_type(auparse_state_t *au);
int auparse_get_field_int(auparse_state_t *au);
const char *auparse_interpret_field(auparse_state_t *au);


#ifdef __cplusplus
}
#endif
 
#endif

