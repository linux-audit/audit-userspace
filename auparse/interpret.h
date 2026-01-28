/* interpret.h --
 * Copyright 2007,08,2016-23 Red Hat Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#ifndef INTERPRET_HEADER
#define INTERPRET_HEADER

#include "config.h"
#include "dso.h"
#include "rnode.h"
#include <time.h>
#include "gcc-attributes.h"

#define NEVER_LOADED 0xFFFF

/* Make these hidden to prevent conflicts */
AUDIT_HIDDEN_START

void init_interpretation_list(auparse_state_t *au);
int load_interpretation_list(auparse_state_t *au, const char *buf);
void free_interpretation_list(auparse_state_t *au);
unsigned int interpretation_list_cnt(const auparse_state_t *au);
int lookup_type(const char *name);
const char *do_interpret(auparse_state_t *au, rnode *r);
void _aulookup_destroy_uid_list(auparse_state_t *au);
void aulookup_destroy_gid_list(auparse_state_t *au);
void aulookup_metrics(const auparse_state_t *au, unsigned int *uid,
			unsigned int *gid);
char *au_unescape(const char *buf)  __attribute_malloc__ __attr_dealloc_free;

AUDIT_HIDDEN_END

#endif

