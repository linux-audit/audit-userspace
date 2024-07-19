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

/* Make these hidden to prevent conflicts */
AUDIT_HIDDEN_START

void init_interpretation_list(void);
int load_interpretation_list(const char *buf);
void free_interpretation_list(void);
unsigned int interpretation_list_cnt(void);
int lookup_type(const char *name);
const char *do_interpret(rnode *r, auparse_esc_t escape_mode);
void aulookup_destroy_uid_list(void);
void aulookup_destroy_gid_list(void);
void aulookup_metrics(unsigned int *uid, unsigned int *gid);
char *au_unescape(char *buf);

AUDIT_HIDDEN_END

#endif

