/* audit-fgets.h -- a replacement for glibc's fgets
 * Copyright 2018-23 Red Hat Inc.
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

#ifndef AUDIT_FGETS_HEADER
#define AUDIT_FGETS_HEADER

#include <sys/types.h>
#include "dso.h"
// These macros originate in sys/cdefs.h
#ifndef __attr_access
#  define __attr_access(x)
#endif
#ifndef __attr_dealloc
#  define __attr_dealloc(dealloc, argno)
#endif
#ifndef __wur
# define __wur
#endif
AUDIT_HIDDEN_START

void audit_fgets_clear(void);
int audit_fgets_eof(void);
int audit_fgets_more(size_t blen);
int audit_fgets(char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 1, 2));

char *audit_strsplit_r(char *s, char **savedpp);
char *audit_strsplit(char *s);
int audit_is_last_record(int type);

AUDIT_HIDDEN_END
#endif

