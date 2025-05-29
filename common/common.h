/* common.h -- common utility functions used throughout
 * Copyright 2018-24 Red Hat Inc.
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

#ifndef AUDIT_COMMON_HEADER
#define AUDIT_COMMON_HEADER

#ifdef HAVE_ATOMIC
#include <stdatomic.h>
#endif
#include <sys/types.h>
#include "dso.h"
// These macros originate in sys/cdefs.h
#ifndef __attr_access
#  define __attr_access(x)
#endif
#ifndef __attribute_malloc__
#  define __attribute_malloc__
#endif
#ifndef __attr_dealloc
#  define __attr_dealloc(dealloc, argno)
#endif
#ifndef __wur
# define __wur
#endif

/* Wrapper macros for optional atomics
 * Note: ATOMIC_INT and ATOMIC_UNSIGNED are defined in config.h */
#ifdef HAVE_ATOMIC
#  define AUDIT_ATOMIC_STORE(var, val) \
   atomic_store_explicit(&(var), (val), memory_order_relaxed)
#  define AUDIT_ATOMIC_LOAD(var) \
   atomic_load_explicit(&(var), memory_order_relaxed)
#else
#  define AUDIT_ATOMIC_STORE(var, val) do { (var) = (val); } while (0)
#  define AUDIT_ATOMIC_LOAD(var) (var)
#endif
AUDIT_HIDDEN_START

char *audit_strsplit_r(char *s, char **savedpp);
char *audit_strsplit(char *s);
int audit_is_last_record(int type);

int write_to_console(const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)));
#else
	;
#endif

void wall_message(const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((format(printf, 1, 2)));
#else
	;
#endif

AUDIT_HIDDEN_END
#endif

