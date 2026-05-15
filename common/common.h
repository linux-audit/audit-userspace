/* common.h -- common utility functions used throughout
 * Copyright 2018-25 Red Hat Inc.
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

#include "config.h"
#include <limits.h> /* POSIX_HOST_NAME_MAX */
#ifdef HAVE_ATOMIC
#include <stdatomic.h>
#endif
#include <sys/types.h>
#include "dso.h"
#include "gcc-attributes.h"

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

// Used in auditd-event.c and audisp.c to size buffers for formatting
#define FORMAT_BUF_LEN (MAX_AUDIT_MESSAGE_LENGTH + _POSIX_HOST_NAME_MAX)

#ifndef HAVE_STRNDUPA
#define strndupa(s, n)                                          \
	({                                                      \
		const char *__old = (s);			\
		size_t __len = strnlen (__old, (n));            \
		char *__new = (char *) alloca(__len + 1);       \
		__new[__len] = '\0';                            \
		(char *) memcpy (__new, __old, __len);          \
	})
#endif

AUDIT_HIDDEN_START

char *audit_strsplit_r(char *s, char **savedpp);
char *audit_strsplit(char *s);
int audit_is_last_record(int type) __attribute_const__;

extern const char *SINGLE;
extern const char *HALT;
void change_runlevel(const char *level);
const char *get_progname(void);

#define MINUTES 60
#define HOURS   60*MINUTES
#define DAYS    24*HOURS
#define WEEKS   7*DAYS
#define MONTHS  30*DAYS
long time_string_to_seconds(const char *time_string,
			    const char *subsystem, int line);

/* Messages */
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

typedef enum { MSG_STDERR, MSG_SYSLOG, MSG_QUIET } message_t;
typedef enum { DBG_NO, DBG_YES } debug_message_t;
void _set_aumessage_mode(message_t mode, debug_message_t debug);

AUDIT_HIDDEN_END

#endif

