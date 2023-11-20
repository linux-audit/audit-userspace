/* audit_logging.h --
 * Copyright 2023 Red Hat Inc.
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

#ifndef _AUDIT_LOGGING_H
#define _AUDIT_LOGGING_H

// Next include is to pick up the function attribute macros
#include <features.h>
#include <audit-records.h>

#ifdef __cplusplus
extern "C" {
#endif

// The following macros originate in sys/cdefs.h
// gcc-analyzer notation
// Define buffer access modes
#ifndef __attr_access
#  define __attr_access(x)
#endif
#ifndef __attr_dealloc
# define __attr_dealloc(dealloc, argno)
# define __attr_dealloc_free
#endif
// Warn unused result
#ifndef __wur
# define __wur
#endif

/* Prerequisite to logging is acquiring and disposing of netlink connections */
int  audit_open(void) __wur;
void audit_close(int fd);

/* The following are for standard formatting of messages */
int audit_value_needs_encoding(const char *str, unsigned int size)
	__attr_access ((__read_only__, 1, 2))
	__wur;
char *audit_encode_value(char *final,const char *buf,unsigned int size)
	__attr_access ((__write_only__, 1))
	__attr_access ((__read_only__, 2, 3));
char *audit_encode_nv_string(const char *name, const char *value,
	unsigned int vlen)
	__attr_access ((__read_only__, 2, 3))
	__attr_dealloc_free;
int audit_log_user_message(int audit_fd, int type, const char *message,
	const char *hostname, const char *addr, const char *tty, int result)
	__wur;
int audit_log_user_comm_message(int audit_fd, int type,
	const char *message, const char *comm, const char *hostname,
	const char *addr, const char *tty, int result) __wur;
int audit_log_acct_message(int audit_fd, int type, const char *pgname,
	const char *op, const char *name, unsigned int id,
	const char *host, const char *addr, const char *tty, int result) __wur;
int audit_log_user_avc_message(int audit_fd, int type,
	const char *message, const char *hostname, const char *addr,
	const char *tty, uid_t auid);
int audit_log_semanage_message(int audit_fd, int type,
	const char *pgname, const char *op, const char *name, unsigned int id,
	const char *new_seuser, const char *new_role, const char *new_range,
	const char *old_seuser, const char *old_role, const char *old_range,
	const char *host, const char *addr,
	const char *tty, int result);
int audit_log_user_command(int audit_fd, int type, const char *command,
        const char *tty, int result) __wur;

#ifdef __cplusplus
}
#endif

#endif

