/* private.h -- 
 * Copyright 2007,2013 Red Hat Inc., Durham, North Carolina.
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
#ifndef _PRIVATE_H_
#define _PRIVATE_H_

#include "auparse.h"
#include "libaudit.h"
#include "dso.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Internal syslog messaging */
#define audit_msg auparse_msg
#define set_aumessage_mode set_aup_message_mode
void auparse_msg(int priority, const char *fmt, ...) hidden
#ifdef __GNUC__
        __attribute__ ((format (printf, 2, 3)));
#else
        ;
#endif
void set_aumessage_mode(message_t mode, debug_message_t debug) hidden;

char *audit_strsplit_r(char *s, char **savedpp);
char *audit_strsplit(char *s);
hidden_proto(audit_strsplit_r)
hidden_proto(audit_strsplit)

#ifdef __cplusplus
}
#endif

#endif

