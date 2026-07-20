/* ids.h --
 * Copyright 2021,2023,2025 Steve Grubb.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 *
 */

#ifndef IDS_HEADER
#define IDS_HEADER

#include "libaudit.h"
#define DAEMON_SESSION "4294967295"
#define UNSET 4294967295

extern int debug;
extern void my_printf(const char *fmt, ...)
	 __attribute__ (( format(printf, 1, 2) ));
extern int log_audit_event(int type, const char *text, int res);
extern volatile int hup;
extern volatile int dump_state;
void reload_config(void);
void output_state(void);

#endif
