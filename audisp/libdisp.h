/* libdisp.h -- audit event dispatcher interface
 * Copyright 2018,2026 Red Hat Inc.
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
 */

#ifndef LIBDISP_HEADERS
#define LIBDISP_HEADERS

#include <stdio.h>
#include "libaudit.h"
#include "auditd-config.h"

typedef struct event
{
	struct audit_dispatcher_header hdr;
	char data[MAX_AUDIT_MESSAGE_LENGTH];
} event_t;


int libdisp_init(const struct daemon_conf *config);
void libdisp_shutdown(void);
void libdisp_reconfigure(const struct daemon_conf *config);
void libdisp_child_changed(void);
int libdisp_enqueue(event_t *e);
int libdisp_active(void);
void libdisp_nudge_queue(void);
void libdisp_write_queue_state(FILE *f);
void libdisp_resume(void);

#endif
