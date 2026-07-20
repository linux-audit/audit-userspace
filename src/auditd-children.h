/* auditd-children.h -- exact-PID reaping for auditd helper processes
 * Copyright 2026 Red Hat Inc.
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

#ifndef AUDITD_CHILDREN_HEADER
#define AUDITD_CHILDREN_HEADER

#include <sys/types.h>

typedef void (*auditd_child_callback)(void);

pid_t auditd_fork_child(auditd_child_callback callback);
void auditd_reap_children(void);

#endif
