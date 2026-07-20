/* auditctl-listing.h - Header file for auditctl-listing.c
 * Copyright 2014,2018,2023 Red Hat Inc.
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
 *   Steve Grubb <sgrubb@redhat.com>
 */

#ifndef CTLLISTING_HEADER
#define CTLLISTING_HEADER

#include "config.h"
#include "libaudit.h"

void audit_print_init(void);
int audit_print_reply(const struct audit_reply *rep, int fd);
int key_match(const struct audit_rule_data *r);

#endif
