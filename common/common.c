/* common.c --
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

#include "libaudit.h"
#include "common.h"

/*
 * This function returns 1 if it is the last record in an event.
 * It returns 0 otherwise.
 *
 * When processing an event stream we define the end of an event via
 *   record type = AUDIT_EOE (audit end of event type record), or
 *   record type = AUDIT_PROCTITLE   (we note the AUDIT_PROCTITLE is always
 *                                    the last record), or
 *   record type = AUDIT_KERNEL (kernel events are one record events), or
 *   record type < AUDIT_FIRST_EVENT (only single record events appear
 *                                    before this type), or
 *   record type >= AUDIT_FIRST_ANOM_MSG (only single record events appear
 *                                      after this type), or
 *   record type >= AUDIT_MAC_UNLBL_ALLOW && record type <= AUDIT_MAC_CALIPSO_DEL
 *                                       (these are also one record events)
 */
int audit_is_last_record(int type)
{
	if (type == AUDIT_PROCTITLE ||
	    type == AUDIT_EOE ||
	    (type > AUDIT_LOGIN &&
	     type < AUDIT_FIRST_EVENT) ||
	    type >= AUDIT_FIRST_ANOM_MSG ||
	    type == AUDIT_KERNEL ||
	    (type >= AUDIT_MAC_UNLBL_ALLOW &&
	     type <= AUDIT_MAC_CALIPSO_DEL)) {
		return 1;
	}
	return 0;
}

