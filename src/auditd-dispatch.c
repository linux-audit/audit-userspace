/* auditd-dispatch.c -- 
 * Copyright 2005-07,2013,2016-17 Red Hat Inc., Durham, North Carolina.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *   Junji Kanemaru <junji.kanemaru@linuon.com>
 */

#include "config.h"
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "libaudit.h"
#include "private.h"
#include "auditd-dispatch.h"
#include "libdisp.h"


int dispatcher_pid(void)
{
	return 0;
}

void dispatcher_reaped(void)
{
	shutdown_dispatcher();
}

/* This function returns 1 on error & 0 on success */
int init_dispatcher(const struct daemon_conf *config)
{
	return libdisp_init(config);
}

void shutdown_dispatcher(void)
{
	libdisp_shutdown();
}

void reconfigure_dispatcher(const struct daemon_conf *config)
{
	libdisp_reconfigure(config);
}

/* Returns -1 on err, 0 on success */
int dispatch_event(const struct audit_reply *rep, int protocol_ver)
{
	event_t *e;

	if (!libdisp_active())
		return 0;

	// Translate event into dispatcher format
	e = malloc(sizeof(event_t));
	if (e == NULL)
		return -1;

	e->hdr.ver = protocol_ver;
	e->hdr.hlen = sizeof(struct audit_dispatcher_header);
	e->hdr.type = rep->type;

	// Network originating events have data at rep->message
	if (protocol_ver == AUDISP_PROTOCOL_VER) {
		e->hdr.size = rep->msg.nlh.nlmsg_len;
		memcpy(e->data, (void*)rep->msg.data, e->hdr.size);
	} else if (protocol_ver == AUDISP_PROTOCOL_VER2) {
		e->hdr.size = rep->len;
		memcpy(e->data, (void*)rep->message, e->hdr.size);
	} else {
		free(e);
		return 0;
	}
	return libdisp_enqueue(e);
}

