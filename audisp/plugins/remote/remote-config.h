/* remote-config.h -- 
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
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
 * 
 */

#ifndef REMOTE_CONFIG_H
#define REMOTE_CONFIG_H

typedef enum { M_IMMEDIATE, M_STORE_AND_FORWARD  } mode_t;
typedef enum { T_TCP, T_SSL, T_GSSAPI, T_LABELED } transport_t;
typedef enum { F_IGNORE, F_SYSLOG, F_EXEC, F_SUSPEND, F_SINGLE, F_HALT } fail_t;
typedef enum { F_ASCII, F_MANAGED } format_t;

typedef struct remote_conf
{
	const char *remote_server;
	unsigned int port;
	unsigned int local_port;
	transport_t transport;
	mode_t mode;
	unsigned int queue_depth;
	fail_t fail_action;
	const char *fail_exe;
	format_t format;
} remote_conf_t;

void clear_config(remote_conf_t *config);
int  load_config(remote_conf_t *config, const char *file);
void free_config(remote_conf_t *config);

#endif

