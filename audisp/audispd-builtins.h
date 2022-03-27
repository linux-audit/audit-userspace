/*
* audispd-builtins.h - Interface to builtin plugins
* Copyright (c) 2007,2013,2018,2022 Red Hat Inc.
* All Rights Reserved.
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
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
*/

#ifndef AUDISPD_BUILTINS_HEADER
#define AUDISPD_BUILTINS_HEADER

#include "queue.h"
#ifndef __attr_access
#  define __attr_access(x)
#endif

void start_builtin(plugin_conf_t *conf);
void stop_builtin(plugin_conf_t *conf);
void send_af_unix_string(const char *s, unsigned int len)
	__attr_access ((__read_only__, 1, 2));
void send_af_unix_binary(event_t *e);
void destroy_af_unix(void);

#endif

