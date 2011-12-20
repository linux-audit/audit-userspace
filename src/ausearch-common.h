/* ausearch-common.h -- 
 * Copyright 2006-08,2010 Red Hat Inc., Durham, North Carolina.
 * Copyright (c) 2011 IBM Corp.
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
 *   Marcelo Henrique Cerri <mhcerri@br.ibm.com>
 * 
 */

#ifndef AUREPORT_COMMON_H
#define AUREPORT_COMMON_H

#include "ausearch-string.h"

/* Global variables that describe what search is to be performed */
extern time_t start_time, end_time;
extern unsigned int event_id;
extern gid_t event_gid, event_egid;
extern pid_t event_pid;
extern int event_exact_match;
extern uid_t event_uid, event_euid, event_loginuid;
const slist *event_node_list;
extern const char *event_comm;
extern const char *event_filename;
extern const char *event_hostname;
extern const char *event_terminal;
extern int event_syscall;
extern const char *event_exe;
extern int event_ua, event_ga;
extern int event_exit, event_exit_is_set;
extern const char *event_uuid;
extern const char *event_vmname;

typedef enum { F_BOTH, F_FAILED, F_SUCCESS } failed_t;
typedef enum { C_NEITHER, C_ADD, C_DEL } conf_act_t;
typedef enum { S_UNSET=-1, S_FAILED, S_SUCCESS } success_t;
typedef enum { RPT_RAW, RPT_DEFAULT, RPT_INTERP, RPT_PRETTY } report_t;

extern failed_t event_failed;
extern conf_act_t event_conf_act;
extern success_t event_success;

#endif

