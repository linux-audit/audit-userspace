/*
* ausearch-parse.h - Header file for ausearch-llist.c
* Copyright (c) 2005,2020 Red Hat
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

#ifndef AUSEARCH_PARSE_HEADER
#define AUSEARCH_PARSE_HEADER

#include "config.h"
#include "ausearch-llist.h"

int extract_search_items(llist *l);
void lookup_uid_destroy_list(void);

struct audit_log_info {
	char *name;
	time_t sec;
	unsigned int milli;
};

int audit_log_list(const char *basefile, struct audit_log_info **logs,
		   size_t *log_cnt);
unsigned audit_log_find_start(const struct audit_log_info *logs,
			      size_t log_cnt, time_t start);
void audit_log_free(struct audit_log_info *logs, size_t log_cnt);

#endif

