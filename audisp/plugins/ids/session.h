/* session.h --
 * Copyright 2021,2023,2026 Steve Grubb.
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

#ifndef SESSION_HEADER
#define SESSION_HEADER

#include <stdio.h>
#include "avl.h"
#include "origin.h"
#include "ids_config.h"

typedef struct session_data {
	avl_t avl;	// This has to be first

	unsigned int session;
	unsigned int score;
	unsigned int killed;
	ids_address_t origin;
	const char *acct;	// Not used at the moment
} session_data_t;


void init_sessions(void);
void new_session(unsigned int s, const ids_address_t *o, const char *acct);
void destroy_sessions(void);
unsigned int get_num_sessions(void);
void traverse_sessions(FILE *f);

int add_session(session_data_t *s);
session_data_t *find_session(unsigned int s);
session_data_t *current_session(void);
int del_session(unsigned int s);
void add_to_score_session(session_data_t *s, unsigned int adj);

#endif
