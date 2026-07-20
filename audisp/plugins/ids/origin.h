/* origin.h --
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

#ifndef ORIGIN_HEADER
#define ORIGIN_HEADER

#include <stdio.h>
#include "avl.h"
#include "address.h"
#include "ids_config.h"

typedef struct origin_data {
	avl_t avl;	// This has to be first

	ids_address_t address;
	unsigned int karma;
	unsigned int blocked;
} origin_data_t;


void init_origins(void);
void new_origin(const ids_address_t *address);
void destroy_origins(void);
unsigned int get_num_origins(void);
void traverse_origins(FILE *f);

int add_origin(origin_data_t *o);
origin_data_t *find_origin(const ids_address_t *address);
origin_data_t *current_origin(void);
int del_origin(const ids_address_t *address);
void bad_login_origin(origin_data_t *o, struct ids_conf *config);
void bad_service_login_origin(origin_data_t *o, struct ids_conf *config,
	const char *acct);
void watched_login_origin(origin_data_t *o, struct ids_conf *config,
	const char *acct);
void add_to_score_origin(origin_data_t *o, unsigned int adj);
int unblock_origin(const char *addr);

#endif
