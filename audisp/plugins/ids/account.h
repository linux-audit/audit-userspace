/* account.h --
 * Copyright 2021,2023 Steve Grubb.
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

#ifndef ACCOUNT_HEADER
#define ACCOUNT_HEADER

#include <stdio.h>
#include "avl.h"

typedef struct account_data {
	avl_t avl;	// This has to be first

	const char *name;
	unsigned int karma;
} account_data_t;


void init_accounts(void);
void destroy_accounts(void);
void new_account(const char *name);
unsigned int get_num_accounts(void);
void traverse_accounts(FILE *f);

int add_account(account_data_t *a);
account_data_t *find_account(const char *name);
account_data_t *current_account(void);
int del_account(const char *name);
void add_to_score_account(account_data_t *a, unsigned int adj);

#endif
