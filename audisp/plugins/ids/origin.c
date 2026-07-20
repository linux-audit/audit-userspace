/* origin.c --
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

#include "config.h"
#include <stdlib.h>
#include "ids.h"
#include "origin.h"
#include "reactions.h"

// This holds info about all sessions
struct origin_avl{
	avl_tree_t index;
	unsigned int count;
};

static struct origin_avl origins;
static origin_data_t *cur = NULL;

static int cmp_origins(void *a, void *b)
{
	const origin_data_t *left = a;
	const origin_data_t *right = b;

	return ids_address_compare(&left->address, &right->address);
}

void init_origins(void)
{
	origins.count = 0;
	cur = NULL;
	avl_init(&origins.index, cmp_origins);
}

unsigned int get_num_origins(void)
{
	return origins.count;
}

static int dump_origin(void *entry, void *data)
{
	FILE *f = data;
	origin_data_t *o = entry;
	char address[INET6_ADDRSTRLEN];

	fprintf(f, "\n");
	if (ids_address_format(&o->address, address, sizeof(address)))
		fprintf(f, " address: %s\n", address);
	else
		fprintf(f, " address: ?\n");
	fprintf(f, " karma: %u\n", o->karma);
	fprintf(f, " blocked: %u\n", o->blocked);

	return 0;
}

void traverse_origins(FILE *f)
{
	fprintf(f, "Origins\n");
	fprintf(f, "=======\n");
	fprintf(f, "count: %u\n", origins.count);
	avl_traverse(&origins.index, dump_origin, f);
}

static void free_origin(origin_data_t *o)
{
	if (debug)
		my_printf("Origin freeing %p", o);
	free(o);
}

void new_origin(const ids_address_t *address)
{
	origin_data_t *tmp;

	if (!ids_address_is_valid(address))
		return;

	tmp = (origin_data_t *)malloc(sizeof(origin_data_t));
	if (tmp) {
		tmp->address = *address;
		tmp->karma = 0;
		tmp->blocked = 0;
		add_origin(tmp);
	}
}

static void destroy_origin(void)
{
	avl_t *cur = origins.index.root;

	origin_data_t *o = (origin_data_t *)avl_remove(&origins.index, cur);
	if ((avl_t *)o != cur)
		my_printf("origin: removal of invalid node");

	// Now free any data pointed to by cur
	free_origin(o);
	cur = NULL;
}

void destroy_origins(void)
{
	while (origins.index.root) {
		origins.count--;
		destroy_origin();
	}
}

int add_origin(origin_data_t *o)
{
	origin_data_t *tmp;
	if (debug) {
		char address[INET6_ADDRSTRLEN];

		if (ids_address_format(&o->address, address, sizeof(address)))
			my_printf("Adding origin %s", address);
	}

	cur = NULL;
	tmp = (origin_data_t *)avl_insert(&origins.index, (avl_t *)(o));
	if (tmp) {
		if (tmp != o) {
			if (debug)
				my_printf("origin: duplicate address found");
			free(o);
			return 1;
		}
		origins.count++;
		cur = tmp;
	} else if (debug)
		my_printf("origin: failed inserting address");
	return 0;
}

origin_data_t *find_origin(const ids_address_t *address)
{
	origin_data_t tmp;

	if (!ids_address_is_valid(address)) {
		cur = NULL;
		return NULL;
	}

	tmp.address = *address;
	cur = (origin_data_t *)avl_search(&origins.index, (avl_t *) &tmp);
	return cur;
}

origin_data_t *current_origin(void)
{
	return cur;
}

int del_origin(const ids_address_t *address)
{
	origin_data_t tmp1, *tmp2;

	if (!ids_address_is_valid(address)) {
		cur = NULL;
		return 1;
	}

	tmp1.address = *address;

	if (debug) {
		char printable[INET6_ADDRSTRLEN];

		if (ids_address_format(address, printable, sizeof(printable)))
			my_printf("Deleting %s", printable);
	}
	cur = NULL;
	tmp2 = (origin_data_t *)avl_remove(&origins.index, (avl_t *) &tmp1);
	if (tmp2) {
		origins.count--;
		if (ids_address_compare(&tmp2->address, address) != 0) {
			if (debug)
				my_printf("origin: deleting unknown address");
			return 1;
		}
	} else {
		if (debug)
			my_printf("origin: didn't find address");
		return 1;
	}

	// Now free any data pointed to by tmp2
	free_origin(tmp2);

	return 0;
}

void bad_login_origin(origin_data_t *o, struct ids_conf *config)
{	// We will just add a 1 for a bad login.
	add_to_score_origin(o, config->option_bad_login_weight);
}

void bad_service_login_origin(origin_data_t *o, struct ids_conf *config,
		const char *acct)
{	// We will just add a 5 for a bad service login.
	char address[INET6_ADDRSTRLEN] = "?";
	char buf[96];

	if (o)
		ids_address_format(&o->address, address, sizeof(address));
	// Account names can be up to 32 characters and IPv6 can use 45.
	snprintf(buf, sizeof(buf), "acct=%.32s daddr=%.45s",
			acct ? acct : "?", address);
	log_audit_event(AUDIT_ANOM_LOGIN_SERVICE, buf, 1);

	add_to_score_origin(o, config->option_service_login_weight);
}

void watched_login_origin(origin_data_t *o, struct ids_conf *config,
		const char *acct)
{	// We will just add a 5 for a watched login.
	char address[INET6_ADDRSTRLEN] = "?";
	char buf[96];

	if (o)
		ids_address_format(&o->address, address, sizeof(address));
	snprintf(buf, sizeof(buf), "acct=%.32s daddr=%.45s",
			acct ? acct : "?", address);
	log_audit_event(AUDIT_ANOM_LOGIN_ACCT, buf, 1);

	add_to_score_origin(o, config->option_root_login_weight);
}

void add_to_score_origin(origin_data_t *o, unsigned int adj)
{
	cur = o;
	if (o == NULL) {
		if (debug)
			my_printf("origin NULL adding score");
		return;
	}

	o->karma += adj;
        if (debug)
                my_printf("origin karma: %u", o->karma);
}

// Returns 1 on success and 0 on failure
int unblock_origin(const char *addr)
{
	ids_address_t address;
	origin_data_t *o;

	if (!ids_address_parse(addr, &address))
		return 0;
	o = find_origin(&address);
	if (o) {
		o->blocked = 0;
		return 1;
	}

	return 0;
}
