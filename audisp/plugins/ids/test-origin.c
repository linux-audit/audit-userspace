/*
 * test-origin.c - Test IDS address parsing and origin tracking
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <assert.h>
#include <string.h>
#include "address.h"
#include "ids.h"
#include "ids_config.h"
#include "origin.h"

int debug;

/* Ignore audit events emitted by origin scoring helpers. */
int log_audit_event(int type __attribute__((unused)),
	const char *text __attribute__((unused)),
	int res __attribute__((unused)))
{
	return 0;
}

/* Ignore debug messages emitted while exercising origin tracking. */
void my_printf(const char *fmt __attribute__((unused)), ...)
{
}

/* Parse a valid address and abort the test if conversion fails. */
static ids_address_t parse_address(const char *text)
{
	ids_address_t address;

	assert(ids_address_parse(text, &address) == 1);
	return address;
}

/* Verify IPv4 and IPv6 are canonicalized into distinct stable keys. */
static void test_address_keys(void)
{
	ids_address_t ipv4 = parse_address("192.0.2.1");
	ids_address_t ipv6 = parse_address("2001:0db8:0:0:0:0:0:1");
	ids_address_t equivalent = parse_address("2001:db8::1");
	ids_address_t invalid;
	char text[INET6_ADDRSTRLEN];

	assert(ipv4.family == AF_INET);
	assert(ipv6.family == AF_INET6);
	assert(ids_address_compare(&ipv4, &ipv6) != 0);
	assert(ids_address_compare(&ipv6, &equivalent) == 0);
	assert(ids_address_format(&ipv6, text, sizeof(text)) == 1);
	assert(strcmp(text, "2001:db8::1") == 0);

	assert(ids_address_parse(NULL, &invalid) == 0);
	assert(invalid.family == AF_UNSPEC);
	assert(ids_address_parse("?", &invalid) == 0);
	assert(invalid.family == AF_UNSPEC);
	assert(ids_address_parse("not-an-address", &invalid) == 0);
	assert(invalid.family == AF_UNSPEC);
	assert(ids_address_format(&invalid, text, sizeof(text)) == 0);
}

/* Verify origin scores and blocked state remain isolated by address family. */
static void test_origin_tracking(void)
{
	struct ids_conf config = { .option_bad_login_weight = 1 };
	ids_address_t ipv4 = parse_address("192.0.2.1");
	ids_address_t ipv6 = parse_address("2001:db8::1");
	ids_address_t invalid;
	origin_data_t *ipv4_origin;
	origin_data_t *ipv6_origin;

	assert(ids_address_parse("invalid", &invalid) == 0);
	init_origins();
	new_origin(&invalid);
	assert(get_num_origins() == 0);

	new_origin(&ipv4);
	new_origin(&ipv6);
	assert(get_num_origins() == 2);
	ipv4_origin = find_origin(&ipv4);
	ipv6_origin = find_origin(&ipv6);
	assert(ipv4_origin != NULL);
	assert(ipv6_origin != NULL);
	assert(ipv4_origin != ipv6_origin);

	bad_login_origin(ipv6_origin, &config);
	bad_login_origin(ipv6_origin, &config);
	assert(ipv6_origin->karma == 2);
	assert(ipv4_origin->karma == 0);
	ipv6_origin->blocked = 1;
	assert(unblock_origin("2001:0db8:0:0:0:0:0:1") == 1);
	assert(ipv6_origin->blocked == 0);
	assert(unblock_origin("invalid") == 0);

	assert(del_origin(&ipv4) == 0);
	assert(del_origin(&ipv6) == 0);
	assert(get_num_origins() == 0);
	destroy_origins();
}

/* Run IDS address and origin regression coverage. */
int main(void)
{
	test_address_keys();
	test_origin_tracking();
	return 0;
}
