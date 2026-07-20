/* address.h --
 * Copyright 2026 Steve Grubb.
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
 */

#ifndef IDS_ADDRESS_HEADER
#define IDS_ADDRESS_HEADER

#include <arpa/inet.h>
#include <stddef.h>

typedef struct ids_address {
	int family;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} addr;
} ids_address_t;

int ids_address_parse(const char *text, ids_address_t *address);
int ids_address_compare(const ids_address_t *left,
	const ids_address_t *right);
int ids_address_format(const ids_address_t *address, char *buffer,
	size_t size);
int ids_address_is_valid(const ids_address_t *address);

#endif
