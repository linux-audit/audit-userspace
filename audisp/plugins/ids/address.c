/* address.c --
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

#include "config.h"
#include <string.h>
#include "address.h"

/*
 * ids_address_parse - parse an IPv4 or IPv6 address into a tracking key
 * Args:
 *   text    - printable address from an audit event
 *   address - destination key, cleared to AF_UNSPEC on failure
 * Rtns:
 *   1 on success, 0 for an unknown or malformed address
 */
int ids_address_parse(const char *text, ids_address_t *address)
{
	if (address == NULL)
		return 0;

	memset(address, 0, sizeof(*address));
	address->family = AF_UNSPEC;
	if (text == NULL || *text == '\0' || *text == '?')
		return 0;

	if (inet_pton(AF_INET, text, &address->addr.ipv4) == 1) {
		address->family = AF_INET;
		return 1;
	}

	if (inet_pton(AF_INET6, text, &address->addr.ipv6) == 1) {
		address->family = AF_INET6;
		return 1;
	}

	memset(address, 0, sizeof(*address));
	address->family = AF_UNSPEC;
	return 0;
}

/*
 * ids_address_compare - order two address keys by family and network bytes
 * Args:
 *   left  - first address key
 *   right - second address key
 * Rtns:
 *   less than, equal to, or greater than zero as left sorts before, at, or
 *   after right
 */
int ids_address_compare(const ids_address_t *left,
	const ids_address_t *right)
{
	if (left->family < right->family)
		return -1;
	if (left->family > right->family)
		return 1;

	if (left->family == AF_INET)
		return memcmp(&left->addr.ipv4, &right->addr.ipv4,
			sizeof(left->addr.ipv4));
	if (left->family == AF_INET6)
		return memcmp(&left->addr.ipv6, &right->addr.ipv6,
			sizeof(left->addr.ipv6));
	return 0;
}

/*
 * ids_address_format - write the canonical text for an address key
 * Args:
 *   address - address key to format
 *   buffer  - destination string buffer
 *   size    - destination buffer size
 * Rtns:
 *   1 on success, 0 for an unsupported family or conversion failure
 */
int ids_address_format(const ids_address_t *address, char *buffer,
	size_t size)
{
	const void *src;

	if (address == NULL || buffer == NULL || size == 0)
		return 0;

	if (address->family == AF_INET)
		src = &address->addr.ipv4;
	else if (address->family == AF_INET6)
		src = &address->addr.ipv6;
	else
		return 0;

	return inet_ntop(address->family, src, buffer, size) != NULL;
}

/*
 * ids_address_is_valid - report whether a key has a supported family
 * Args:
 *   address - address key to inspect
 * Rtns:
 *   1 for IPv4 or IPv6, 0 otherwise
 */
int ids_address_is_valid(const ids_address_t *address)
{
	return address != NULL &&
		(address->family == AF_INET || address->family == AF_INET6);
}
