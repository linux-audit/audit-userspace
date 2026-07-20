/* address.h --
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
