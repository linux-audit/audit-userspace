/* origin.h --
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
