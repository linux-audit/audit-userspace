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
#include "ids_config.h"

typedef struct origin_data {
	avl_t avl;	// This has to be first

	unsigned int address; // This hack works for IPv4
	unsigned int karma;
	unsigned int blocked;
} origin_data_t;


void init_origins(void);
void new_origin(unsigned int a);
void destroy_origins(void);
unsigned int get_num_origins(void);
void traverse_origins(FILE *f);

int add_origin(origin_data_t *o);
origin_data_t *find_origin(unsigned int addr);
origin_data_t *current_origin(void);
int del_origin(unsigned int addr);
void bad_login_origin(origin_data_t *o, struct ids_conf *config);
void bad_service_login_origin(origin_data_t *o, struct ids_conf *config,
	const char *acct);
void watched_login_origin(origin_data_t *o, struct ids_conf *config,
	const char *acct);
void add_to_score_origin(origin_data_t *o, unsigned int adj);
int unblock_origin(const char *addr);
char *sockint_to_ipv4(unsigned int addr);
unsigned int ipv4_to_sockint(const char *buf);

#endif

