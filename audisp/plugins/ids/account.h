/* account.h --
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

