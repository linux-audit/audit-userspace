/* account.c --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include "ids.h"
#include "account.h"
#include "reactions.h"


// This holds info about all sessions
struct account_avl{
	avl_tree_t index;
	unsigned int count;
};

static struct account_avl accounts;
static account_data_t *cur = NULL;


static int cmp_accounts(void *a, void *b)
{
	return strcmp(((account_data_t *)a)->name, ((account_data_t *)b)->name);
}

void init_accounts(void)
{
	accounts.count = 0;
	cur = NULL;
	avl_init(&accounts.index, cmp_accounts);
}

unsigned int get_num_accounts(void)
{
	return accounts.count;
}

static int dump_account(void *entry, void *data)
{
	FILE *f = data;
	account_data_t *a = entry;

	fprintf(f, "\n");
	fprintf(f, " name: %s\n", a->name);
	fprintf(f, " karma: %u\n", a->karma);

	return 0;
}

void traverse_accounts(FILE *f)
{
	fprintf(f, "Accounts\n");
	fprintf(f, "========\n");
	fprintf(f, "count: %u\n", accounts.count);
	avl_traverse(&accounts.index, dump_account, f);
}

static void free_account(account_data_t *a)
{
	if (debug)
		my_printf("Account freeing %p", a);
	free((void *)a->name);
	free(a);
}

static void destroy_account(void)
{
	avl_t *cur = accounts.index.root;

	account_data_t *a = (account_data_t *)avl_remove(&accounts.index, cur);
	if ((avl_t *)a != cur)
		my_printf("account: removal of invalid node");

	// Now free any data pointed to by cur
	free_account(a);
	cur = NULL;
}

void new_account(const char *name)
{
	account_data_t *tmp = (account_data_t *)malloc(sizeof(account_data_t));
	if (tmp) {
		tmp->name = name ? strdup(name) : strdup("");
		tmp->karma = 0;
		add_account(tmp);
	}
}

void destroy_accounts(void)
{
	while (accounts.index.root) {
		accounts.count--;
		destroy_account();
	}
}

int add_account(account_data_t *a)
{
	account_data_t *tmp;
	if (debug)
		my_printf("Adding account %s", a->name);

	cur = NULL;
	tmp = (account_data_t *)avl_insert(&accounts.index, (avl_t *)(a));
	if (tmp) {
		if (tmp != a) {
			if (debug)
				my_printf("account: duplicate name found");
			free_account(a);
			return 1;
		}
		accounts.count++;
		cur = tmp;
	} else if (debug)
		my_printf("account: failed inserting name %s", a->name);
	return 0;
}

account_data_t *find_account(const char *name)
{
	account_data_t tmp;

	if (name == NULL)
		return NULL;

	tmp.name = name;
	cur = (account_data_t *)avl_search(&accounts.index, (avl_t *) &tmp);
	return cur;
}

account_data_t *current_account(void)
{
	return cur;
}

int del_account(const char *name)
{
	account_data_t tmp1, *tmp2;
	tmp1.name = name;

	if (debug)
		my_printf("Deleting %s", name);
	cur = NULL;
	tmp2 = (account_data_t *)avl_remove(&accounts.index, (avl_t *) &tmp1);
	if (tmp2) {
		accounts.count--;
		if (strcmp(tmp2->name, name) != 0) {
			if (debug)
				my_printf("account: deleting unknown name");
			return 1;
		}
	} else {
		if (debug)
			my_printf("account: didn't find name");

		return 1;
	}

	// Now free any data pointed to by tmp2
	free_account(tmp2);

	return 0;
}

void add_to_score_account(account_data_t *a, unsigned int adj)
{
	cur = a;
	if (a == NULL) {
		if (debug)
			my_printf("Account NULL adding score");
		return;
	}

	a->karma += adj;

	// Now invoke any reaction
	if (a->karma >= 5) {
	}
}

