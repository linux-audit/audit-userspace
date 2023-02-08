/* origin.c --
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
	return (((origin_data_t *)a)->address - 
			((origin_data_t *)b)->address);
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

	fprintf(f, "\n");
	fprintf(f, " address: %s\n", sockint_to_ipv4(o->address));
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

void new_origin(unsigned int a)
{
	origin_data_t *tmp = (origin_data_t *)malloc(sizeof(origin_data_t));
	if (tmp) {
		tmp->address = a;
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
	if (debug)
		my_printf("Adding origin %u", o->address);

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
		my_printf("origin: failed inserting address %u", o->address);
	return 0;
}

origin_data_t *find_origin(unsigned int addr)
{
	origin_data_t tmp;

	tmp.address = addr;
	cur = (origin_data_t *)avl_search(&origins.index, (avl_t *) &tmp);
	return cur;
}

origin_data_t *current_origin(void)
{
	return cur;
}

int del_origin(unsigned int addr)
{
	origin_data_t tmp1, *tmp2;
	tmp1.address = addr;

	if (debug)
		my_printf("Deleting %u", addr);
	cur = NULL;
	tmp2 = (origin_data_t *)avl_remove(&origins.index, (avl_t *) &tmp1);
	if (tmp2) {
		origins.count--;
		if (tmp2->address != addr) {
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

char *sockint_to_ipv4(unsigned int addr)
{
        unsigned char *uaddr = (unsigned char *)&(addr);
        static char buf[16];

        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                uaddr[0], uaddr[1], uaddr[2], uaddr[3]);
        return buf;
}

unsigned int ipv4_to_sockint(const char *buf)
{
	unsigned int addr;
	unsigned int ip[4] = {0, 0, 0, 0};

	if (sscanf(buf, "%u.%u.%u.%u", &ip[3], &ip[2], &ip[1], &ip[0]) != 4)
		return 0;

	addr = ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3];
	return addr;
}

void bad_login_origin(origin_data_t *o, struct ids_conf *config)
{	// We will just add a 1 for a bad login.
	add_to_score_origin(o, config->option_bad_login_weight);
}

void bad_service_login_origin(origin_data_t *o, struct ids_conf *config,
		const char *acct)
{	// We will just add a 5 for a bad service login.
	char buf[62];
	const char *addr = sockint_to_ipv4(o->address);
	// account names can be up to 32 characters. IPv4 can be 16
	snprintf(buf, sizeof(buf), "acct=%.32s daddr=%.16s",
			acct ? acct : "?", addr);
	log_audit_event(AUDIT_ANOM_LOGIN_SERVICE, buf, 1);

	add_to_score_origin(o, config->option_service_login_weight);
}

void watched_login_origin(origin_data_t *o, struct ids_conf *config,
		const char *acct)
{	// We will just add a 5 for a watched login.
	char buf[62];
	const char *addr = sockint_to_ipv4(o->address);
	snprintf(buf, sizeof(buf), "acct=%.32s daddr=%.16s",
			acct ? acct : "?", addr);
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
	unsigned int uaddr = ipv4_to_sockint(addr);
	origin_data_t *o = find_origin(uaddr);
	if (o) {
		o->blocked = 0;
		return 1;
	}

	return 0;
}
