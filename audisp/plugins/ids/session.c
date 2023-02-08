/* session.c --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "ids.h"
#include "ids_config.h"
#include "origin.h"
#include "account.h"
#include "session.h"
#include "reactions.h"

// This holds info about all sessions
struct session_avl{
	avl_tree_t index;
	unsigned int count;
};

static struct session_avl sessions;
static session_data_t *cur = NULL;


static int cmp_sessions(void *a, void *b)
{
	return (((session_data_t *)a)->session - 
			((session_data_t *)b)->session);
}

void init_sessions(void)
{
	sessions.count = 0;
	cur = NULL;
	avl_init(&sessions.index, cmp_sessions);
}

unsigned int get_num_sessions(void)
{
	return sessions.count;
}

static int dump_session(void *entry, void *data)
{
	FILE *f = data;
	session_data_t *s = entry;

	fprintf(f, "\n");
	fprintf(f, " session: %u\n", s->session);
	fprintf(f, " score: %u\n", s->score);
	fprintf(f, " killed: %u\n", s->killed);
	fprintf(f, " origin: %s\n", sockint_to_ipv4(s->origin));
	fprintf(f, " acct: %s\n", s->acct);

	return 0;
}

void traverse_sessions(FILE *f)
{
	fprintf(f, "Sessions\n");
	fprintf(f, "========\n");
	fprintf(f, "count: %u\n", sessions.count);
	avl_traverse(&sessions.index, dump_session, f);
}

static void free_session(session_data_t *s)
{
	if (debug)
		my_printf("Freeing session %u, %p", s->session, s);
	free((void *)s->acct);
	free((void *)s);
}

static void destroy_session(void)
{
	avl_t *cur = sessions.index.root;

	session_data_t *tmp =(session_data_t *)avl_remove(&sessions.index, cur);
	if ((avl_t *)tmp != cur)
		my_printf("session: removal of invalid node");
	free_session(tmp);
	cur = NULL;
}

void new_session(unsigned int s, unsigned int o, const char *acct)
{
	session_data_t *tmp = malloc(sizeof(session_data_t));
	if (tmp) {
		tmp->session = s;
		tmp->score = 0;
		tmp->killed = 0;
		tmp->origin = o;
		tmp->acct = acct ? acct : strdup("");
		add_session(tmp);
	}
}

void destroy_sessions(void)
{
	while (sessions.index.root) {
		sessions.count--;
		destroy_session();
	}
}

int add_session(session_data_t *s)
{
	session_data_t *tmp;
	if (debug)
		my_printf("Adding session %u, %p", s->session, s);

	cur = NULL;
	tmp = (session_data_t *)avl_insert(&sessions.index, (avl_t *)(s));
	if (tmp) {
		if (tmp != s) {
			if (debug)
				my_printf("session: duplicate session found");
			free_session(s);
			return 1;
		}
		sessions.count++;
		cur = tmp;

		// Add origin info
		origin_data_t *o = find_origin(s->origin);
		if (o == NULL)
			new_origin(s->origin);

		// Add account info
		account_data_t *a = find_account(s->acct);
		if (a == NULL)
			new_account(s->acct);
		return 1;
	} else if (debug)
		my_printf("session: failed inserting session %u", s->session);
	return 0;
}

session_data_t *find_session(unsigned int s)
{
	session_data_t tmp;

	tmp.session = s;
	cur = (session_data_t *)avl_search(&sessions.index, (avl_t *) &tmp);
	return cur;
}

session_data_t *current_session(void)
{
	return cur;
}

int del_session(unsigned int s)
{
	session_data_t tmp1, *tmp2;
	tmp1.session = s;

	if (debug)
		my_printf("Deleting %u", s);
	cur = NULL;
	tmp2 = (session_data_t *)avl_remove(&sessions.index, (avl_t *) &tmp1);
	if (tmp2) {
		sessions.count--;
		if (tmp2->session != s) {
			if (debug)
				my_printf("session: deleting unknown session");
			return 1;
		}
	} else { 
		if (debug)
			my_printf("session: didn't find session");
		return 1;
	}

	// Now free any data pointed to by tmp2
	free_session(tmp2);

	return 0;
}

void add_to_score_session(session_data_t *s, unsigned int adj)
{
	cur = s;
	if (s == NULL) {
		if (debug)
			my_printf("session is NULL adding score");
		return;
	}

	s->score += adj;
	if (debug)
		my_printf("session score: %u", s->score);
}

