/* session.h --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#ifndef SESSION_HEADER
#define SESSION_HEADER

#include <stdio.h>
#include "avl.h"
#include "origin.h"
#include "ids_config.h"

typedef struct session_data {
	avl_t avl;	// This has to be first

	unsigned int session;
	unsigned int score;
	unsigned int killed;
	unsigned int origin;	// This hack works for IPv4
	const char *acct;	// Not used at the moment
} session_data_t;


void init_sessions(void);
void new_session(unsigned int s, unsigned int o, const char *acct);
void destroy_sessions(void);
unsigned int get_num_sessions(void);
void traverse_sessions(FILE *f);

int add_session(session_data_t *s);
session_data_t *find_session(unsigned int s);
session_data_t *current_session(void);
int del_session(unsigned int s);
void add_to_score_session(session_data_t *s, unsigned int adj);

#endif

