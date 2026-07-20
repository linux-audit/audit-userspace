/*
 * test-model-bad-event.c - Test IDS failed-login origin tracking
 * Copyright (c) 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <auparse.h>
#include "address.h"
#include "ids.h"
#include "ids_config.h"
#include "model_bad_event.h"
#include "origin.h"
#include "session.h"

int debug;

/* Report that no sessions exist in this failed-login-only test. */
unsigned int get_num_sessions(void)
{
	return 0;
}

/* Ignore session cleanup because failed logins never create a session. */
void destroy_sessions(void)
{
}

/* Reject any unexpected attempt to create a failed-login session. */
void new_session(unsigned int session __attribute__((unused)),
	const ids_address_t *origin __attribute__((unused)),
	const char *acct __attribute__((unused)))
{
	assert(0);
}

/* Ignore logout processing, which is outside this test's event set. */
int del_session(unsigned int session __attribute__((unused)))
{
	return 0;
}

/* Reject reactions because the test threshold is deliberately unreachable. */
void do_reaction(unsigned int answer __attribute__((unused)),
	const char *reason __attribute__((unused)),
	const session_data_t *session __attribute__((unused)))
{
	assert(0);
}

/* Ignore audit events emitted by origin scoring helpers. */
int log_audit_event(int type __attribute__((unused)),
	const char *text __attribute__((unused)),
	int res __attribute__((unused)))
{
	return 0;
}

/* Ignore debug messages emitted while processing test events. */
void my_printf(const char *fmt __attribute__((unused)), ...)
{
}

/* Process one failed USER_LOGIN event with the supplied remote address. */
static void process_failed_login(const char *address, unsigned long serial,
	struct ids_conf *config)
{
	char event[512];
	auparse_state_t *au;

	snprintf(event, sizeof(event),
		"type=USER_LOGIN msg=audit(1.001:%lu): pid=1 uid=0 "
		"auid=1000 ses=1 msg='op=login id=1000 "
		"exe=\"/usr/sbin/sshd\" hostname=? addr=%s "
		"terminal=ssh res=failed'\n", serial, address);
	au = auparse_init(AUSOURCE_BUFFER, event);
	assert(au != NULL);
	assert(auparse_next_event(au) > 0);
	assert(auparse_normalize(au, NORM_OPT_NO_ATTRS) == 0);
	process_bad_event_model(au, config);
	auparse_destroy(au);
}

/* Verify USER_LOGIN events track both families and reject invalid keys. */
int main(void)
{
	struct ids_conf config = {
		.option_origin_failed_logins_threshold = UINT_MAX,
		.option_service_login_allowed = 1,
		.option_root_login_allowed = 1,
		.option_bad_login_weight = 1,
	};
	ids_address_t ipv4;
	ids_address_t ipv6;
	origin_data_t *origin;

	init_origins();
	process_failed_login("2001:db8::1", 1, &config);
	assert(get_num_origins() == 1);
	assert(ids_address_parse("2001:db8::1", &ipv6) == 1);
	origin = find_origin(&ipv6);
	assert(origin != NULL);
	assert(origin->karma == 1);

	process_failed_login("2001:0db8:0:0:0:0:0:1", 2, &config);
	assert(get_num_origins() == 1);
	assert(origin->karma == 2);

	process_failed_login("?", 3, &config);
	process_failed_login("not-an-address", 4, &config);
	assert(get_num_origins() == 1);

	process_failed_login("192.0.2.1", 5, &config);
	assert(get_num_origins() == 2);
	assert(ids_address_parse("192.0.2.1", &ipv4) == 1);
	origin = find_origin(&ipv4);
	assert(origin != NULL);
	assert(origin->karma == 1);

	destroy_origins();
	return 0;
}
