/*
 * auditd_dispatch_test.c - dispatcher protocol length tests
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "config.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "auditd-dispatch.h"
#include "libdisp.h"

static event_t *queued_event;

/*
 * libdisp_active - make the dispatcher available to the unit under test
 *
 * Returns: Non-zero.
 */
int libdisp_active(void)
{
	return 1;
}

/*
 * libdisp_enqueue - capture a dispatched event for assertions
 * @e: event transferred by the dispatcher
 *
 * Returns: Success.
 */
int libdisp_enqueue(event_t *e)
{
	queued_event = e;
	return 0;
}

/*
 * libdisp_init - provide the unused dispatcher setup symbol for linking
 * @config: dispatcher configuration
 *
 * Returns: Success.
 */
int libdisp_init(const struct daemon_conf *config)
{
	(void)config;
	return 0;
}

/*
 * libdisp_shutdown - provide the unused dispatcher shutdown symbol for linking
 *
 * Returns: None.
 */
void libdisp_shutdown(void)
{
}

/*
 * libdisp_reconfigure - provide the unused reconfigure symbol for linking
 * @config: dispatcher configuration
 *
 * Returns: None.
 */
void libdisp_reconfigure(const struct daemon_conf *config)
{
	(void)config;
}

/*
 * free_queued_event - release the event captured by the dispatcher stub
 *
 * Returns: None.
 */
static void free_queued_event(void)
{
	free(queued_event);
	queued_event = NULL;
}

/*
 * test_netlink_payload_length - kernel nlmsg_len is the payload size directly
 *
 * The kernel audit subsystem sets nlmsg_len = skb->len - NLMSG_HDRLEN,
 * i.e. the payload size only.  Verify dispatch uses it as-is.
 */
static void test_netlink_payload_length(void)
{
	struct audit_reply rep;

	memset(&rep, 0, sizeof(rep));
	memset(rep.msg.data, 'a', sizeof(rep.msg.data));
	rep.type = AUDIT_SYSCALL;
	rep.nlh = &rep.msg.nlh;
	rep.msg.nlh.nlmsg_len = sizeof(rep.msg.data);

	assert(dispatch_event(&rep, AUDISP_PROTOCOL_VER) == 0);
	assert(queued_event != NULL);
	assert(queued_event->hdr.size == sizeof(queued_event->data));
	assert(memcmp(queued_event->data, rep.msg.data,
		      sizeof(queued_event->data)) == 0);
	free_queued_event();
}

/*
 * test_invalid_netlink_length - reject oversized payloads
 *
 * Returns: None.
 */
static void test_invalid_netlink_length(void)
{
	struct audit_reply rep;

	memset(&rep, 0, sizeof(rep));
	rep.nlh = &rep.msg.nlh;
	rep.msg.nlh.nlmsg_len = sizeof(rep.msg.data) + 1;
	assert(dispatch_event(&rep, AUDISP_PROTOCOL_VER) == -1);
	assert(queued_event == NULL);
}

/*
 * test_synthetic_payload_length - retain auditd's local V1 length convention
 *
 * Returns: None.
 */
static void test_synthetic_payload_length(void)
{
	struct audit_reply rep;

	memset(&rep, 0, sizeof(rep));
	rep.msg.nlh.nlmsg_len = 2;
	memcpy(rep.msg.data, "ok", 2);

	assert(dispatch_event(&rep, AUDISP_PROTOCOL_VER) == 0);
	assert(queued_event != NULL);
	assert(queued_event->hdr.size == 2);
	assert(memcmp(queued_event->data, "ok", 2) == 0);
	free_queued_event();
}

/*
 * test_realistic_user_event - exercise a USER record like auditctl -m produces
 *
 * The kernel sets nlmsg_len to the payload size (not including the netlink
 * header).  The dispatcher must copy exactly that many bytes from msg.data.
 */
static void test_realistic_user_event(void)
{
	struct audit_reply rep;
	const char *payload =
		"audit(1721000000.123:42): pid=1234 uid=0 auid=0 ses=1 "
		"subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 "
		"msg='text=dispatch-test "
		"exe=\"/usr/sbin/auditctl\" "
		"hostname=? addr=? terminal=pts/0 res=success'";
	unsigned int plen = strlen(payload);

	memset(&rep, 0, sizeof(rep));
	rep.type = AUDIT_USER;
	rep.nlh = &rep.msg.nlh;
	rep.msg.nlh.nlmsg_len = plen;
	memcpy(rep.msg.data, payload, plen);

	assert(dispatch_event(&rep, AUDISP_PROTOCOL_VER) == 0);
	assert(queued_event != NULL);
	assert(queued_event->hdr.size == plen);
	assert(memcmp(queued_event->data, payload, plen) == 0);
	free_queued_event();
}

/*
 * test_v2_protocol_uses_rep_len - VER2 events use rep->len and rep->message
 *
 * Enriched / pre-formatted events travel as AUDISP_PROTOCOL_VER2 and must
 * use the explicit rep->len field rather than nlmsg_len.
 */
static void test_v2_protocol_uses_rep_len(void)
{
	struct audit_reply rep;
	const char *formatted = "type=USER msg=audit(1721000000.789:44): "
				"op=user-msg terminal=pts/0 res=success";
	unsigned int flen = strlen(formatted);

	memset(&rep, 0, sizeof(rep));
	rep.type = AUDIT_USER;
	rep.len = flen;
	rep.message = (char *)formatted;

	assert(dispatch_event(&rep, AUDISP_PROTOCOL_VER2) == 0);
	assert(queued_event != NULL);
	assert(queued_event->hdr.size == flen);
	assert(memcmp(queued_event->data, formatted, flen) == 0);
	free_queued_event();
}

int main(void)
{
	test_netlink_payload_length();
	test_invalid_netlink_length();
	test_synthetic_payload_length();
	test_realistic_user_event();
	test_v2_protocol_uses_rep_len();
	return 0;
}
