#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libaudit.h"
#include "auparse.h"

static void test_new_buffer(void)
{
	const char buf1[] = "type=LOGIN msg=audit(1143146623.787:142): pid=1\n";
	const char buf2[] = "type=USER_LOGIN msg=audit(1143146623.879:146): pid=2\n";
	auparse_state_t *au = auparse_init(AUSOURCE_BUFFER, buf1);
	assert(au != NULL);
	assert(auparse_next_event(au) > 0);
	assert(auparse_get_type(au) == AUDIT_LOGIN);
	assert(auparse_new_buffer(au, buf2, strlen(buf2)) == 0);
	assert(auparse_next_event(au) > 0);
	assert(auparse_get_type(au) == AUDIT_USER_LOGIN);
	auparse_destroy(au);
}

static int cb_count;
static void ready_cb(auparse_state_t *au, auparse_cb_event_t e, void *d)
{
	if (e == AUPARSE_CB_EVENT_READY)
		cb_count++;
}

static void test_feed_state(void)
{
	const char buf[] = "type=LOGIN msg=audit(1143146623.787:142): pid=1\n";
	auparse_state_t *au = auparse_init(AUSOURCE_FEED, NULL);
	assert(au != NULL);
	auparse_add_callback(au, ready_cb, NULL, NULL);
	assert(auparse_feed_has_data(au) == 0);
	assert(auparse_feed(au, buf, strlen(buf)) == 0);
	assert(auparse_feed_has_data(au) == 1);
	auparse_flush_feed(au);
	assert(cb_count == 1);
	auparse_destroy(au);
}

static void test_normalize(void)
{
	auparse_state_t *au = auparse_init(AUSOURCE_FILE, "./test.log");
	assert(au != NULL);
	assert(auparse_next_event(au) > 0);
	assert(auparse_normalize(au, NORM_OPT_ALL) == 0);
	const char *kind = auparse_normalize_get_event_kind(au);
	assert(kind && strcmp(kind, "mac-decision") == 0);
	assert(auparse_normalize_subject_primary(au) == 1);
	assert(auparse_get_field_str(au) != NULL);
	auparse_normalize_object_primary(au);
	auparse_interpret_realpath(au);
	auparse_destroy(au);
}

static void test_compare(void)
{
	auparse_state_t *au = auparse_init(AUSOURCE_FILE, "./test.log");
	assert(au != NULL);
	assert(auparse_next_event(au) > 0);
	const au_event_t *e1 = auparse_get_timestamp(au);
	assert(e1 != NULL);
	au_event_t copy = *e1;

	assert(auparse_next_event(au) > 0);
	const au_event_t *e2 = auparse_get_timestamp(au);
	assert(e2 != NULL);

	assert(auparse_node_compare(&copy, e2) == 0);
	assert(auparse_timestamp_compare(&copy, e2) < 0);
	auparse_destroy(au);
}

/* Test parsing of timestamp expressions for millisecond range. */
static void test_timestamp_milli(void)
{
	auparse_state_t *au;
	char *err = NULL;
	int rc;

	au = auparse_init(AUSOURCE_FILE, "./test.log");
	assert(au != NULL);

	rc = ausearch_add_expression(au,
				"\\timestamp == ts:1.999",
				&err, AUSEARCH_RULE_CLEAR);
	assert(rc == 0);
	assert(err == NULL);

	rc = ausearch_add_expression(au,
				"\\timestamp == ts:1.1000",
				&err, AUSEARCH_RULE_CLEAR);
	assert(rc == -1);
	assert(err != NULL);
	free(err);

	auparse_destroy(au);
}

int main(void)
{
	test_new_buffer();
	test_feed_state();
	test_normalize();
	test_compare();
	test_timestamp_milli();
	printf("extra auparse tests: all passed\n");
	return 0;
}

