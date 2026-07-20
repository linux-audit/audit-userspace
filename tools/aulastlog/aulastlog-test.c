/*
 * aulastlog-test.c - Test overrides for aulastlog
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "auparse.h"

const au_event_t *__real_auparse_get_timestamp(const auparse_state_t *au);
const char *__real_auparse_find_field(auparse_state_t *au, const char *name);
int __real_auparse_get_field_int(const auparse_state_t *au);

static int passwd_returned;
static struct tm test_tm;
static struct passwd test_passwd = {
	.pw_name = "test-user",
	.pw_uid = 1234,
};

/*
 * getpwent - return a controlled passwd enumeration for aulastlog tests
 * @void: no input
 *
 * Return: NULL for an empty or exhausted enumeration, otherwise a test user.
 */
struct passwd *getpwent(void)
{
	if (getenv("AULASTLOG_TEST_EMPTY_PASSWD") || passwd_returned)
		return NULL;

	passwd_returned = 1;
	return &test_passwd;
}

/*
 * endpwent - reset the controlled passwd enumeration
 * @void: no input
 *
 * Return: none.
 */
void endpwent(void)
{
	passwd_returned = 0;
}

/*
 * __wrap_auparse_get_timestamp - inject a missing event timestamp
 * @au: parser state to query
 *
 * Return: NULL when requested by the test, otherwise the parser timestamp.
 */
const au_event_t *__wrap_auparse_get_timestamp(const auparse_state_t *au)
{
	if (getenv("AULASTLOG_TEST_NULL_TIMESTAMP"))
		return NULL;
	return __real_auparse_get_timestamp(au);
}

/*
 * __wrap_auparse_find_field - make the null-timestamp path reach the user
 * @au: parser state to query
 * @name: field name to find
 *
 * Return: a synthetic auid when testing, otherwise the parser field value.
 */
const char *__wrap_auparse_find_field(auparse_state_t *au, const char *name)
{
	if (getenv("AULASTLOG_TEST_NULL_TIMESTAMP") &&
			strcmp(name, "auid") == 0)
		return "1234";
	return __real_auparse_find_field(au, name);
}

/*
 * __wrap_auparse_get_field_int - return the synthetic test user's ID
 * @au: parser state to query
 *
 * Return: the synthetic uid when testing, otherwise the current field value.
 */
int __wrap_auparse_get_field_int(const auparse_state_t *au)
{
	if (getenv("AULASTLOG_TEST_NULL_TIMESTAMP"))
		return 1234;
	return __real_auparse_get_field_int(au);
}

/*
 * localtime - inject a calendar conversion failure for aulastlog tests
 * @timer: timestamp to convert
 *
 * Return: NULL when requested by the test, otherwise the converted time.
 */
struct tm *localtime(const time_t *timer)
{
	if (getenv("AULASTLOG_TEST_LOCALTIME_FAIL"))
		return NULL;
	return localtime_r(timer, &test_tm);
}
