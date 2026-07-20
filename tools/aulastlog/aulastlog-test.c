/*
 * aulastlog-test.c - Test overrides for aulastlog
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <pwd.h>
#include <stdlib.h>

static int passwd_returned;
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
