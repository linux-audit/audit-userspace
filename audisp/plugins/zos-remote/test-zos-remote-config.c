/*
 * test-zos-remote-config.c - mode tests for z/OS remote configuration
 * Copyright 2026 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 */

#include "config.h"
#include <assert.h>
#include <stdarg.h>
#include "zos-remote-log.h"

static void test_log(const char *fmt, ...)
{
	va_list ap;

	(void)fmt;
	va_start(ap, fmt);
	va_end(ap);
}

#define log_err test_log
#define log_warn test_log
#define log_info test_log
#include "zos-remote-config.c"
#undef log_info
#undef log_warn
#undef log_err

static void test_secure_config_modes(void)
{
	assert(is_secure_config_mode(0600));
	assert(is_secure_config_mode(0640));
	assert(!is_secure_config_mode(0644));
	assert(!is_secure_config_mode(0660));
	assert(!is_secure_config_mode(0666));
}

int main(void)
{
	test_secure_config_modes();
	return 0;
}
