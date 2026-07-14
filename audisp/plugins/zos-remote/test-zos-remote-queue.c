/*
 * test-zos-remote-queue.c - ownership tests for z/OS remote queue drops
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
#include <stdint.h>
#include <stdarg.h>
#include "zos-remote-log.h"

static BerElement *freed[2];
static unsigned int freed_count;

static void test_log(const char *fmt, ...)
{
	va_list ap;

	(void)fmt;
	va_start(ap, fmt);
	va_end(ap);
}

static void test_ber_free(BerElement *ber, int freebuf)
{
	(void)freebuf;
	assert(freed_count < 2);
	freed[freed_count++] = ber;
}

#define log_err test_log
#define ber_free test_ber_free
#include "zos-remote-queue.c"
#undef ber_free
#undef log_err

static void test_full_queue_frees_dropped_event(void)
{
	BerElement *first = (BerElement *)(uintptr_t)1;
	BerElement *second = (BerElement *)(uintptr_t)2;

	freed_count = 0;
	assert(init_queue(1) == 0);
	enqueue(first);
	enqueue(second);
	assert(freed_count == 1);
	assert(freed[0] == second);
	destroy_queue();
	assert(freed_count == 2);
	assert(freed[1] == first);
}

int main(void)
{
	test_full_queue_frees_dropped_event();
	return 0;
}
