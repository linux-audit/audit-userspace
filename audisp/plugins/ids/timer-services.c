/* timer-services.c --
 * Copyright 2021 Steve Grubb.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>	// for snprintf
#include "timer-services.h"
#include "nvpair.h"
#include "reactions.h"
#include "ids.h"

static pthread_t timer_thread;
static void *timer_thread_main(void *arg);
static nvlist jobs;
static volatile atomic_int halt = 0, locked = 0;

// Something to think about, jobs should probably be peristent so that
// we can resume them after starting back up.

void init_timer_services(void)
{
	nvpair_list_create(&jobs);
	pthread_create(&timer_thread, NULL, timer_thread_main, NULL);
}

static void *timer_thread_main(void *arg __attribute__((unused)))
{
	sigset_t sigs;
	time_t now;

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGCHLD);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	now = time(NULL);
	while (!halt) {
		sleep(5);
		now += 5;
rerun_jobs:
		while (__sync_lock_test_and_set(&locked, 1));
		while (!halt && nvpair_list_find_job(&jobs, now)) {
			nvnode *j = nvpair_list_get_cur(&jobs);
			switch (j->job) {
				case UNLOCK_ACCOUNT:
					unlock_account(j->arg);
					// Should we reset the stats?
					break;
				case UNBLOCK_ADDRESS:
					{
					int res = unblock_ip_address(j->arg);
					// Should we reset the stats?
					char buf[24];
					snprintf(buf, sizeof(buf),
						 "daddr=%.16s", j->arg);
					log_audit_event(
						AUDIT_RESP_ORIGIN_UNBLOCK_TIMED,
						buf, !res);
					}
					break;
				default:
					break;
			}
			nvpair_list_delete_cur(&jobs);
		}
		__sync_lock_release(&locked);

		// Every 5 minutes resync to the clock
		if (now%600 == 0) {
			time_t cur = now;
			now = time(NULL);
			if (now > cur) {
				if (debug)
				    my_printf("Time jumped - rerunning jobs");
				goto rerun_jobs;
			}
		}
	}
	return NULL;
}

void add_timer_job(jobs_t job, const char *arg, unsigned long length)
{
	nvnode node;

	node.job = job;
	node.arg = strdup(arg);
	node.expiration = time(NULL) + length;

	while (__sync_lock_test_and_set(&locked, 1));
	nvpair_list_append(&jobs, &node);
	__sync_lock_release(&locked);
}

void shutdown_timer_services(void)
{
	halt = 1;
	pthread_cancel(timer_thread);

	while (__sync_lock_test_and_set(&locked, 1));
	nvpair_list_clear(&jobs);
	__sync_lock_release(&locked);

	pthread_join(timer_thread, NULL);
}

