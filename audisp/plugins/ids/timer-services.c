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
#include <string.h>
#include <unistd.h>
#include <stdio.h>	// for snprintf
#include "timer-services.h"
#include "nvpair.h"
#include "reactions.h"
#include "ids.h"
#include "origin.h"

static nvlist jobs;
static time_t now;
// Something to think about, jobs should probably be persistent so that
// we can resume them after starting back up.

void init_timer_services(void)
{
	nvpair_list_create(&jobs);
	now = time(NULL);
}

void do_timer_services(unsigned int interval)
{
	now += interval;
rerun_jobs:
	while (nvpair_list_find_job(&jobs, now)) {
		nvnode *j = nvpair_list_get_cur(&jobs);
		switch (j->job) {
			case UNLOCK_ACCOUNT:
				unlock_account(j->arg);
				// Should we reset the stats?
				break;
			case UNBLOCK_ADDRESS:
				{
				// Send iptables rule
				int res = unblock_ip_address(j->arg);

				// Log that its back in business
				char buf[24];
				snprintf(buf, sizeof(buf),
						 "daddr=%.16s", j->arg);
				log_audit_event(
					AUDIT_RESP_ORIGIN_UNBLOCK_TIMED,
					buf, !res);

				// Reset origin state
				unblock_origin(j->arg);
				}
				break;
			default:
				break;
		}
		nvpair_list_delete_cur(&jobs);
	}

	// Every 10 minutes resync to the clock
	if (now%600 > interval) {
		time_t cur = now;
		now = time(NULL);
		if (now > cur) {
			if (debug)
			    my_printf("Time jumped - rerunning jobs");
			goto rerun_jobs;
		}
	}
}

void add_timer_job(jobs_t job, const char *arg, unsigned long length)
{
	nvnode node;

	node.job = job;
	node.arg = strdup(arg);
	node.expiration = time(NULL) + length;

	nvpair_list_append(&jobs, &node);
}

void shutdown_timer_services(void)
{
	nvpair_list_clear(&jobs);
}

