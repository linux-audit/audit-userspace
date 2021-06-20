/* timer-services.h --
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

#ifndef TIMER_SERVICES_HEADER
#define TIMER_SERVICES_HEADER

typedef enum {UNLOCK_ACCOUNT, UNBLOCK_ADDRESS} jobs_t;

void init_timer_services(void);
void do_timer_services(unsigned int interval);
void add_timer_job(jobs_t job, const char *arg, unsigned long length);
void shutdown_timer_services(void);

#endif
