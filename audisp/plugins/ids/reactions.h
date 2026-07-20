/* reactions.h --
 * Copyright 2021,2026 Steve Grubb.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#ifndef REACTIONS_HEADER
#define REACTIONS_HEADER

#include "address.h"

struct session_data;

int kill_process(pid_t pid);
int kill_session(int session);
int restricted_role(const char *acct);
int force_password_reset(const char *acct);
int lock_account(const char *acct);
int unlock_account(const char *acct);
int lock_account_timed(const char *acct, unsigned long length);
int block_ip_address(const ids_address_t *address);
int block_ip_address_timed(const ids_address_t *address,
	unsigned long length);
int unblock_ip_address(const char *addr);
int system_reboot(void);
int system_single_user(void);
int system_halt(void);
void do_reaction(unsigned int answer, const char *reason,
	const struct session_data *session);

#endif
