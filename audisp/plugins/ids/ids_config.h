/* ids_config.h --
 * Copyright 2021,2023,2025 Steve Grubb.
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

#ifndef IDS_CONFIG_HEADER
#define IDS_CONFIG_HEADER

#include <stdio.h>

// Notifications
#define REACTION_IGNORE			0x0000001
#define REACTION_LOG			0x0000002
#define REACTION_EMAIL			0x0000004

// Bad process defenses
#define REACTION_TERMINATE_PROCESS	0x0000010
// freeze process?

// Bad session defenses
#define REACTION_TERMINATE_SESSION	0x0000100

// Account defenses
#define REACTION_RESTRICT_ROLE		0x0001000
#define REACTION_PASSWORD_RESET		0x0002000
#define REACTION_LOCK_ACCOUNT_TIMED	0x0004000
#define REACTION_LOCK_ACCOUNT		0x0008000
// drop supplemental groups?

// Remote system defenses
#define REACTION_BLOCK_ADDRESS_TIMED	0x0010000
#define REACTION_BLOCK_ADDRESS		0x0020000

// System defenses
// sysctls, selinux booleans
// update specific rpm, all rpms
// restart service
// drop service timed <- check this against list of things that can't be dropped

// System terminations
// Drop network timed
#define REACTION_SYSTEM_REBOOT		0x2000000
#define REACTION_SYSTEM_SINGLE_USER	0x4000000
#define REACTION_SYSTEM_HALT		0x8000000

struct ids_conf
{
	unsigned int option_origin_failed_logins_threshold;
	unsigned int option_origin_failed_logins_reaction;
	unsigned int option_session_badness1_threshold;
	unsigned int option_session_badness1_reaction;
	unsigned int option_service_login_allowed;
	unsigned int option_service_login_weight;
	unsigned int option_root_login_allowed;
	unsigned int option_root_login_weight;
	unsigned int option_bad_login_weight;
	unsigned int block_address_time;
	unsigned int lock_account_time;
};

extern struct ids_conf config;

int load_config(struct ids_conf *config);
void reset_config(struct ids_conf *config);
void free_config(struct ids_conf *config);
void dump_config(struct ids_conf *config, FILE *f);

#endif
