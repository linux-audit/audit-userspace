/*
 * ausearch-userspace.c - ausearch userspace configuration code
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"
#include <stdio.h>
#include "auditd-config.h"
#include "ausearch-lol.h"

// Set up userspace configuration items from auditd.conf
// We load the daemon configuration file and update any internal user space
// configuration items if they are different to default

void setup_userspace_configitems(void)
{
	struct daemon_conf config;

	// Load the configuration file 
	(void)load_config(&config, TEST_SEARCH);

	lol_set_eoe_timeout((time_t)config.end_of_event_timeout);
	free_config(&config);
}
