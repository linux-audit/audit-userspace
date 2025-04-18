/* strsplit.c --
 * Copyright 2014,2016,2017,2025 Red Hat Inc.
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
#include "common.h"
#pragma GCC optimize("O3")

/*
 * This function is similar to strtok_r except it is aimed at
 * splitting strings at a space character.
 */
char *audit_strsplit_r(char *s, char **savedpp)
{
	char *ptr;

	// On new string, initialize
	if (s)
		*savedpp = s;

	// Are we done?
	if (*savedpp == NULL)
		return NULL;

	// skip leading spaces
	while (**savedpp == ' ')
		(*savedpp)++;

	// end of string?
	if (**savedpp == '\0') {
		*savedpp = NULL;
		return NULL;
	}

	// Mark the start
	ptr = *savedpp;

	// advance until space or end
	while (**savedpp != '\0' && **savedpp != ' ')
		(*savedpp)++;

	if (**savedpp == ' ')
		*(*savedpp)++ = '\0'; // terminate and advance past the space
	else
		*savedpp = NULL; // at end of string

	return ptr;
}

/*
 * This function is similar to strtok except it is aimed at
 * splitting strings at a space character.
 */
char *audit_strsplit(char *s)
{
    static char *str;
    return audit_strsplit_r(s, &str);
}

