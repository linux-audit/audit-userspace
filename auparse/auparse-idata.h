/*
* idata.h - Header file for ausearch-lookup.c
* Copyright (c) 2013 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved.
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#ifndef IDATA_HEADER
#define IDATA_HEADER

#include "config.h"
#include "dso.h"

typedef struct _idata {
	unsigned int machine;	// The machine type for the event
	int syscall;		// The syscall for the event
	unsigned long long a0;	// arg 0 to the syscall
	unsigned long long a1;	// arg 1 to the syscall
	const char *name;	// name of field being interpretted
	const char *val;	// value of field being interpretted
} idata;

int auparse_interp_adjust_type(int rtype, const char *name, const char *val);
const char *auparse_do_interpretation(int type, const idata *id);

hidden_proto(auparse_interp_adjust_type)
hidden_proto(auparse_do_interpretation)

#endif

