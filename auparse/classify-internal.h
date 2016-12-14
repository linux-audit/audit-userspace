/*
 * classify-internal.h
 * Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
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

#ifndef CLASSIFY_INTERNAL
#define CLASSIFY_INTERNAL

#define CLASS_UNKNOWN		0
#define CLASS_FILE		1
#define CLASS_FILE_CHATTR	2
#define CLASS_FILE_LDMOD	3
#define CLASS_FILE_UNLDMOD	4
#define CLASS_FILE_DIR		5
#define CLASS_FILE_MOUNT	6
#define CLASS_FILE_RENAME	7
#define CLASS_FILE_STAT		8
#define CLASS_FILE_LNK		9
#define CLASS_FILE_UMNT		10
#define CLASS_FILE_DEL		11
#define CLASS_FILE_TIME		12
#define CLASS_EXEC		13
#define CLASS_SOCKET_ACCEPT	14
#define CLASS_SOCKET_BIND	15
#define CLASS_SOCKET_CONN	16
#define CLASS_SOCKET_RECV	17
#define CLASS_SOCKET_SEND	18
#define CLASS_PID		19
#define CLASS_MAC		20
#define CLASS_MAC_ERR		21
#define CLASS_IPTABLES		22
#define CLASS_PROMISCUOUS	23
#define CLASS_UID		24
#define CLASS_GID		25

// This enum is used to map what the system objects are
#define CLASS_WHAT_UNKNOWN	0
#define CLASS_WHAT_FIFO		1
#define CLASS_WHAT_CHAR_DEV	2
#define CLASS_WHAT_DIRECTORY	3
#define CLASS_WHAT_BLOCK_DEV	4
#define CLASS_WHAT_FILE		5
#define CLASS_WHAT_LINK		6
#define CLASS_WHAT_SOCKET	7
#define CLASS_WHAT_PROCESS	8
#define CLASS_WHAT_FIREWALL	9
#define CLASS_WHAT_SERVICE	10
#define CLASS_WHAT_ACCT		11
#define CLASS_WHAT_USER_SESSION	12
#define CLASS_WHAT_VM		13
#define CLASS_WHAT_PRINTER	14
#define CLASS_WHAT_SYSTEM	15
#define CLASS_WHAT_AUDIT_RULE	16
#define CLASS_WHAT_AUDIT_CONFIG	17
#define CLASS_WHAT_MAC_CONFIG	18

#endif
