/*
 * normalize-internal.h
 * Copyright (c) 2016-17 Red Hat Inc., Durham, North Carolina.
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

#ifndef NORMALIZE_INTERNAL
#define NORMALIZE_INTERNAL

#define NORM_UNKNOWN		0
#define NORM_FILE		1
#define NORM_FILE_CHATTR	2
#define NORM_FILE_LDMOD	3
#define NORM_FILE_UNLDMOD	4
#define NORM_FILE_DIR		5
#define NORM_FILE_MOUNT	6
#define NORM_FILE_RENAME	7
#define NORM_FILE_STAT		8
#define NORM_FILE_LNK		9
#define NORM_FILE_UMNT		10
#define NORM_FILE_DEL		11
#define NORM_FILE_TIME		12
#define NORM_EXEC		13
#define NORM_SOCKET_ACCEPT	14
#define NORM_SOCKET_BIND	15
#define NORM_SOCKET_CONN	16
#define NORM_SOCKET_RECV	17
#define NORM_SOCKET_SEND	18
#define NORM_PID		19
#define NORM_MAC		20
#define NORM_MAC_ERR		21
#define NORM_IPTABLES		22
#define NORM_PROMISCUOUS	23
#define NORM_UID		24
#define NORM_GID		25
#define NORM_SYSTEM_TIME	26
#define NORM_MAKE_DEV		27
#define NORM_SYSTEM_NAME	28
#define NORM_FILE_SYS_STAT	29

// This enum is used to map what the system objects are
#define NORM_WHAT_UNKNOWN	0
#define NORM_WHAT_FIFO		1
#define NORM_WHAT_CHAR_DEV	2
#define NORM_WHAT_DIRECTORY	3
#define NORM_WHAT_BLOCK_DEV	4
#define NORM_WHAT_FILE		5
#define NORM_WHAT_LINK		6
#define NORM_WHAT_SOCKET	7
#define NORM_WHAT_PROCESS	8
#define NORM_WHAT_FIREWALL	9
#define NORM_WHAT_SERVICE	10
#define NORM_WHAT_ACCT		11
#define NORM_WHAT_USER_SESSION	12
#define NORM_WHAT_VM		13
#define NORM_WHAT_PRINTER	14
#define NORM_WHAT_SYSTEM	15
#define NORM_WHAT_AUDIT_RULE	16
#define NORM_WHAT_AUDIT_CONFIG	17
#define NORM_WHAT_MAC_CONFIG	18
#define NORM_WHAT_FILESYSTEM	19

// This enum is used to map events to what kind they are
#define NORM_EVTYPE_UNKNOWN		0
#define NORM_EVTYPE_USERSPACE		1
#define NORM_EVTYPE_SYSTEM_SERVICES	2
#define NORM_EVTYPE_CONFIG		3
#define NORM_EVTYPE_TTY			4
#define NORM_EVTYPE_USER_ACCT		5
#define NORM_EVTYPE_USER_LOGIN		6
#define NORM_EVTYPE_AUDIT_DAEMON	7
#define NORM_EVTYPE_MAC_DECISION	8
#define NORM_EVTYPE_ANOMALY		9
#define NORM_EVTYPE_INTEGRITY		10
#define NORM_EVTYPE_ANOMALY_RESP	11
#define NORM_EVTYPE_MAC			12
#define NORM_EVTYPE_CRYPTO		13
#define NORM_EVTYPE_VIRT		14
#define NORM_EVTYPE_AUDIT_RULE		15

#endif
