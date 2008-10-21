/*
* ausearch-lookup.c - Lookup values to something more readable
* Copyright (c) 2005-06 Red Hat Inc., Durham, North Carolina.
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

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <linux/net.h>
#include "ausearch-lookup.h"
#include "ausearch-options.h"
#include "ausearch-nvpair.h"

/* This is the name/value pair used by search tables */
struct nv_pair {
	int        value;
	const char *name;
};


/* The machine based on elf type */
static int machine = 0;
static const char *Q = "?";
static const char *results[3]= { "unset", "denied", "granted" };
static const char *success[3]= { "unset", "no", "yes" };

const char *aulookup_result(avc_t result)
{
	return results[result];
}

const char *aulookup_success(int s)
{
	switch (s)
	{
		default:
			return success[0];
			break;
		case S_FAILED:
			return success[1];
			break;
		case S_SUCCESS:
			return success[2];
			break;
	}
}

const char *aulookup_syscall(llist *l, char *buf, size_t size)
{
	const char *sys;

	if (report_format <= RPT_DEFAULT) {
		snprintf(buf, size, "%d", l->s.syscall);
		return buf;
	}
	machine = audit_elf_to_machine(l->s.arch);
	if (machine < 0)
		return Q;
	sys = audit_syscall_to_name(l->s.syscall, machine);
	if (sys) {
		const char *func = NULL;
		if (strcmp(sys, "socketcall") == 0) {
			if (list_find_item(l, AUDIT_SYSCALL))
				func = aulookup_socketcall((long)l->cur->a0);
		} else if (strcmp(sys, "ipc") == 0) {
			if(list_find_item(l, AUDIT_SYSCALL))
				func = aulookup_ipccall((long)l->cur->a0);
		}
		if (func) {
			snprintf(buf, size, "%s(%s)", sys, func);
			return buf;
		}
		return sys;
	}
	snprintf(buf, size, "%d", l->s.syscall);
	return buf;
}

static struct nv_pair socktab[] = {
	{SYS_SOCKET, "socket"},
	{SYS_BIND, "bind"},
	{SYS_CONNECT, "connect"},
	{SYS_LISTEN, "listen"},
	{SYS_ACCEPT, "accept"},
	{SYS_GETSOCKNAME, "getsockname"},
	{SYS_GETPEERNAME, "getpeername"},
	{SYS_SOCKETPAIR, "socketpair"},
	{SYS_SEND, "send"},
	{SYS_RECV, "recv"},
	{SYS_SENDTO, "sendto"},
	{SYS_RECVFROM, "recvfrom"},
	{SYS_SHUTDOWN, "shutdown"},
	{SYS_SETSOCKOPT, "setsockopt"},
	{SYS_GETSOCKOPT, "getsockopt"},
	{SYS_SENDMSG, "sendmsg"},
	{SYS_RECVMSG, "recvmsg"}
};
#define SOCK_NAMES (sizeof(socktab)/sizeof(socktab[0]))

const char *aulookup_socketcall(long sc)
{
        int i;

        for (i = 0; i < SOCK_NAMES; i++)
                if (socktab[i].value == sc)
                        return socktab[i].name;

        return NULL;
}

/* This is from asm/ipc.h. Copying it for now as some platforms
 * have broken headers. */
#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24

/*
 * This table maps ipc calls to their text name
 */
static struct nv_pair ipctab[] = {
        {SEMOP, "semop"},
        {SEMGET, "semget"},
        {SEMCTL, "semctl"},
        {MSGSND, "msgsnd"},
        {MSGRCV, "msgrcv"},
        {MSGGET, "msgget"},
        {MSGCTL, "msgctl"},
        {SHMAT, "shmat"},
        {SHMDT, "shmdt"},
        {SHMGET, "shmget"},
        {SHMCTL, "shmctl"}
};
#define IPC_NAMES (sizeof(ipctab)/sizeof(ipctab[0]))

const char *aulookup_ipccall(long ic)
{
        int i;

        for (i = 0; i < IPC_NAMES; i++)
                if (ipctab[i].value == ic)
                        return ipctab[i].name;

        return NULL;
}

static nvlist uid_nvl;
static int uid_list_created=0;
const char *aulookup_uid(uid_t uid, char *buf, size_t size)
{
	char *name = NULL;
	int rc;

	if (report_format <= RPT_DEFAULT) {
		snprintf(buf, size, "%d", uid);
		return buf;
	}
	if (uid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	}

	// Check the cache first
	if (uid_list_created == 0) {
		nvlist_create(&uid_nvl);
		nvlist_clear(&uid_nvl);
		uid_list_created = 1;
	}
	rc = nvlist_find_val(&uid_nvl, uid);
	if (rc) {
		name = uid_nvl.cur->name;
	} else {
		// Add it to cache
		struct passwd *pw;
		pw = getpwuid(uid);
		if (pw) {
			nvnode nv;
			nv.name = strdup(pw->pw_name);
			nv.val = uid;
			nvlist_append(&uid_nvl, &nv);
			name = uid_nvl.cur->name;
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", uid);
	return buf;
}

void aulookup_destroy_uid_list(void)
{
	if (uid_list_created == 0)
		return;

	nvlist_clear(&uid_nvl); 
	uid_list_created = 0;
}

static nvlist gid_nvl;
static int gid_list_created=0;
const char *aulookup_gid(gid_t gid, char *buf, size_t size)
{
	char *name = NULL;
	int rc;

	if (report_format <= RPT_DEFAULT) {
		snprintf(buf, size, "%d", gid);
		return buf;
	}
	if (gid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	}

	// Check the cache first
	if (gid_list_created == 0) {
		nvlist_create(&gid_nvl);
		nvlist_clear(&gid_nvl);
		gid_list_created = 1;
	}
	rc = nvlist_find_val(&gid_nvl, gid);
	if (rc) {
		name = gid_nvl.cur->name;
	} else {
		// Add it to cache
		struct group *gr;
		gr = getgrgid(gid);
		if (gr) {
			nvnode nv;
			nv.name = strdup(gr->gr_name);
			nv.val = gid;
			nvlist_append(&gid_nvl, &nv);
			name = gid_nvl.cur->name;
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", gid);
	return buf;
}

void aulookup_destroy_gid_list(void)
{
	if (gid_list_created == 0)
		return;

	nvlist_clear(&gid_nvl); 
	gid_list_created = 0;
}

