/* classify.c --
 * Copyright 2016 Red Hat Inc., Durham, North Carolina.
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
 *      Steve Grubb <sgrubb@redhat.com>
 */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <libaudit.h>
#include "auparse.h"
#include "internal.h"
#include "classify-llist.h"
#include "classify-internal.h"
#include "gen_tables.h"
#include "classify_record_maps.h"
#include "classify_syscall_maps.h"
#include "classify_obj_type_maps.h"


/*
 * Field accessors. x is the new value, y is the variable
 * Layout is: 0xFFFF FFFF  where first is record and second is field
 * Both record and field are 0 based. Simple records are always 0. Compound
 * records start at 0 and go up.
 */
#define UNSET 0xFFFF
#define get_record(y) ((y >> 16) & 0x0000FFFF)
#define set_record(y, x) (((x & 0x0000FFFF) << 16) | (y & 0x0000FFFF))
#define get_field(y) (y & 0x0000FFFF)
#define set_field(y, x) ((y & 0xFFFF0000) | (x & 0x0000FFFF))
#define is_unset(y) (get_record(y) == UNSET)
#define D au->cl_data


void init_classify(classify_data *d)
{
	d->session = set_record(0, UNSET);
	d->actor.primary = set_record(0, UNSET);
	d->actor.secondary = set_record(0, UNSET);
	cllist_create(&d->actor.attr, NULL);
	d->action = NULL;
	d->thing.primary = set_record(0, UNSET);
	d->thing.secondary = set_record(0, UNSET);
	cllist_create(&d->thing.attr, NULL);
	d->thing.what = CLASS_WHAT_UNKNOWN;
	d->results = set_record(0, UNSET);
	d->how = NULL;
	d->opt = CLOPT_ALL;
}

void clear_classify(classify_data *d)
{
	d->actor.primary = set_record(0, UNSET);
	d->actor.secondary = set_record(0, UNSET);
	cllist_clear(&d->actor.attr);
	free(d->action);
	d->action = NULL;
	d->thing.primary = set_record(0, UNSET);
	d->thing.secondary = set_record(0, UNSET);
	cllist_clear(&d->thing.attr);
	d->thing.what = CLASS_WHAT_UNKNOWN;
	d->results = set_record(0, UNSET);
	free(d->how);
	d->how = NULL;
	d->opt = CLOPT_ALL;
}

static unsigned int set_prime_subject(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	if (auparse_find_field(au, str)) {
		D.actor.primary = set_record(0, rnum);
		D.actor.primary = set_field(D.actor.primary,
				auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static unsigned int set_secondary_subject(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	if (auparse_find_field(au, str)) {
		D.actor.secondary = set_record(0, rnum);
		D.actor.secondary = set_field(D.actor.secondary,
				auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static void add_subj_attr(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	value_t attr;

	if ((auparse_find_field(au, str))) {
		attr = set_record(0, rnum);
		attr = set_field(attr, auparse_get_field_num(au));
		cllist_append(&D.actor.attr, attr, NULL);
	} else
		auparse_goto_record_num(au, rnum);
}

static unsigned int set_prime_object(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	if (auparse_find_field(au, str)) {
		D.thing.primary = set_record(0, rnum);
		D.thing.primary = set_field(D.thing.primary,
			auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static unsigned int add_obj_attr(auparse_state_t *au, const char *str,
	unsigned int rnum)
{
	value_t attr;

	if ((auparse_find_field(au, str))) {
		attr = set_record(0, rnum);
		attr = set_field(attr, auparse_get_field_num(au));
		cllist_append(&D.thing.attr, attr, NULL);
		return 0;
	} else
		auparse_goto_record_num(au, rnum);
	return 1;
}

static unsigned int add_session(auparse_state_t *au, unsigned int rnum)
{
	if (auparse_find_field(au, "ses")) {
		D.session = set_record(0, rnum);
		D.session = set_field(D.session,
				auparse_get_field_num(au));
		return 0;
	} else
		auparse_first_record(au);
	return 1;
}

static unsigned int set_results(auparse_state_t *au, unsigned int rnum)
{
	if (auparse_find_field(au, "res")) {
		D.results = set_record(0, rnum);
		D.results = set_field(D.results, auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

static void syscall_subj_attr(auparse_state_t *au)
{
	unsigned int rnum;

	auparse_first_record(au);
	do {
		rnum = auparse_get_record_num(au);
		if (auparse_get_type(au) == AUDIT_SYSCALL) {
			add_subj_attr(au, "ppid", rnum);
			add_subj_attr(au, "pid", rnum);
			add_subj_attr(au, "gid", rnum);
			add_subj_attr(au, "euid", rnum);
			add_subj_attr(au, "suid", rnum);
			add_subj_attr(au, "fsuid", rnum);
			add_subj_attr(au, "egid", rnum);
			add_subj_attr(au, "sgid", rnum);
			add_subj_attr(au, "fsgid", rnum);
			add_subj_attr(au, "tty", rnum);
			add_session(au, rnum);
			add_subj_attr(au, "subj", rnum);
			return;
		}
	} while (auparse_next_record(au) == 1);
}

static void collect_path_attrs(auparse_state_t *au)
{
	value_t attr;
	unsigned int rnum = auparse_get_record_num(au);

	if (add_obj_attr(au, "mode", rnum))
		return;	// Failed opens don't have anything else

	// All the rest of the fields matter
	while ((auparse_next_field(au))) {
		attr = set_record(0, rnum);
		attr = set_field(attr, auparse_get_field_num(au));
		cllist_append(&D.thing.attr, attr, NULL);
	}
}

static void collect_cwd_attrs(auparse_state_t *au)
{
	unsigned int rnum = auparse_get_record_num(au);
	add_obj_attr(au, "cwd", rnum);
}

static void collect_sockaddr_attrs(auparse_state_t *au)
{
	unsigned int rnum = auparse_get_record_num(au);
	add_obj_attr(au, "saddr", rnum);
}

static void simple_file_attr(auparse_state_t *au)
{
	int parent = 0;

	if (D.opt == CLOPT_NO_ATTRS)
		return;

	auparse_first_record(au);
	do {
		const char *f;
		int type = auparse_get_type(au);
		switch (type)
		{
			case AUDIT_PATH:
				f = auparse_find_field(au, "nametype");
				if (f && strcmp(f, "PARENT") == 0) {
					if (parent == 0)
					    parent = auparse_get_record_num(au);
					continue;
				}
				// First normal record is collected
				auparse_first_field(au);
				collect_path_attrs(au);
				return;
				break;
			case AUDIT_CWD:
				collect_cwd_attrs(au);
				break;
			case AUDIT_SOCKADDR:
				collect_sockaddr_attrs(au);
				break;
		}
	} while (auparse_next_record(au) == 1);

	// If we get here, path was never collected. Go back and get parent
	if (parent) {
		auparse_goto_record_num(au, parent);
		auparse_first_field(au);
		collect_path_attrs(au);
	}
}

static void set_file_object(auparse_state_t *au, int adjust)
{
	const char *f;
	int parent = 0;
	unsigned int rnum;

	auparse_goto_record_num(au, 2 + adjust);
	auparse_first_field(au);

	// Now double check that we picked the right one.
	do {
		f = auparse_find_field(au, "nametype");
		if (f) {
			if (strcmp(f, "PARENT"))
				break;
			if (parent == 0)
				parent = auparse_get_record_num(au);
		}
	} while (f && auparse_next_record(au) == 1);

	// Sometimes we only have the parent (failed open at dir permission)
	if (f == NULL) {
		if (parent == 0)
			return;

		auparse_goto_record_num(au, parent);
		auparse_first_field(au);
		rnum = parent;
	} else
		rnum = auparse_get_record_num(au);

	if (auparse_get_type(au) == AUDIT_PATH) {
		auparse_first_field(au);

		// Object
		set_prime_object(au, "name", rnum);

		f = auparse_find_field(au, "inode");
		if (f) {
			D.thing.secondary = set_record(0, rnum);
			D.thing.secondary = set_field(D.thing.secondary,
						auparse_get_field_num(au));
		}
		f = auparse_find_field(au, "mode");
		if (f) {
			int mode = auparse_get_field_int(au);
			if (mode != -1) {
				if (S_ISREG(mode))
					D.thing.what = CLASS_WHAT_FILE;
				else if (S_ISDIR(mode))
					D.thing.what = CLASS_WHAT_DIRECTORY;
				else if (S_ISCHR(mode))
					D.thing.what = CLASS_WHAT_CHAR_DEV;
				else if (S_ISBLK(mode))
					D.thing.what = CLASS_WHAT_BLOCK_DEV;
				else if (S_ISFIFO(mode))
					D.thing.what = CLASS_WHAT_FIFO;
				else if (S_ISLNK(mode))
					D.thing.what = CLASS_WHAT_LINK;
				else if (S_ISSOCK(mode))
					D.thing.what = CLASS_WHAT_SOCKET;
			}
		}
	}
}

static void set_socket_object(auparse_state_t *au)
{
	const char *f;

	auparse_goto_record_num(au, 1);
	auparse_first_field(au);
	set_prime_object(au, "saddr", 1);
}

static int set_program_obj(auparse_state_t *au)
{
	auparse_first_record(au);
	if (auparse_find_field(au, "exe")) {
		const char *exe = auparse_interpret_field(au);
		if (strncmp(exe, "/usr/bin/python", 15) == 0) {
			auparse_first_record(au);
			auparse_find_field(au, "comm");
		}
		// FIXME: sh, perl
		D.thing.primary = set_record(0,
				auparse_get_record_num(au));
		D.thing.primary = set_field(D.thing.primary,
				auparse_get_field_num(au));
		return 0;
	}
	return 1;
}

/*
 * This function is supposed to come up with the action and object for the
 * syscalls.
 */
static int classify_syscall(auparse_state_t *au, const char *syscall, int type)
{
	int rc, cltype = CLASS_UNKNOWN;
	const char *act = NULL, *f;

	// cycle through all records and see what we have
	rc = auparse_first_record(au);
	while (rc == 1) {
		int ttype = auparse_get_type(au);

		if (ttype == AUDIT_AVC) {
			cltype = CLASS_MAC;
			break;
		} else if (ttype == AUDIT_SELINUX_ERR) {
			cltype = CLASS_MAC_ERR;
			break;
		} else if (ttype == AUDIT_NETFILTER_CFG) {
			cltype = CLASS_IPTABLES;
			break;
		} else if (ttype == AUDIT_ANOM_PROMISCUOUS) {
			cltype = CLASS_PROMISCUOUS;
			break;
		}
		rc = auparse_next_record(au);
	}

	// lookup system call
	if (cltype == CLASS_UNKNOWN)
		classify_syscall_map_s2i(syscall, &cltype);

	switch (cltype)
	{
		case CLASS_FILE:
			act = "opened-file";
			set_file_object(au, 0);
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			simple_file_attr(au);
			break;
		case CLASS_FILE_CHATTR:
			act = "changed-file-attributes-of";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case CLASS_FILE_LDMOD:
			act = "loaded-kernel-module";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			// set_file_object(au, 0);
			// simple_file_attr(au);
			break;
		case CLASS_FILE_UNLDMOD:
			act = "unloaded-kernel-module";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			// set_file_object(au, 0);
			// simple_file_attr(au);
			break;
		case CLASS_FILE_DIR:
			act = "created-directory";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 1); // New dir is one after
			simple_file_attr(au);
			break;
		case CLASS_FILE_MOUNT:
			act = "mounted";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 1); // The device is one after
			simple_file_attr(au);
			break;
		case CLASS_FILE_RENAME:
			act = "renamed";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 2); // Thing renamed is 2 after
			simple_file_attr(au);
			break;
		case CLASS_FILE_STAT:
			act = "checked";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case CLASS_FILE_LNK:
			act = "symlinked";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			// FIXME: what do we do with the link?
			break;
		case CLASS_FILE_UMNT:
			act = "unmounted";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case CLASS_FILE_DEL:
			act = "deleted";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case CLASS_FILE_TIME:
			act = "changed-timestamp-of";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 0);
			simple_file_attr(au);
			break;
		case CLASS_EXEC:
			act = "executed";
			D.thing.what = CLASS_WHAT_FILE; // this gets overridden
			set_file_object(au, 1);
			simple_file_attr(au);
			break;
		case CLASS_SOCKET_ACCEPT:
			act = "accepted-connection-from";
			D.thing.what = CLASS_WHAT_SOCKET;// this gets overridden
			set_socket_object(au);
			break;
		case CLASS_SOCKET_BIND:
			act = "bound-socket";
			D.thing.what = CLASS_WHAT_SOCKET;// this gets overridden
			set_socket_object(au);
			break;
		case CLASS_SOCKET_CONN:
			act = "connected-to";
			D.thing.what = CLASS_WHAT_SOCKET;// this gets overridden
			set_socket_object(au);
			break;
		case CLASS_SOCKET_RECV:
			act = "received-from";
			D.thing.what = CLASS_WHAT_SOCKET;// this gets overridden
			set_socket_object(au);
			break;
		case CLASS_SOCKET_SEND:
			act = "sent-to";
			D.thing.what = CLASS_WHAT_SOCKET;// this gets overridden
			set_socket_object(au);
			break;
		case CLASS_PID:
			if (auparse_get_num_records(au) > 2)
				// FIXME: this has implications for object
				act = "killed-list-of-pids";
			else
				act = "killed-pid";
			auparse_goto_record_num(au, 1);
			auparse_first_field(au);
			f = auparse_find_field(au, "saddr");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			D.thing.what = CLASS_WHAT_PROCESS;
			break;
		case CLASS_MAC:
			// FIXME: we need to also use other classifications
			// the AVC could be against many kinds of objects.
			act = "violated-mac-policy";
			break;
		case CLASS_MAC_ERR:
			// FIXME: See above
			act = "caused-mac-policy-error";
			break;
		case CLASS_IPTABLES:
			act = "loaded-firewall-rule-to";
			auparse_first_record(au);
			f = auparse_find_field(au, "table");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			D.thing.what = CLASS_WHAT_FIREWALL;
			break;
		case CLASS_PROMISCUOUS:
			auparse_first_record(au);
			f = auparse_find_field(au, "dev");
			if (f) {
				D.thing.primary = set_record(0,
					auparse_get_record_num(au));
				D.thing.primary = set_field(D.thing.primary,
					auparse_get_field_num(au));
			}
			f = auparse_find_field(au, "prom");
			if (f) {
				int i = auparse_get_field_int(au);
				if (i == 0)
					act = "left-promiscuous-mode-on-device";
				else
					act = "entered-promiscuous-mode-on-device";
			}
			D.thing.what = CLASS_WHAT_SOCKET;
			break;
		case CLASS_UID:
		case CLASS_GID:
			act = "changed-identity-of";
			D.thing.what = CLASS_WHAT_PROCESS;
			set_program_obj(au);
			if (D.how) {
				free(D.how);
				D.how = strdup(syscall);
			}
			break;
		default:
			{
				char *k;
				rc = auparse_first_record(au);
				k = auparse_find_field(au, "key");
				if (k && strcmp(k, "(null)")) {
					act = "triggered-audit-rule";
					D.thing.primary = set_record(0,
						auparse_get_record_num(au));
					D.thing.primary = set_field(
						D.thing.primary,
						auparse_get_field_num(au));
				} else
					act = "triggered-unknown-audit-rule";
				D.thing.what = CLASS_WHAT_AUDIT_RULE;
			}
			break;
	}
	if (act)
		D.action = strdup(act);

	return 0;
}

static int classify_compound(auparse_state_t *au)
{
	const char *f, *syscall = NULL;
	int rc, recno, saved = 0, type = auparse_get_type(au);

	// All compound events have a syscall record
	// Some start with a record type and follow with a syscall
	if (type == AUDIT_NETFILTER_CFG || type == AUDIT_ANOM_PROMISCUOUS ||
		type == AUDIT_AVC || type == AUDIT_SELINUX_ERR) {
		auparse_next_record(au);
		type = auparse_get_type(au);
	} else if (type == AUDIT_ANOM_LINK) {
		// Save the action before moving to syscall
		saved = type;
		auparse_next_record(au);
		auparse_next_record(au);
		type = auparse_get_type(au);
	}
	if (type == AUDIT_SYSCALL) {
		recno = auparse_get_record_num(au);
		f = auparse_find_field(au, "syscall");
		if (f) {
			f = auparse_interpret_field(au);
			if (f)
				syscall = strdup(f);
		}

		// Results
		f = auparse_find_field(au, "success");
		if (f) {
			D.results = set_record(0, recno);
			D.results = set_field(D.results,
					auparse_get_field_num(au));
		} else {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free(syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		// Subject - primary
		if (set_prime_subject(au, "auid", recno)) {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free(syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		// Subject - alias, uid comes before auid
		if (set_secondary_subject(au, "uid", recno)) {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free(syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		// Subject attributes
		syscall_subj_attr(au);

		// how
		auparse_first_field(au);
		f = auparse_find_field(au, "exe");
		if (f) {
			const char *exe = auparse_interpret_field(au);
			D.how = strdup(exe);
			if (strncmp(exe, "/usr/bin/python", 15) == 0) {
				auparse_first_record(au);
				f = auparse_find_field(au, "comm");
				if (f) {
					exe = auparse_interpret_field(au);
					// We can do this because comm is
					// guaranteed to be 16 bytes max.
					strcpy(D.how, exe);
				}
			}
			// FIXME: sh, perl
		} else {
			rc = auparse_goto_record_num(au, recno);
			if (rc != 1) {
				free(syscall);
				return 1;
			}
			auparse_first_field(au);
		}

		// action & object
		if (saved) {
			const char *act = classify_record_map_i2s(saved);
			if (act)
				D.action = strdup(act);
		} else
			classify_syscall(au, syscall, type);
	}

	free(syscall);
	return 0;
}

static value_t find_simple_object(auparse_state_t *au, int type)
{
	value_t o = set_record(0, UNSET);
	const char *f = NULL;

	auparse_first_field(au);
	switch (type)
	{
		case AUDIT_SERVICE_START:
		case AUDIT_SERVICE_STOP:
			f = auparse_find_field(au, "unit");
			D.thing.what = CLASS_WHAT_SERVICE;
			break;
		case AUDIT_SYSTEM_RUNLEVEL:
			f = auparse_find_field(au, "new-level");
			D.thing.what = CLASS_WHAT_SYSTEM;
			break;
		case AUDIT_USER_ROLE_CHANGE:
			f = auparse_find_field(au, "selected-context");
			D.thing.what = CLASS_WHAT_USER_SESSION;
			break;
		case AUDIT_ROLE_ASSIGN:
		case AUDIT_ROLE_REMOVE:
		case AUDIT_ADD_USER:
		case AUDIT_DEL_USER:
		case AUDIT_ADD_GROUP:
		case AUDIT_DEL_GROUP:
			f = auparse_find_field(au, "id");
			if (f == NULL) {
				auparse_first_record(au);
				f = auparse_find_field(au, "acct");
			}
			D.thing.what = CLASS_WHAT_ACCT;
			break;
		case AUDIT_USER_START:
		case AUDIT_USER_END:
		case AUDIT_USER_ERR:
			f = auparse_find_field(au, "terminal");
			D.thing.what = CLASS_WHAT_USER_SESSION;
			break;
		case AUDIT_USER_LOGIN:
		case AUDIT_USER_LOGOUT:
			f = auparse_find_field(au, "exe");
			D.thing.what = CLASS_WHAT_USER_SESSION;
			break;
		case AUDIT_USER_AUTH:
		case AUDIT_USER_ACCT:
		case AUDIT_USER_MGMT:
		case AUDIT_CRED_ACQ:
		case AUDIT_CRED_REFR:
		case AUDIT_CRED_DISP:
		case AUDIT_USER_CHAUTHTOK:
			f = auparse_find_field(au, "acct");
			D.thing.what = CLASS_WHAT_USER_SESSION;
			break;
		case AUDIT_USER_CMD:
			f = auparse_find_field(au, "cmd");
			D.thing.what = CLASS_WHAT_PROCESS;
			break;
		case AUDIT_VIRT_MACHINE_ID:
			f = auparse_find_field(au, "vm");
			D.thing.what = CLASS_WHAT_VM;
			break;
		case AUDIT_VIRT_RESOURCE:
			f = auparse_find_field(au, "resrc");
			D.thing.what = CLASS_WHAT_VM;
			break;
		case AUDIT_VIRT_CONTROL:
			f = auparse_find_field(au, "op");
			D.thing.what = CLASS_WHAT_VM;
			break;
		case AUDIT_LABEL_LEVEL_CHANGE:
			f = auparse_find_field(au, "printer");
			D.thing.what = CLASS_WHAT_PRINTER;
			break;
		case AUDIT_CONFIG_CHANGE:
			f = auparse_find_field(au, "key");
			D.thing.what = CLASS_WHAT_AUDIT_CONFIG;
			break;
		case AUDIT_MAC_CONFIG_CHANGE:
			f = auparse_find_field(au, "bool");
			D.thing.what = CLASS_WHAT_MAC_CONFIG;
			break;
		case AUDIT_MAC_STATUS:
			f = auparse_find_field(au, "enforcing");
			D.thing.what = CLASS_WHAT_MAC_CONFIG;
			break;
		case AUDIT_USER:
			f = auparse_find_field(au, "addr");
			break;
		case AUDIT_USYS_CONFIG:
			f = auparse_find_field(au, "op");
			break;
		case AUDIT_CRYPTO_KEY_USER:
			f = auparse_find_field(au, "fp");
			D.thing.what = CLASS_WHAT_USER_SESSION;
			break;
		case AUDIT_CRYPTO_SESSION:
			f = auparse_find_field(au, "addr");
			D.thing.what = CLASS_WHAT_USER_SESSION;
			break;
		default:
			break;
	}
	if (f) {
		o = set_record(0, 0);
		o = set_field(o, auparse_get_field_num(au));
	}
	return o;
}

static value_t find_simple_obj_secondary(auparse_state_t *au, int type)
{
	value_t o = set_record(0, UNSET);
	const char *f = NULL;

	// FIXME: maybe pass flag indicating if this is needed
	auparse_first_field(au);
	switch (type)
	{
		case AUDIT_USER_LOGIN:
		case AUDIT_USER_LOGOUT:
			f = auparse_find_field(au, "terminal");
			break;
		case AUDIT_VIRT_CONTROL:
			f = auparse_find_field(au, "vm");
			break;
		case AUDIT_VIRT_RESOURCE:
			f = auparse_find_field(au, "vm");
			break;
		case AUDIT_CRYPTO_SESSION:
			f = auparse_find_field(au, "rport");
			break;
		default:
			break;
	}
	if (f) {
		o = set_record(0, 0);
		o = set_field(o, auparse_get_field_num(au));
	}
	return o;
}

static void collect_simple_subj_attr(auparse_state_t *au)
{
	value_t attr;

        if (D.opt == CLOPT_NO_ATTRS)
                return;

        auparse_first_record(au);
        auparse_first_field(au);
	add_subj_attr(au, "pid", 0); // Just pass 0 since simple is 1 record
	add_subj_attr(au, "subj", 0);
}

static int classify_simple(auparse_state_t *au)
{
	const char *f, *act;
	int type = auparse_get_type(au);

	// netfilter_cfg sometimes emits 1 record events
	if (type == AUDIT_NETFILTER_CFG)
		return 1;

	// Some older OS do not have PROCTITLE records
	if (type == AUDIT_SYSCALL)
		return classify_compound(au);

	// This is for events that follow:
	// auid, (op), (uid), stuff
	if (type == AUDIT_CONFIG_CHANGE || type == AUDIT_FEATURE_CHANGE ||
			type == AUDIT_SECCOMP || type == AUDIT_ANOM_ABEND) {
		// Subject - primary
		set_prime_subject(au, "auid", 0);

		// Session
		add_session(au, 0);

		// Subject attrs
		collect_simple_subj_attr(au);

		// action
		if (type == AUDIT_CONFIG_CHANGE) {
			auparse_first_field(au);
			f = auparse_find_field(au, "op");
			if (f) {
				const char *str = auparse_interpret_field(au);
				if (*str == '"')
					str++;
				if (strncmp(str, "add_rule", 8) == 0) {
					D.action = strdup("added-audit-rule");
					D.thing.primary =
						find_simple_object(au, type);
				} else if (strncmp(str,"remove_rule",11) == 0){
					D.action = strdup("deleted-audit-rule");
					D.thing.primary =
						find_simple_object(au, type);
				} else {
					act = classify_record_map_i2s(type);
					if (act)
						D.action = strdup(act);
					else
						goto map;
				}
			} else
				goto map;
		} else {
map:
			act = classify_record_map_i2s(type);
			if (act)
				D.action = strdup(act);
			auparse_first_record(au);
		}

		// object
		if (type == AUDIT_FEATURE_CHANGE) {
			// Subject - secondary
			auparse_first_field(au);
			set_secondary_subject(au, "uid", 0);

			// how
			f = auparse_find_field(au, "exe");
			if (f) {
				const char *sig = auparse_interpret_field(au);
				D.how = strdup(sig);
			}

			// object
			set_prime_object(au, "feature", 0);
		}

		if (type == AUDIT_SECCOMP) {
			// Subject - secondary
			auparse_first_field(au);
			if (set_secondary_subject(au, "uid", 0))
				auparse_first_record(au);

			// how
			f = auparse_find_field(au, "exe");
			if (f) {
				const char *sig = auparse_interpret_field(au);
				D.how = strdup(sig);
			}

			// Object
			if (set_prime_object(au, "syscall", 0))
				auparse_first_record(au);
		}

		if (type == AUDIT_ANOM_ABEND) {
			// Subject - secondary
			auparse_first_field(au);
			if (set_secondary_subject(au, "uid", 0))
				auparse_first_record(au);

			//object
			if (set_prime_object(au, "exe", 0))
				auparse_first_record(au);

			// how
			f = auparse_find_field(au, "sig");
			if (f) {
				const char *sig = auparse_interpret_field(au);
				D.how = strdup(sig);
			}
		}

		// Results
		set_results(au, 0);

		return 0;
	}

	// This one is atypical
	if (type == AUDIT_LOGIN) {
		// Secondary
		if (set_secondary_subject(au, "uid", 0))
			auparse_first_record(au);

		// Subject attrs
		collect_simple_subj_attr(au);

		// Subject
		if (set_prime_subject(au, "old-auid", 0))
			auparse_first_record(au);

		// Object
		if (set_prime_object(au, "auid", 0))
			auparse_first_record(au);

		// Session
		add_session(au, 0);

		// Results
		set_results(au, 0);

		// action
		act = classify_record_map_i2s(type);
		if (act)
			D.action = strdup(act);

		// How
		D.thing.what = CLASS_WHAT_USER_SESSION;

		return 0;
	}

	if (type >= AUDIT_FIRST_DAEMON && 
		type < AUDIT_LAST_DAEMON) {
		// Subject - primary
		set_prime_subject(au, "auid", 0);

		// Secondary - optional
		if (set_secondary_subject(au, "uid", 0))
			auparse_first_record(au);

		// Session - optional
		if (add_session(au, 0))
			auparse_first_record(au);

		// Subject attrs
		collect_simple_subj_attr(au);

		// action
		act = classify_record_map_i2s(type);
		if (act)
			D.action = strdup(act);

		// Object type
		D.thing.what = CLASS_WHAT_SERVICE;

		// Results
		set_results(au, 0);
		return 0;
	}

	// This is for events that follow:
	// uid, auid, ses, res, find_simple_object
	//
	// Subject - alias, uid comes before auid
	if (set_secondary_subject(au, "uid", 0))
		auparse_first_record(au);

	// Subject - primary
	set_prime_subject(au, "auid", 0);

	// Session
	add_session(au, 0);

	// Subject attrs
	collect_simple_subj_attr(au);

	// Results
	set_results(au, 0);

	// action
	act = classify_record_map_i2s(type);
	if (act)
		D.action = strdup(act);

	// object
	D.thing.primary = find_simple_object(au, type);
	D.thing.secondary = find_simple_obj_secondary(au, type);

	// how
	if (type == AUDIT_SYSTEM_BOOT) {
		D.thing.what = CLASS_WHAT_SYSTEM;
		return 0;
	} else if (type == AUDIT_SYSTEM_SHUTDOWN) {
		D.thing.what = CLASS_WHAT_SERVICE;
		return 0;
	}
	auparse_first_record(au);
	f = auparse_find_field(au, "exe");
	if (f) {
		const char *exe = auparse_interpret_field(au);
		D.how = strdup(exe);
		if (strncmp(D.how, "/usr/bin/python", 15) == 0) {
			auparse_first_record(au);
			f = auparse_find_field(au, "comm");
			if (f) {
				free(D.how);
				exe = auparse_interpret_field(au);
				D.how = strdup(exe);
			}
		}
		//  FIXME: sh, perl, etc
	}

	return 0;
}

/*
 * This is the main entry point for the classification. This function
 * will analyze the current record to pick out the important pieces.
 */
int auparse_classify(auparse_state_t *au, classify_option_t opt)
{
	int rc = auparse_first_record(au);
	unsigned num = auparse_get_num_records(au);

	// Reset cursor - no idea what we are being handed
	auparse_first_record(au);
	clear_classify(&D);
	D.opt = opt;

	// If we have more than one record in the event its a syscall based
	// event. Otherwise its a simple event with all pieces in the same
	// record.
	if (num > 1)
		rc = classify_compound(au);
	else
		rc = classify_simple(au);	

	// Reset the cursor
	auparse_first_record(au);
	return rc;
}

/*
 * This function positions the internal cursor to the record and field that
 * the location refers to.
 * Returns: -1 = error, 0 uninitialized, 1 == success
 */
static int seek_field(auparse_state_t *au, value_t location)
{
	int record, field, rc;

	if (is_unset(location))
		return 0;

	record = get_record(location);
	field = get_field(location);

	rc = auparse_goto_record_num(au, record);
	if (rc != 1)
		return -1;

	rc = auparse_goto_field_num(au, field);
	if (rc != 1)
		return -1;

	return 1;
}

int auparse_classify_session(auparse_state_t *au)
{
	return seek_field(au, D.session);
}

int auparse_classify_subject_primary(auparse_state_t *au)
{
	return seek_field(au, D.actor.primary);
}

int auparse_classify_subject_secondary(auparse_state_t *au)
{
	return seek_field(au, D.actor.secondary);
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_classify_subject_first_attribute(auparse_state_t *au)
{
	if (D.actor.attr.cnt) {
		data_node *n;

		cllist_first(&D.actor.attr);
		n = cllist_get_cur(&D.actor.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_classify_subject_next_attribute(auparse_state_t *au)
{
	if (D.actor.attr.cnt) {
		data_node *n;

		n = cllist_next(&D.actor.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

const char *auparse_classify_get_action(auparse_state_t *au)
{
	return D.action;
}

int auparse_classify_object_primary(auparse_state_t *au)
{
	return seek_field(au, D.thing.primary);
}

int auparse_classify_object_secondary(auparse_state_t *au)
{
	return seek_field(au, D.thing.secondary);
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_classify_object_first_attribute(auparse_state_t *au)
{
	if (D.thing.attr.cnt) {
		data_node *n;

		cllist_first(&D.thing.attr);
		n = cllist_get_cur(&D.thing.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

// Returns: -1 = error, 0 uninitialized, 1 == success
int auparse_classify_object_next_attribute(auparse_state_t *au)
{
	if (D.thing.attr.cnt) {
		data_node *n;

		n = cllist_next(&D.thing.attr);
		if (n)
			return seek_field(au, n->num);
	}
	return 0;
}

const char *auparse_classify_object_type(auparse_state_t *au)
{
	return classify_obj_type_map_i2s(D.thing.what);
}

int auparse_classify_get_results(auparse_state_t *au)
{
	return seek_field(au, D.results);
}

const char *auparse_classify_how(auparse_state_t *au)
{
	return D.how;
}

