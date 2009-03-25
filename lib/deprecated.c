/* deprecated.c -- This file is the trash heap of things about to leave 
 * Copyright 2006-07 Red Hat Inc., Durham, North Carolina.
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

#include "config.h"
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "libaudit.h"
#include "private.h"

extern int audit_archadded hidden;
extern int audit_syscalladded hidden;
extern unsigned int audit_elf hidden;
extern int audit_priority(int xerrno) hidden;

int audit_request_rules_list(int fd)
{
	int rc = audit_send(fd, AUDIT_LIST, NULL, 0);
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending rule list request (%s)", 
			strerror(-rc));
	return rc;
}
hidden_def(audit_request_rules_list)

int audit_add_rule(int fd, struct audit_rule *rule, int flags, int action)
{
	int rc;

	rule->flags  = flags;
	rule->action = action;
	rc = audit_send(fd, AUDIT_ADD, rule, sizeof(struct audit_rule));
	if (rc < 0)
		audit_msg(audit_priority(errno),
			"Error sending add rule request (%s)",
				errno == EEXIST ?
				"Rule exists" :	strerror(-rc));
	return rc;
}
hidden_def(audit_add_rule)

int audit_delete_rule(int fd, struct audit_rule *rule, int flags, int action)
{
	int rc;

	rule->flags  = flags;
	rule->action = action;
	rc = audit_send(fd, AUDIT_DEL, rule, sizeof(struct audit_rule));
	if (rc < 0) {
		if (rc == -ENOENT)
			audit_msg(LOG_WARNING,
			"Error sending delete rule request (No rule matches)");
		else
			audit_msg(audit_priority(errno),
				"Error sending delete rule request (%s)",
				strerror(-rc));
	}
	return rc;
}
hidden_def(audit_delete_rule)

/*
 * This function will send a user space message to the kernel.
 * It returns the sequence number which is > 0 on success  
 * or <= 0 on error. (pam uses this) This is the main audit sending
 * function now.
 */
int audit_send_user_message(int fd, int type, hide_t hide_error,
	const char *message)
{
	int retry_cnt = 0;
	int rc;
retry:
	rc = audit_send(fd, type, message, strlen(message)+1);
	if (rc == -ECONNREFUSED) {
		/* This is here to let people that build their own kernel
		   and disable the audit system get in. ECONNREFUSED is
		   issued by the kernel when there is "no on listening". */
		return 0;
	} else if (rc == -EPERM && getuid() != 0 && hide_error == HIDE_IT) {
		/* If we get this, then the kernel supports auditing
		 * but we don't have enough privilege to write to the
		 * socket. Therefore, we have already been authenticated
		 * and we are a common user. Just act as though auditing
		 * is not enabled. Any other error we take seriously.
		 * This is here basically to satisfy Xscreensaver. */
		return 0;
	} else if (rc == -EINVAL) {
		/* If we get this, the kernel doesn't understand the
		 * netlink message type. This is most likely due to
		 * being an old kernel. Use the old message type. */
		if (type >= AUDIT_FIRST_USER_MSG && 
				type <= AUDIT_LAST_USER_MSG && !retry_cnt) {

			/* do retry */
			type = AUDIT_USER;
			retry_cnt++;
			goto retry;
		} 
	}
	return rc;
}
hidden_def(audit_send_user_message)

int audit_rule_syscall(struct audit_rule *rule, int scall)
{
	int word = AUDIT_WORD(scall);
	int bit  = AUDIT_BIT(scall);

	if (word >= (AUDIT_BITMASK_SIZE-1)) 
		return -1;
	rule->mask[word] |= bit;
	return 0;
}
hidden_def(audit_rule_syscall)

int audit_rule_syscallbyname(struct audit_rule *rule,
                             const char *scall)
{
	int nr, i;
	int machine;

	if (!strcmp(scall, "all")) {
		for (i = 0; i < (AUDIT_BITMASK_SIZE-1); i++) 
			rule->mask[i] = ~0;
		return 0;
	}
	if (!audit_elf)
		machine = audit_detect_machine();
	else
		machine = audit_elf_to_machine(audit_elf);
	if (machine < 0)
		return -2;
	nr = audit_name_to_syscall(scall, machine);
	if (nr < 0) {
		if (isdigit(scall[0]))
			nr = strtol(scall, NULL, 0);
	}
	if (nr >= 0) 
		return audit_rule_syscall(rule, nr);
	return -1;
}
hidden_def(audit_rule_syscallbyname)

// Delete this with audit_rule_fieldpair
static int name_to_uid(const char *name, uid_t *uid)
{
        struct passwd *pw;

        pw = getpwnam(name);
        if (pw == NULL)
                return 1;

        memset(pw->pw_passwd, ' ', strlen(pw->pw_passwd));
        *uid = pw->pw_uid;
        return 0;
}

// Delete this with audit_rule_fieldpair
static int name_to_gid(const char *name, gid_t *gid)
{
        struct group *gr;

        gr = getgrnam(name);
        if (gr == NULL)
                return 1;

        *gid = gr->gr_gid;
        return 0;
}

int audit_rule_fieldpair(struct audit_rule *rule, const char *pair, int flags)
{
	const char *f = pair;
	char       *v;
	int        op;
	int        field;
	int        vlen;
    
	if (f == NULL)
		return -1;

	/* look for 2-char operators first
	   then look for 1-char operators afterwards
	   when found, null out the bytes under the operators to split
	   and set value pointer just past operator bytes
	*/
	if ( (v = strstr(pair, "!=")) ) {
		*v++ = '\0';
		*v++ = '\0';
		op = AUDIT_NEGATE; // legacy
		// op = AUDIT_NOT_EQUAL;
	} else if ( (v = strstr(pair, ">")) ) {
		return -10;
	} else if ( (v = strstr(pair, "<")) ) {
		return -10;
	} else if ( (v = strstr(pair, "&")) ) {
		return -10;
	} else if ( (v = strstr(pair, "=")) ) {
		*v++ = '\0';
		op = 0; // legacy 
		// op = AUDIT_EQUAL;
	}

	if (v == NULL)
		return -1;
	
	if (*f == 0)
		return -22;

	if (*v == 0)
		return -20;

	audit_msg(LOG_DEBUG,"pair=%s\n", f);
	if ((field = audit_name_to_field(f)) < 0) 
		return -2;

	/* Exclude filter can be used only with MSGTYPE field */
	if (flags == AUDIT_FILTER_EXCLUDE && field != AUDIT_MSGTYPE)
		return -12; 

	audit_msg(LOG_DEBUG,"f%d%s%s\n", field, audit_operator_to_symbol(op),v);
	rule->fields[rule->field_count] = field | op;
	switch (field)
	{
		case AUDIT_UID:
		case AUDIT_EUID:
		case AUDIT_SUID:
		case AUDIT_FSUID:
		case AUDIT_LOGINUID:
			// Do positive & negative separate for 32 bit systems
			vlen = strlen(v);
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtoul(v, NULL, 0);
			else if (vlen >= 2 && *(v)=='-' &&
						(isdigit((char)*(v+1))))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else {
				if (name_to_uid(v, 
					&rule->values[rule->field_count])) {
					audit_msg(LOG_ERR, "Unknown user: %s",
						v);
					return -2;
				}
			}
			break;
		case AUDIT_GID:
		case AUDIT_EGID:
		case AUDIT_SGID:
		case AUDIT_FSGID:
			if (isdigit((char)*(v))) 
				rule->values[rule->field_count] = 
					strtol(v, NULL, 0);
			else {
				if (name_to_gid(v, 
					&rule->values[rule->field_count])) {
					audit_msg(LOG_ERR, "Unknown group: %s",
						v);
					return -2;
				}
			}
			break;
		case AUDIT_EXIT:
			if (flags != AUDIT_FILTER_EXIT)
				return -7;
			vlen = strlen(v);
			if (isdigit((char)*(v)))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else if (vlen >= 2 && *(v)=='-' &&
					(isdigit((char)*(v+1))))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else {
				rule->values[rule->field_count] =
						audit_name_to_errno(v);
				if (rule->values[rule->field_count] == 0) 
					return -15;
			}
			break;
		case AUDIT_MSGTYPE:
			if (flags != AUDIT_FILTER_EXCLUDE)
				return -9;

			if (isdigit((char)*(v)))
				rule->values[rule->field_count] =
					strtol(v, NULL, 0);
			else
				if (audit_name_to_msg_type(v) > 0)
					rule->values[rule->field_count] =
						audit_name_to_msg_type(v);
				else
					return -8;
			break;
		case AUDIT_ARCH:
			if (audit_syscalladded) 
				return -3;
			if (!(op == AUDIT_NEGATE || op == 0))
				return -13;
			if (isdigit((char)*(v))) {
				int machine;

				errno = 0;
				audit_elf = strtoul(v, NULL, 0);
				if (errno) 
					return -5;

				// Make sure we have a valid mapping
				machine = audit_elf_to_machine(audit_elf);
				if (machine < 0)
					return -5;
			}
			else {
				// what do we want? i686, x86_64, ia64
				// or b64, b32
				int machine;
				unsigned int bits=0, elf;
				const char *arch=v;
				if (strcasecmp("b64", arch) == 0) {
					bits = __AUDIT_ARCH_64BIT;
					machine = audit_detect_machine();
				} else if (strcasecmp("b32", arch) == 0) {
					bits = ~__AUDIT_ARCH_64BIT;
					machine = audit_detect_machine();
				} 
				else 
					machine = audit_name_to_machine(arch);

				if (machine < 0) 
					return -4;

				/* Here's where we fixup the machine.
				 * for example, they give x86_64 & want 32 bits.
				 * we translate that to i686. */
				if (bits == ~__AUDIT_ARCH_64BIT &&
					machine == MACH_86_64)
						machine = MACH_X86;
				else if (bits == ~__AUDIT_ARCH_64BIT &&
					machine == MACH_PPC64)
						machine = MACH_PPC;
				else if (bits == ~__AUDIT_ARCH_64BIT &&
					machine == MACH_S390X)
						machine = MACH_S390;

				/* Check for errors - return -6 
				 * We don't allow 32 bit machines to specify 
				 * 64 bit. */
				switch (machine)
				{
					case MACH_X86:
						if (bits == __AUDIT_ARCH_64BIT)
							return -6;
						break;
					case MACH_IA64:
						if (bits == ~__AUDIT_ARCH_64BIT)
							return -6;
						break;
					case MACH_PPC:
						if (bits == __AUDIT_ARCH_64BIT)
							return -6;
						break;
					case MACH_S390:
						if (bits == __AUDIT_ARCH_64BIT)
							return -6;
						break;
					case MACH_86_64: /* fallthrough */
					case MACH_PPC64: /* fallthrough */
					case MACH_S390X: /* fallthrough */
						break;
					default:
						return -6;
				}

				/* OK, we have the machine type, now convert
				   to elf. */
				elf = audit_machine_to_elf(machine);
				if (elf == 0)
					return -5;

				audit_elf = elf;
			}
			rule->values[rule->field_count] = audit_elf;
			audit_archadded = 1;
			break;
		case AUDIT_FILETYPE:
			if (flags != AUDIT_FILTER_EXIT && flags != AUDIT_FILTER_ENTRY)
				return -17;
			rule->values[rule->field_count] =
				audit_name_to_ftype(v);
			if (rule->values[rule->field_count] < 0) {
				return -16;
			}
			break;
		/* These are strings */
		case AUDIT_SUBJ_USER:
		case AUDIT_SUBJ_ROLE:
		case AUDIT_SUBJ_TYPE:
		case AUDIT_SUBJ_SEN:
		case AUDIT_SUBJ_CLR:
		case AUDIT_OBJ_USER:
		case AUDIT_OBJ_ROLE:
		case AUDIT_OBJ_TYPE:
		case AUDIT_OBJ_LEV_LOW:
		case AUDIT_OBJ_LEV_HIGH:
		case AUDIT_WATCH:
		case AUDIT_PERM:
		case AUDIT_DIR:
		case AUDIT_FILTERKEY:
			return -10;
                case AUDIT_DEVMAJOR...AUDIT_INODE:
                case AUDIT_SUCCESS:
			if (flags != AUDIT_FILTER_EXIT)
				return -7;
			/* fallthrough */
		default:
			if (field == AUDIT_INODE) {
				if (!(op == AUDIT_NEGATE || op == 0))
					return -13;
			}
			if (field == AUDIT_PPID && (flags != AUDIT_FILTER_EXIT
				&& flags != AUDIT_FILTER_ENTRY))
				return -17;
			
			if (flags == AUDIT_FILTER_EXCLUDE)
				return -18;
			
			if (!isdigit((char)*(v)))
				return -21;

			rule->values[rule->field_count] = strtol(v, NULL, 0);
			break;
	}
	++rule->field_count;
	return 0;
}
hidden_def(audit_rule_fieldpair)

void audit_rule_free(struct audit_rule *rule)
{
	free(rule);
}
hidden_def(audit_rule_free)

// FIXME: delete this function after bumping the SONAME NUMBER
int audit_log_avc(int fd, int type, const char *fmt, va_list ap)
{
	type = fd;
        return 0;
}
hidden_def(audit_log_avc)

