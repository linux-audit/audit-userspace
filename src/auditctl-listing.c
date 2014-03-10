/* auditctl-listing.c -- 
 * Copyright 2014 Red Hat Inc., Durham, North Carolina.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auditctl-listing.h"
#include "private.h"


/* Global functions */
int audit_print_reply(struct audit_reply *rep);

/* Global vars */
extern int list_requested;
extern char key[AUDIT_MAX_KEY_LEN+1];
extern int printed;
extern const char key_sep[2];

/*
 * Returns 1 if rule should be printed & 0 if not
 */
int key_match(struct audit_reply *rep)
{
	int i;
	size_t boffset = 0;

	if (key[0] == 0)
		return 1;

	// At this point, we have a key
	for (i = 0; i < rep->ruledata->field_count; i++) {
		int field = rep->ruledata->fields[i] & ~AUDIT_OPERATORS;
		if (field == AUDIT_FILTERKEY) {
			char *keyptr;
			if (asprintf(&keyptr, "%.*s", rep->ruledata->values[i],
				     &rep->ruledata->buf[boffset]) < 0)
				keyptr = NULL;
			else if (strstr(keyptr, key)) {
				free(keyptr);
				return 1;
			}
			free(keyptr);
		}
		if (((field >= AUDIT_SUBJ_USER && field <= AUDIT_OBJ_LEV_HIGH)
                     && field != AUDIT_PPID) || field == AUDIT_WATCH ||
			field == AUDIT_DIR || field == AUDIT_FILTERKEY) {
				boffset += rep->ruledata->values[i];
		}
	}
	return 0;
}

/*
 * This function detects if we have a watch. A watch is detected when we
 * have syscall == all and a perm field.
 */
static int is_watch(const struct audit_reply *rep)
{
	int i, perm = 0, all = 1;

	for (i = 0; i < rep->ruledata->field_count; i++) {
		int field = rep->ruledata->fields[i] & ~AUDIT_OPERATORS;
		if (field == AUDIT_PERM)
			perm = 1;
		// Watches can have only 4 field types
		if (field != AUDIT_PERM && field != AUDIT_FILTERKEY &&
			field != AUDIT_DIR && field != AUDIT_WATCH)
			return 0;
	}

	if (((rep->ruledata->flags & AUDIT_FILTER_MASK) != AUDIT_FILTER_USER) &&
		((rep->ruledata->flags & AUDIT_FILTER_MASK) !=
					 AUDIT_FILTER_TASK) &&
		((rep->ruledata->flags & AUDIT_FILTER_MASK) !=
						AUDIT_FILTER_EXCLUDE)) {
		for (i = 0; i < (AUDIT_BITMASK_SIZE-1); i++) {
			if (rep->ruledata->mask[i] != (uint32_t)~0) {
				all = 0;
				break;
			}
		}
	}
	if (perm && all)
		return 1;
	return 0;
}

static void print_arch(unsigned int value, int op)
{
	unsigned int machine;
	_audit_elf = value;
	machine = audit_elf_to_machine(_audit_elf);
	if (machine < 0)
		printf(" -F arch%s0x%X", audit_operator_to_symbol(op),
				(unsigned)value);
	else {
		const char *ptr = audit_machine_to_name(machine);
		printf(" -F arch%s%s", audit_operator_to_symbol(op), ptr);
	}
}

static void print_syscall(const struct audit_reply *rep)
{
	int first = 1;
	int all = 1;
	unsigned int i;
	int machine = audit_detect_machine();

	/* Rules on the following filters do not take a syscall */
	if (((rep->ruledata->flags & AUDIT_FILTER_MASK) == AUDIT_FILTER_USER) ||
	    ((rep->ruledata->flags & AUDIT_FILTER_MASK) == AUDIT_FILTER_TASK) ||
	    ((rep->ruledata->flags &AUDIT_FILTER_MASK) == AUDIT_FILTER_EXCLUDE))
		return;

	/* See if its all or specific syscalls */
	for (i = 0; i < (AUDIT_BITMASK_SIZE-1); i++) {
		if (rep->ruledata->mask[i] != (uint32_t)~0) {
			all = 0;
			break;
		}
	}

	if (all)
		printf(" -S all");
	else for (i = 0; i < AUDIT_BITMASK_SIZE * 32; i++) {
		int word = AUDIT_WORD(i);
		int bit  = AUDIT_BIT(i);
		if (rep->ruledata->mask[word] & bit) {
			const char *ptr;
			if (_audit_elf)
				machine = audit_elf_to_machine(_audit_elf);
			if (machine < 0)
				ptr = NULL;
			else
				ptr = audit_syscall_to_name(i, machine);
			if (ptr)
				printf(" -S %s%s", first ? "" : ",", ptr);
			else
				printf(" -S %s%d", first ? "" : ",", i);
			first = 0;
		}
	}
}

static void print_field_cmp(int value, int op)
{
	switch (value)
	{
		case AUDIT_COMPARE_UID_TO_OBJ_UID:
			printf(" -C uid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_OBJ_GID:
			printf(" -C gid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EUID_TO_OBJ_UID:
			printf(" -C euid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EGID_TO_OBJ_GID:
			printf(" -C egid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_OBJ_UID:
			printf(" -C auid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SUID_TO_OBJ_UID:
			printf(" -C suid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SGID_TO_OBJ_GID:
			printf(" -C sgid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_FSUID_TO_OBJ_UID:
			printf(" -C fsuid%sobj_uid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_FSGID_TO_OBJ_GID:
			printf(" -C fsgid%sobj_gid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_AUID:
			printf(" -C uid%sauid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_EUID:
			printf(" -C uid%seuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_FSUID:
			printf(" -C uid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_UID_TO_SUID:
			printf(" -C uid%ssuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_FSUID:
			printf(" -C auid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_SUID:
			printf(" -C auid%ssuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_AUID_TO_EUID:
			printf(" -C auid%seuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EUID_TO_SUID:
			printf(" -C euid%ssuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EUID_TO_FSUID:
			printf(" -C euid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SUID_TO_FSUID:
			printf(" -C suid%sfsuid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_EGID:
			printf(" -C gid%segid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_FSGID:
			printf(" -C gid%sfsgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_GID_TO_SGID:
			printf(" -C gid%ssgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EGID_TO_FSGID:
			printf(" -C egid%sfsgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_EGID_TO_SGID:
			printf(" -C egid%ssgid",
				audit_operator_to_symbol(op));
			break;
		case AUDIT_COMPARE_SGID_TO_FSGID:
			printf(" -C sgid%sfsgid",
				audit_operator_to_symbol(op));
			break;
	}
}

/*
 *  This function prints 1 rule from the kernel reply
 */
static void print_rule(struct audit_reply *rep)
{
	unsigned int i;
	size_t boffset = 0;
	int watch = is_watch(rep);

	if (!watch) { /* This is syscall auditing */
		printf("-a %s,%s",
			audit_action_to_name((int)rep->ruledata->action),
				audit_flag_to_name(rep->ruledata->flags));

		// Now find the arch and print it
		for (i = 0; i < rep->ruledata->field_count; i++) {
			int field = rep->ruledata->fields[i] & ~AUDIT_OPERATORS;
			if (field == AUDIT_ARCH) {
				int op = rep->ruledata->fieldflags[i] &
							AUDIT_OPERATORS;
				print_arch(rep->ruledata->values[i], op);
			}
		}
		// And last do the syscalls
		print_syscall(rep);
	}

	// Now iterate over the fields
	for (i = 0; i < rep->ruledata->field_count; i++) {
		const char *name;
		int op = rep->ruledata->fieldflags[i] & AUDIT_OPERATORS;
		int field = rep->ruledata->fields[i] & ~AUDIT_OPERATORS;

		if (field == AUDIT_ARCH)
			continue;	// already printed

		name = audit_field_to_name(field);
		if (name) {
			// Special cases to print the different field types
			// in a meaningful way.
			if (field == AUDIT_MSGTYPE) {
				if (!audit_msg_type_to_name(
						rep->ruledata->values[i]))
					printf(" -F %s%s%d", name,
						audit_operator_to_symbol(op),
						rep->ruledata->values[i]);
				else
					printf(" -F %s%s%s", name,
						audit_operator_to_symbol(op),
						audit_msg_type_to_name(
						rep->ruledata->values[i]));
			} else if ((field >= AUDIT_SUBJ_USER &&
						field <= AUDIT_OBJ_LEV_HIGH)
						&& field != AUDIT_PPID &&
						rep->type == AUDIT_LIST_RULES) {
				printf(" -F %s%s%.*s", name,
						audit_operator_to_symbol(op),
						rep->ruledata->values[i],
						&rep->ruledata->buf[boffset]);
				boffset += rep->ruledata->values[i];
			} else if (field == AUDIT_WATCH) {
				if (watch)
					printf("-w %.*s",
						rep->ruledata->values[i],
						&rep->ruledata->buf[boffset]);
				else
					printf(" -F path=%.*s",
						rep->ruledata->values[i],
						&rep->ruledata->buf[boffset]);
				boffset += rep->ruledata->values[i];
			} else if (field == AUDIT_DIR) {
				if (watch)
					printf("-w %.*s/",
						rep->ruledata->values[i],
						&rep->ruledata->buf[boffset]);
				else
					printf(" -F dir=%.*s",
						rep->ruledata->values[i],
						&rep->ruledata->buf[boffset]);

				boffset += rep->ruledata->values[i];
			} else if (field == AUDIT_FILTERKEY) {
				char *rkey, *ptr;
				if (asprintf(&rkey, "%.*s",
					      rep->ruledata->values[i],
					      &rep->ruledata->buf[boffset]) < 0)
					rkey = NULL;
				boffset += rep->ruledata->values[i];
				ptr = strtok(rkey, key_sep);
				while (ptr) {
					if (watch)
						printf(" -k %s", ptr);
					else
						printf(" -F key=%s", ptr);
					ptr = strtok(NULL, key_sep);
				}
				free(rkey);
			} else if (field == AUDIT_PERM) {
				char perms[5];
				int val=rep->ruledata->values[i];
				perms[0] = 0;
				if (val & AUDIT_PERM_READ)
					strcat(perms, "r");
				if (val & AUDIT_PERM_WRITE)
					strcat(perms, "w");
				if (val & AUDIT_PERM_EXEC)
					strcat(perms, "x");
				if (val & AUDIT_PERM_ATTR)
					strcat(perms, "a");
				if (watch)
					printf(" -p %s", perms);
				else
					printf(" -F perm=%s", perms);
			} else if (field == AUDIT_INODE) {
				// This is unsigned
				printf(" -F %s%s%u", name, 
						audit_operator_to_symbol(op),
						rep->ruledata->values[i]);
			} else if (field == AUDIT_FIELD_COMPARE) {
				print_field_cmp(rep->ruledata->values[i], op);
			} else if (field >= AUDIT_ARG0 && field <= AUDIT_ARG3){
				// Show these as hex
				printf(" -F %s%s0x%X", name, 
						audit_operator_to_symbol(op),
						rep->ruledata->values[i]);
			} else {
				// The default is signed decimal
				printf(" -F %s%s%d", name, 
						audit_operator_to_symbol(op),
						rep->ruledata->values[i]);
			}
		} else {
			 // The field name is unknown 
			printf(" f%d%s%d", rep->ruledata->fields[i],
						audit_operator_to_symbol(op),
						rep->ruledata->values[i]);
		}
	}
	printf("\n");
}

/*
 * This function interprets the reply and prints it to stdout. It returns
 * 0 if no more should be read and 1 to indicate that more messages of this
 * type may need to be read. 
 */
int audit_print_reply(struct audit_reply *rep)
{
	_audit_elf = 0; 
	switch (rep->type) {
		case NLMSG_NOOP:
			return 1;
		case NLMSG_DONE:
			if (printed == 0)
				printf("No rules\n");
			break;
		case NLMSG_ERROR: 
		        printf("NLMSG_ERROR %d (%s)\n",
				-rep->error->error, 
				strerror(-rep->error->error));
			printed = 1;
			break;
		case AUDIT_GET:
			printf("AUDIT_STATUS: enabled=%d flag=%d pid=%d"
			" rate_limit=%d backlog_limit=%d lost=%d backlog=%u\n",
			rep->status->enabled, rep->status->failure,
			rep->status->pid, rep->status->rate_limit,
			rep->status->backlog_limit, rep->status->lost,
			rep->status->backlog);
			printed = 1;
			break;
		case AUDIT_LIST_RULES:
			// This could be redesigned where this one appends to
			// a list. Then when we get nlmsg_done, we loop on
			// calling print_rule()
			list_requested = 0;
			if (key_match(rep) == 0)
				return 1;
			printed = 1;
			print_rule(rep);
			return 1;
		default:
			printf("Unknown: type=%d, len=%d\n", rep->type, 
				rep->nlh->nlmsg_len);
			printed = 1;
			break;
	}
	return 0;
}

