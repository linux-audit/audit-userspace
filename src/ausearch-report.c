/*
* ausearch-report.c - Format and output events
* Copyright (c) 2005-09,2011-13 Red Hat Inc., Durham, North Carolina.
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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "libaudit.h"
#include "ausearch-options.h"
#include "ausearch-parse.h"
#include "ausearch-lookup.h"
#include "auparse-idata.h"
#include "auparse-defs.h"

/* Local functions */
static void output_raw(llist *l);
static void output_default(llist *l);
static void output_interpreted(llist *l);
static void output_interpreted_node(const lnode *n, const event *e);
static void interpret(char *name, char *val, int comma, int rtype);

/* The machine based on elf type */
static unsigned long machine = -1;
static int cur_syscall = -1;

/* The first syscall argument */
static unsigned long long a0, a1;

/* This function branches to the correct output format */
void output_record(llist *l)
{
	switch (report_format) {
		case RPT_RAW:
			output_raw(l);
			break;
		case RPT_DEFAULT:
			output_default(l);
			break;
		case RPT_INTERP:
			output_interpreted(l);
			break;
		case RPT_PRETTY:
			break;
		default:
			fprintf(stderr, "Report format error");
			exit(1);
	}
}

/* This function will output the record as is */
static void output_raw(llist *l)
{
	const lnode *n;

	list_first(l);
	n = list_get_cur(l);
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	do {
		puts(n->message);
	} while ((n=list_next(l)));
}

/*
 * This function will take the linked list and format it for output. No
 * interpretation is performed. The output order is lifo for everything.
 */
static void output_default(llist *l)
{
	const lnode *n;

	list_last(l);
	n = list_get_cur(l);
	printf("----\ntime->%s", ctime(&l->e.sec));
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	if (n->type >= AUDIT_DAEMON_START && n->type < AUDIT_SYSCALL)
		puts(n->message); // No injection possible
	else {
		do {
			safe_print_string_n(n->message, n->mlen, 1);
		} while ((n=list_prev(l)));
	}
}

/*
 * This function will take the linked list and format it for output. 
 * Interpretation is performed to aid understanding of records. The output
 * order is lifo for everything.
 */
static void output_interpreted(llist *l)
{
	const lnode *n;

	list_last(l);
	n = list_get_cur(l);
	printf("----\n");
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	if (n->type >= AUDIT_DAEMON_START && n->type < AUDIT_SYSCALL) 
		output_interpreted_node(n, &(l->e));
	else {
		do {
			output_interpreted_node(n, &(l->e));
		} while ((n=list_prev(l)));
	}
}

/*
 * This function will cycle through a single record and lookup each field's
 * value that it finds. 
 */
static void output_interpreted_node(const lnode *n, const event *e)
{
	char *ptr, *str = n->message;
	int found, comma = 0;
	int num = n->type;
	struct tm *btm;
	char tmp[32];

	// Reset these because each record could be different
	machine = -1;
	cur_syscall = -1;

	/* Check and see if we start with a node
 	 * If we do, and there is a space in the line
 	 * move the pointer to the first character past
 	 * the space
  	 */
	if (e->node) {
		if ((ptr=strchr(str, ' ')) != NULL) {
			str = ptr+1;
		}
	}

	// First locate time stamp.
	ptr = strchr(str, '(');
	if (ptr == NULL) {
		fprintf(stderr, "can't find time stamp\n");
		return;
	}

	*ptr++ = 0;	/* move to the start of the timestamp */

	// print everything up to it.
	if (num >= 0) {
		const char	* bptr;
		bptr = audit_msg_type_to_name(num);
		if (bptr) {
			if (e->node)
				printf("node=%s ", e->node);
			printf("type=%s msg=audit(", bptr);
			goto no_print;
		}
	} 
	if (e->node)
		printf("node=%s ", e->node);
	printf("%s(", str);
no_print:

	str = strchr(ptr, ')');
	if(str == NULL)
		return;
	*str++ = 0;
	btm = localtime(&e->sec);
	strftime(tmp, sizeof(tmp), "%x %T", btm);
	printf("%s", tmp);
	printf(".%03d:%lu) ", e->milli, e->serial);

	if (n->type == AUDIT_SYSCALL) { 
		a0 = n->a0;
		a1 = n->a1;
	}

	// for each item.
	found = 0;
	while (str && *str && (ptr = strchr(str, '='))) {
		char *name, *val;
		comma = 0;
		found = 1;

		// look back to last space - this is name
		name = ptr;
		while (*name != ' ' && name > str)
			--name;
		*ptr++ = 0;

		// print everything up to the '='
		printf("%s=", str);

		// Some user messages have msg='uid=500   in this case
		// skip the msg= piece since the real stuff is the uid=
		if (strcmp(name, "msg") == 0) {
			str = ptr;
			continue;
		}

		// In the above case, after msg= we need to trim the ' from uid
		if (*name == '\'')
			name++;

		// get string after = to the next space or end - this is value
		if (*ptr == '\'' || *ptr == '"') {
			str = strchr(ptr+1, *ptr);
			if (str) {
				str++;
				if (*str)
					*str++ = 0;
			}
		} else {
			str = strchr(ptr, ',');
			val = strchr(ptr, ' ');
			if (str && val && (str < val)) {
			// Value side  has commas and another field exists
			// Known: LABEL_LEVEL_CHANGE banners=none,none
			// Known: ROLL_ASSIGN new-role=r,r
			// Known: any MAC LABEL can potentially have commas
				int ftype = auparse_interp_adjust_type(n->type,
								name, val);
				if (ftype == AUPARSE_TYPE_MAC_LABEL) {
					str = val;
					*str++ = 0;
				} else {
					*str++ = 0;
					comma = 1;
				}
			} else if (str && (val == NULL)) {
			// Goes all the way to the end. Done parsing
			// Known: MCS context in PATH rec obj=u:r:t:s0:c2,c7
				int ftype = auparse_interp_adjust_type(n->type,
								name, ptr);
				if (ftype == AUPARSE_TYPE_MAC_LABEL)
					str = NULL;
				else {
					*str++ = 0;
					comma = 1;
				}
			} else if (val) {
			// There is another field, point to next (normal path)
				str = val;
				*str++ = 0;
			}
		}
		// val points to begin & str 1 past end
		val = ptr;
		
		// print interpreted string
		interpret(name, val, comma, n->type);
	}
	// If nothing found, just print out as is
	if (!found && ptr == NULL && str)
		safe_print_string(str, 1);

	// If last field had comma, output the rest
	else if (comma)
		safe_print_string(str, 1);
	printf("\n");
}

static void interpret(char *name, char *val, int comma, int rtype)
{
	int type;
	idata id;

	while (*name == ' '||*name == '(')
		name++;

	if (*name == 'a' && strcmp(name, "acct") == 0) {
		// Remove trailing punctuation
		int len = strlen(val);
		if (val[len-1] == ':')
			val[len-1] = 0;
	}
	type = auparse_interp_adjust_type(rtype, name, val);

	if (rtype == AUDIT_SYSCALL || rtype == AUDIT_SECCOMP) {
		if (machine == (unsigned long)-1) 
			machine = audit_detect_machine();
		if (*name == 'a' && strcmp(name, "arch") == 0) {
			unsigned long ival;
			errno = 0;
			ival = strtoul(val, NULL, 16);
			if (errno) {
				printf("arch conversion error(%s) ", val);
				return;
			}
			machine = audit_elf_to_machine(ival);
		}
		if (cur_syscall < 0 && *name == 's' &&
				strcmp(name, "syscall") == 0) {
			unsigned long ival;
			errno = 0;
			ival = strtoul(val, NULL, 10);
			if (errno) {
				printf("syscall conversion error(%s) ", val);
				return;
			}
			cur_syscall = ival;
		}
		id.syscall = cur_syscall;
	} else
		id.syscall = 0;
	id.machine = machine;
	id.a0 = a0;
	id.a1 = a1;
	id.name = name;
	id.val = val;

	char *out = auparse_do_interpretation(type, &id);
	if (type == AUPARSE_TYPE_UNCLASSIFIED)
		printf("%s%c", val, comma ? ',' : ' ');
	else if (name[0] == 'k' && strcmp(name, "key") == 0) {
		char *str, *ptr = out;
		int count = 0;
		while ((str = strchr(ptr, AUDIT_KEY_SEPARATOR))) {
			*str = 0;
			if (count == 0) {
				printf("%s", ptr);
				count++;
			} else
				printf(" key=%s", ptr);
			ptr = str+1;
		}
		if (count == 0)
			printf("%s ", out);
		else
			printf(" key=%s ", ptr);
	} else if (type == AUPARSE_TYPE_TTY_DATA)
		printf("%s", out);
	else
		printf("%s ", out);

	free(out);
}

