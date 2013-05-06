/* auditctl.c -- 
 * Copyright 2004-2013 Red Hat Inc., Durham, North Carolina.
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
 *     Rickard E. (Rik) Faith <faith@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>	/* strdup needs xopen define */
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>	/* For basename */
#include <limits.h>	/* PATH_MAX */
#include "libaudit.h"
#include "private.h"

/* This define controls how many rule options we will allow when
 * reading a rule from a file. 64 fields are allowed by the kernel, so I
 * want to allow that plus a few entries for lists and other such items */
#define NUM_OPTIONS 72

/* This define controls the size of the line that we will request when
 * reading in rules from a file. We need to allow 64 fields. 25 bytes is 
 * the largest syscall name, so lets allow 1600 per line. 
 * Unrealistic - I know. 
 */
#define LINE_SIZE 1600


/* Global functions */
static int handle_request(int status);
static void get_reply(void);
static int audit_print_reply(struct audit_reply *rep);
extern int delete_all_rules(int fd);

/* Global vars */
static int fd = -1;
static int list_requested = 0;
static int add = AUDIT_FILTER_UNSET, del = AUDIT_FILTER_UNSET, action = -1;
static int ignore = 0, continue_error = 0;
static int exclude = 0;
static int multiple = 0;
static struct audit_rule_data *rule_new = NULL;
static char key[AUDIT_MAX_KEY_LEN+1];
static int keylen;
static int printed;
static const char key_sep[2] = { AUDIT_KEY_SEPARATOR, 0 };

/*
 * This function will reset everything used for each loop when loading 
 * a ruleset from a file.
 */
static int reset_vars(void)
{
	list_requested = 0;
	_audit_syscalladded = 0;
	_audit_permadded = 0;
	_audit_archadded = 0;
	_audit_elf = 0;
	add = AUDIT_FILTER_UNSET;
	del = AUDIT_FILTER_UNSET;
	action = -1;
	exclude = 0;
	multiple = 0;

	free(rule_new);
	rule_new = malloc(sizeof(struct audit_rule_data));
	memset(rule_new, 0, sizeof(struct audit_rule_data));
	if (fd < 0) {
		if ((fd = audit_open()) < 0) {
			fprintf(stderr, "Cannot open netlink audit socket\n");
			return 1;
		}
	}
	return 0;
}

static void usage(void)
{
    printf(
    "usage: auditctl [options]\n"
     "    -a <l,a>            Append rule to end of <l>ist with <a>ction\n"
     "    -A <l,a>            Add rule at beginning of <l>ist with <a>ction\n"
     "    -b <backlog>        Set max number of outstanding audit buffers\n"
     "                        allowed Default=64\n"
     "    -c                  Continue through errors in rules\n"
     "    -C f=f              Compare collected fields if available:\n"
     "                        Field name, operator(=,!=), field name\n"
     "    -d <l,a>            Delete rule from <l>ist with <a>ction\n"
     "                        l=task,exit,user,exclude\n"
     "                        a=never,always\n"
     "    -D                  Delete all rules and watches\n"
     "    -e [0..2]           Set enabled flag\n"
     "    -f [0..2]           Set failure flag\n"
     "                        0=silent 1=printk 2=panic\n"
     "    -F f=v              Build rule: field name, operator(=,!=,<,>,<=,\n"
     "                        >=,&,&=) value\n"
     "    -h                  Help\n"
     "    -i                  Ignore errors when reading rules from file\n"
     "    -k <key>            Set filter key on audit rule\n"
     "    -l                  List rules\n"
     "    -m text             Send a user-space message\n"
     "    -p [r|w|x|a]        Set permissions filter on watch\n"
     "                        r=read, w=write, x=execute, a=attribute\n"
     "    -q <mount,subtree>  make subtree part of mount point's dir watches\n"
     "    -r <rate>           Set limit in messages/sec (0=none)\n"
     "    -R <file>           read rules from file\n"
     "    -s                  Report status\n"
     "    -S syscall          Build rule: syscall name or number\n"
     "    -t                  Trim directory watches\n"
     "    -v                  Version\n"
     "    -w <path>           Insert watch at <path>\n"
     "    -W <path>           Remove watch at <path>\n"
     );
}

static int lookup_filter(const char *str, int *filter)
{
	if (strcmp(str, "task") == 0) 
		*filter = AUDIT_FILTER_TASK;
	else if (strcmp(str, "entry") == 0)
		*filter = AUDIT_FILTER_ENTRY;
	else if (strcmp(str, "exit") == 0)
		*filter = AUDIT_FILTER_EXIT;
	else if (strcmp(str, "user") == 0)
		*filter = AUDIT_FILTER_USER;
	else if (strcmp(str, "exclude") == 0) {
		*filter = AUDIT_FILTER_EXCLUDE;
		exclude = 1;
	} else
		return 2;
	return 0;
}

static int lookup_action(const char *str, int *act)
{
	if (strcmp(str, "never") == 0)
		*act = AUDIT_NEVER;
	else if (strcmp(str, "possible") == 0)
		return 1;
	else if (strcmp(str, "always") == 0)
		*act = AUDIT_ALWAYS;
	else
		return 2;
	return 0;
}

/*
 * Returns 0 ok, 1 deprecated action, 2 rule error,
 * 3 multiple rule insert/delete
 */
static int audit_rule_setup(char *opt, int *filter, int *act, int lineno)
{
	int rc;
	char *p;

	if (++multiple != 1)
		return 3;

	p = strchr(opt, ',');
	if (p == NULL || strchr(p+1, ','))
		return 2;
	*p = 0;

	/* Try opt both ways */
	if (lookup_filter(opt, filter) == 2) {
		rc = lookup_action(opt, act);
		if (rc != 0) {
			*p = ',';
			return rc;
		}
	}

	/* Repair the string */
	*p = ',';
	opt = p+1;

	/* If flags are empty, p+1 must be the filter */
	if (*filter == AUDIT_FILTER_UNSET)
		lookup_filter(opt, filter);
	else {
		rc = lookup_action(opt, act);
		if (rc != 0)
			return rc;
	}

	/* Make sure we set both */
	if (*filter == AUDIT_FILTER_UNSET || *act == -1)
		return 2;

	/* Consolidate rules on exit filter */
	if (*filter == AUDIT_FILTER_ENTRY) {
		*filter = AUDIT_FILTER_EXIT;
		fprintf(stderr,
		    "Warning - entry rules deprecated, changing to exit rule");
		if (lineno)
			fprintf(stderr, " in line %d", lineno);
		fprintf(stderr, "\n");
	}

	return 0;
}

/*
 * This function will check the path before accepting it. It returns
 * 1 on error and 0 on success.
 */
static int check_path(const char *path)
{
	char *ptr, *base;
	size_t nlen;
	size_t plen = strlen(path);
	if (plen >= PATH_MAX) {
		fprintf(stderr, "The path passed for the watch is too big\n");
		return 1;
	}
	if (path[0] != '/') {
		fprintf(stderr, "The path must start with '/'\n");
		return 1;
	}
	ptr = strdup(path);
	base = basename(ptr);
	nlen = strlen(base);
	free(ptr);
	if (nlen > NAME_MAX) {
		fprintf(stderr, "The base name of the path is too big\n");
		return 1;
	}

	/* These are warnings, not errors */
	if (strstr(path, ".."))
		fprintf(stderr, 
			"Warning - relative path notation is not supported\n");
	if (strchr(path, '*') || strchr(path, '?'))
		fprintf(stderr, 
			"Warning - wildcard notation is not supported\n");

	return 0;
}

/*
 * Setup a watch.  The "name" of the watch in userspace will be the <path> to
 * the watch.  When this potential watch reaches the kernel, it will resolve
 * down to <name> (of terminating file or directory). 
 * Returns a 1 on success & -1 on failure.
 */
static int audit_setup_watch_name(struct audit_rule_data **rulep, char *path)
{
	int type = AUDIT_WATCH;
	size_t len;
	struct stat buf;

	if (check_path(path))
		return -1;

	// Trim trailing '/' should they exist
	len = strlen(path);
	if (len > 2 && path[len-1] == '/') {
		while (path[len-1] == '/' && len > 1) {
			path[len-1] = 0;
			len--;
		}
	}
	if (stat(path, &buf) == 0) {
		if (S_ISDIR(buf.st_mode))
			type = AUDIT_DIR;
	}
	/* FIXME: might want to check to see that rule is empty */
	if (audit_add_watch_dir(type, rulep, path)) 
		return -1;

	return 1;
}

/*
 * Setup a watch permissions.
 * Returns a 1 on success & -1 on failure.
 */
static int audit_setup_perms(struct audit_rule_data *rule, const char *opt)
{
	unsigned int i, len, val = 0;

	len = strlen(opt);
	if (len > 4)
		return -1;

	for (i = 0; i < len; i++) {
		switch (tolower(opt[i])) {
			case 'r':
				val |= AUDIT_PERM_READ;
				break;
			case 'w':
				val |= AUDIT_PERM_WRITE;
				break;
			case 'x':
				val |= AUDIT_PERM_EXEC;
				break;
			case 'a':
				val |= AUDIT_PERM_ATTR;
				break;
			default:
				fprintf(stderr,
					"Permission %c isn't supported\n",
					opt[i]);
				return -1;
		}
	}

	if (audit_update_watch_perms(rule_new, val) == 0) {
		_audit_permadded = 1;
		return 1;
	}
	return -1;
}

/* 0 success, -1 failure */
static int lookup_itype(const char *kind)
{
        if (strcmp(kind, "sys") == 0)
                return 0;
        if (strcmp(kind, "file") == 0)
                return 0;
        if (strcmp(kind, "exec") == 0)
                return 0;
        if (strcmp(kind, "mkexe") == 0)
                return 0;
        return -1;
}

/* 0 success, -1 failure */
static int lookup_iseverity(const char *severity)
{
        if (strncmp(severity, "inf", 3) == 0)
                return 0;
        if (strncmp(severity, "low", 3) == 0)
                return 0;
        if (strncmp(severity, "med", 3) == 0)
                return 0;
        if (strncmp(severity, "hi", 2) == 0)
                return 0;
        return -1;
}

/* 0 success, -1 failure */
static int check_ids_key(const char *k)
{
	char *ptr, *kindptr, *ratingptr;
	char keyptr[AUDIT_MAX_KEY_LEN+1];

	if (strlen(k) > AUDIT_MAX_KEY_LEN)
		goto fail_exit;

	strncpy(keyptr, k, sizeof(keyptr));
	keyptr[AUDIT_MAX_KEY_LEN] = 0;
	ptr = strchr(keyptr, '-'); // There has to be a - because strncmp
	kindptr = ptr + 1;
	if (*kindptr == 0) 
		goto fail_exit;

	ptr = strchr(kindptr, '-');
	if (ptr) {
		*ptr = 0;
		ratingptr = ptr +1;
	} else // The rules are misconfigured
		goto fail_exit;
	if (*ratingptr == 0) 
		goto fail_exit;

	if (lookup_itype(kindptr)) {
		fprintf(stderr, "ids key type is bad\n");
		return -1;
	}
	if (lookup_iseverity(ratingptr)) {
		fprintf(stderr, "ids key severity is bad\n");
		return -1;
	}
	return 0;

fail_exit:
	fprintf(stderr, "ids key is bad\n");
	return -1;
}

static int equiv_parse(char *optarg, char **mp, char **sub)
{
	char *ptr = strchr(optarg, ',');
	if (ptr == NULL)
		return -1;	// no comma
	*ptr = 0;
	ptr++;
	if (*ptr == 0)
		return -1;	// ends with comma
	*mp = optarg;
	*sub = ptr;
	if (strchr(*sub, ','))
		return -1;	// too many commas
	return 0;
}

int audit_request_rule_list(int fd)
{
	if (audit_request_rules_list_data(fd) > 0) {
		list_requested = 1;
		get_reply();
		return 1;
	}
	return 0;
}

void check_rule_mismatch(int lineno, const char *option)
{
	struct audit_rule_data tmprule;
	unsigned int old_audit_elf = _audit_elf;
	int rc = 0;

	switch (_audit_elf)
	{
		case AUDIT_ARCH_X86_64:
			_audit_elf = AUDIT_ARCH_I386;
			break;
		case AUDIT_ARCH_PPC64:
			_audit_elf = AUDIT_ARCH_PPC;
			break;
		case AUDIT_ARCH_S390X:
			_audit_elf = AUDIT_ARCH_S390;
			break;
	}
	memset(&tmprule, 0, sizeof(struct audit_rule_data));
	audit_rule_syscallbyname_data(&tmprule, option);
	if (memcmp(tmprule.mask, rule_new->mask, AUDIT_BITMASK_SIZE))
		rc = 1;
	_audit_elf = old_audit_elf;
	if (rc) { 
		fprintf(stderr, "WARNING - 32/64 bit syscall mismatch");
		if (lineno)
			fprintf(stderr, " in line %d", lineno);
		fprintf(stderr, ", you should specify an arch\n");
	}
}

// FIXME: Change these to enums
/*
 * returns: -3 deprecated, -2 success - no reply, -1 error - noreply,
 * 0 success - reply, > 0 success - rule
 */
static int setopt(int count, int lineno, char *vars[])
{
    int c;
    int retval = 0, rc;

    optind = 0;
    opterr = 0;
    key[0] = 0;
    keylen = AUDIT_MAX_KEY_LEN;

    while ((retval >= 0) && (c = getopt(count, vars,
			"hicslDvtC:e:f:r:b:a:A:d:S:F:m:R:w:W:k:p:q:")) != EOF) {
	int flags = AUDIT_FILTER_UNSET;
	rc = 10;	// Init to something impossible to see if unused.
        switch (c) {
        case 'h':
		usage();
		retval = -1;
		break;
	case 'i':
		ignore = 1;
		retval = -2;
		break;
	case 'c':
		ignore = 1;
		continue_error = 1;
		retval = -2;
		break;
        case 's':
		retval = audit_request_status(fd);
		if (retval <= 0)
			retval = -1;
		else
			retval = 0; /* success - just get the reply */
		break;
        case 'e':
		if (optarg && ((strcmp(optarg, "0") == 0) ||
				(strcmp(optarg, "1") == 0) ||
				(strcmp(optarg, "2") == 0))) {
			if (audit_set_enabled(fd, strtoul(optarg,NULL,0)) > 0)
				audit_request_status(fd);
			else
				retval = -1;
		} else {
			fprintf(stderr, "Enable must be 0, 1, or 2 was %s\n", 
				optarg);
			retval = -1;
		}
		break;
        case 'f':
		if (optarg && ((strcmp(optarg, "0") == 0) ||
				(strcmp(optarg, "1") == 0) ||
				(strcmp(optarg, "2") == 0))) {
			if (audit_set_failure(fd, strtoul(optarg,NULL,0)) > 0)
				audit_request_status(fd);
			else
				return -1;
		} else {
			fprintf(stderr, "Failure must be 0, 1, or 2 was %s\n", 
				optarg);
			retval = -1;
		}
		break;
        case 'r':
		if (optarg && isdigit(optarg[0])) { 
			uint32_t rate;
			errno = 0;
			rate = strtoul(optarg,NULL,0);
			if (errno) {
				fprintf(stderr, "Error converting rate\n");
				return -1;
			}
			if (audit_set_rate_limit(fd, rate) > 0)
				audit_request_status(fd);
			else
				return -1;
		} else {
			fprintf(stderr, "Rate must be a numeric value was %s\n",
				optarg);
			retval = -1;
		}
		break;
        case 'b':
		if (optarg && isdigit(optarg[0])) {
			uint32_t limit;
			errno = 0;
			limit = strtoul(optarg,NULL,0);
			if (errno) {
				fprintf(stderr, "Error converting backlog\n");
				return -1;
			}
			if (audit_set_backlog_limit(fd, limit) > 0)
				audit_request_status(fd);
			else
				return -1;
		} else {
			fprintf(stderr, 
				"Backlog must be a numeric value was %s\n", 
				optarg);
			retval = -1;
		}
		break;
        case 'l':
		if (count > 4 || count == 3) {
			fprintf(stderr,
				"Wrong number of options for list request\n");
			retval = -1;
			break;
		} 
		if (count == 4) {
			if (strcmp(vars[optind], "-k") == 0) { 
				strncat(key, vars[3], keylen);
				count -= 2;
			} else {
				fprintf(stderr,
					"Only the -k option is allowed\n");
				retval = -1;
				break;
			}
		}
		if (audit_request_rule_list(fd)) {
			list_requested = 1;
			retval = -2;
		} else
			retval = -1;
		break;
        case 'a':
		if (strstr(optarg, "task") && _audit_syscalladded) {
			fprintf(stderr, 
				"Syscall auditing requested for task list\n");
			retval = -1;
		} else {
			rc = audit_rule_setup(optarg, &add, &action, lineno);
			if (rc == 3) {
				fprintf(stderr,
		"Multiple rule insert/delete operations are not allowed\n");
				retval = -1;
			} else if (rc == 2) {
				fprintf(stderr, 
					"Append rule - bad keyword %s\n",
					optarg);
				retval = -1;
			} else if (rc == 1) {
				fprintf(stderr, 
				    "Append rule - possible is deprecated\n");
				return -3; /* deprecated - eat it */
			} else
				retval = 1; /* success - please send */
		}
		break;
        case 'A': 
		if (strstr(optarg, "task") && _audit_syscalladded) {
			fprintf(stderr, 
			   "Error: syscall auditing requested for task list\n");
			retval = -1;
		} else {
			rc = audit_rule_setup(optarg, &add, &action, lineno);
			if (rc == 3) {
				fprintf(stderr,
		"Multiple rule insert/delete operations are not allowed\n");
				retval = -1;
			} else if (rc == 2) {
				fprintf(stderr,
				"Add rule - bad keyword %s\n", optarg);
				retval = -1;
			} else if (rc == 1) {
				fprintf(stderr, 
				    "Append rule - possible is deprecated\n");
				return -3; /* deprecated - eat it */
			} else {
				add |= AUDIT_FILTER_PREPEND;
				retval = 1; /* success - please send */
			}
		}
		break;
        case 'd': 
		rc = audit_rule_setup(optarg, &del, &action, lineno);
		if (rc == 3) {
			fprintf(stderr,
		"Multiple rule insert/delete operations are not allowed\n");
			retval = -1;
		} else if (rc == 2) {
			fprintf(stderr, "Delete rule - bad keyword %s\n", 
				optarg);
			retval = -1;
		} else if (rc == 1) {
			fprintf(stderr, 
			    "Delete rule - possible is deprecated\n");
			return -3; /* deprecated - eat it */
		} else
			retval = 1; /* success - please send */
		break;
        case 'S': {
		int unknown_arch = !_audit_elf;
		/* Do some checking to make sure that we are not adding a
		 * syscall rule to a list that does not make sense. */
		if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
				AUDIT_FILTER_TASK || (del & 
				(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) == 
				AUDIT_FILTER_TASK)) {
			fprintf(stderr, 
			  "Error: syscall auditing being added to task list\n");
			return -1;
		} else if (((add & (AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
				AUDIT_FILTER_USER || (del &
				(AUDIT_FILTER_MASK|AUDIT_FILTER_UNSET)) ==
				AUDIT_FILTER_USER)) {
			fprintf(stderr, 
			  "Error: syscall auditing being added to user list\n");
			return -1;
		} else if (exclude) {
			fprintf(stderr, 
		    "Error: syscall auditing cannot be put on exclude list\n");
			return -1;
		} else {
			if (unknown_arch) {
				int machine;
				unsigned int elf;
				machine = audit_detect_machine();
				if (machine < 0) {
					fprintf(stderr, 
					    "Error detecting machine type");
					return -1;
				}
				elf = audit_machine_to_elf(machine);
                                if (elf == 0) {
					fprintf(stderr, 
					    "Error looking up elf type");
					return -1;
				}
				_audit_elf = elf;
			}
		}
		rc = audit_rule_syscallbyname_data(rule_new, optarg);
		switch (rc)
		{
			case 0:
				_audit_syscalladded = 1;
				if (unknown_arch && add != AUDIT_FILTER_UNSET)
					check_rule_mismatch(lineno, optarg);
				break;
			case -1:
				fprintf(stderr, "Syscall name unknown: %s\n", 
							optarg);
				retval = -1;
				break;
			case -2:
				fprintf(stderr, "Elf type unknown: 0x%x\n", 
							_audit_elf);
				retval = -1;
				break;
		}}
		break;
        case 'F':
		if (add != AUDIT_FILTER_UNSET)
			flags = add & AUDIT_FILTER_MASK;
		else if (del != AUDIT_FILTER_UNSET)
			flags = del & AUDIT_FILTER_MASK;
		// if the field is arch & there is a -t option...we 
		// can allow it
		else if ((optind >= count) || (strstr(optarg, "arch=") == NULL)
				 || (strcmp(vars[optind], "-t") != 0)) {
			fprintf(stderr, "List must be given before field\n");
			retval = -1;
			break;
		}

		rc = audit_rule_fieldpair_data(&rule_new,optarg,flags);
		if (rc != 0) {
			audit_number_to_errmsg(rc, optarg);
			retval = -1;
		} else {
			if (rule_new->fields[rule_new->field_count-1] ==
						AUDIT_PERM)
				_audit_permadded = 1;
		}

		break;
	case 'C':
		if (add != AUDIT_FILTER_UNSET)
			flags = add & AUDIT_FILTER_MASK;
		else if (del != AUDIT_FILTER_UNSET)
			flags = del & AUDIT_FILTER_MASK;

		rc = audit_rule_interfield_comp_data(&rule_new, optarg, flags);
		if (rc != 0) {
			audit_number_to_errmsg(rc, optarg);
			retval = -1;
		} else {
			if (rule_new->fields[rule_new->field_count - 1] ==
			    AUDIT_PERM)
				_audit_permadded = 1;
		}
		break;
        case 'm':
		if (count > 3) {
			fprintf(stderr,
	"The -m option must be only the only option and takes 1 parameter\n");
			retval = -1;
		} else if (audit_log_user_message( fd, AUDIT_USER,
					optarg, NULL, NULL, NULL, 1) <= 0)
			retval = -1;
		else
			return -2;  // success - no reply for this
		break;
	case 'R':
		fprintf(stderr, "Error - nested rule files not supported\n");
		retval = -1;
		break;
	case 'D':
		if (count > 4 || count == 3) {
			fprintf(stderr,
			    "Wrong number of options for Delete all request\n");
			retval = -1;
			break;
		} 
		if (count == 4) {
			if (strcmp(vars[optind], "-k") == 0) { 
				strncat(key, vars[3], keylen);
				count -= 2;
			} else {
				fprintf(stderr, 
					"Only the -k option is allowed\n");
				retval = -1;
				break;
			}
		}
		retval = delete_all_rules(fd);
		if (retval == 0) {
			(void)audit_request_rule_list(fd);
			key[0] = 0;
			retval = -2;
		}
		break;
	case 'w':
		if (add != AUDIT_FILTER_UNSET ||
			del != AUDIT_FILTER_UNSET) {
			fprintf(stderr,
				"watch option can't be given with a syscall\n");
			retval = -1;
		} else if (optarg) { 
			add = AUDIT_FILTER_EXIT;
			action = AUDIT_ALWAYS;
			_audit_syscalladded = 1;
			retval = audit_setup_watch_name(&rule_new, optarg);
		} else {
			fprintf(stderr, "watch option needs a path\n");	
			retval = -1;
		}
		break;
	case 'W':
		if (optarg) { 
			del = AUDIT_FILTER_EXIT;
			action = AUDIT_ALWAYS;
			_audit_syscalladded = 1;
			retval = audit_setup_watch_name(&rule_new, optarg);
		} else {
			fprintf(stderr, "watch option needs a path\n");	
			retval = -1;
		}
		break;
	case 'k':
		if (!(_audit_syscalladded || _audit_permadded ) ||
				(add==AUDIT_FILTER_UNSET &&
					del==AUDIT_FILTER_UNSET)) {
			fprintf(stderr,
			"key option needs a watch or syscall given prior to it\n");
			retval = -1;
		} else if (!optarg) {
			fprintf(stderr, "key option needs a value\n");
			retval = -1;
		} else if ((strlen(optarg)+strlen(key)+(!!key[0])) >
							AUDIT_MAX_KEY_LEN) {
			fprintf(stderr, "key option exceeds size limit\n");
			retval = -1;
		} else {
			if (strncmp(optarg, "ids-", 4) == 0) {
				if (check_ids_key(optarg)) {
					retval = -1;
					break;
				}
			}
			if (strchr(optarg, AUDIT_KEY_SEPARATOR)) 
				fprintf(stderr,
				    "key %s has illegal character\n", optarg);
			if (key[0]) { // Add the separator if we need to
				strcat(key, key_sep);
				keylen--;
			}
			strncat(key, optarg, keylen);
			keylen = AUDIT_MAX_KEY_LEN - strlen(key);
		}
		break;
	case 'p':
		if (!add && !del) {
			fprintf(stderr,
			"permission option needs a watch given prior to it\n");
			retval = -1;
		} else if (!optarg) {
			fprintf(stderr, "permission option needs a filter\n");
			retval = -1;
		} else 
			retval = audit_setup_perms(rule_new, optarg);
		break;
        case 'q':
		if (_audit_syscalladded) {
			fprintf(stderr, 
			   "Syscall auditing requested for make equivalent\n");
			retval = -1;
		} else {
			char *mp, *sub;
			retval = equiv_parse(optarg, &mp, &sub);
			if (retval < 0) {
				fprintf(stderr, 
			   "Error parsing equivalent parts\n");
				retval = -1;
			} else {
				retval = audit_make_equivalent(fd, mp, sub);
				if (retval <= 0) {
					retval = -1;
				} else
					return -2; // success - no reply needed
			}
		}
		break;
        case 't':
		retval = audit_trim_subtrees(fd);
		if (retval <= 0)
			retval = -1;
		else
			return -2;  // success - no reply for this
		break;
	case 'v':
		printf("auditctl version %s\n", VERSION);
		retval = -2;
		break;
        default: 
		usage();
		retval = -1;
		break;
        }
    }
    /* catch extra args or errors where the user types "- s" */
    if (optind == 1)
	retval = -1;
    else if ((optind < count) && (retval != -1)) {
	fprintf(stderr, "parameter passed without an option given\n");	
	retval = -1;
    }

    /* See if we were adding a key */
    if (key[0] && list_requested == 0) {
	int flags = 0;
	char *cmd=NULL;

	/* Get the flag */
	if (add != AUDIT_FILTER_UNSET)
		flags = add & AUDIT_FILTER_MASK;
	else if (del != AUDIT_FILTER_UNSET)
		flags = del & AUDIT_FILTER_MASK;

	/* Build the command */
	if (asprintf(&cmd, "key=%s", key) < 0) {
		cmd = NULL;
		fprintf(stderr, "Out of memory adding key\n");
		retval = -1;
	} else {
		/* Add this to the rule */
		int ret = audit_rule_fieldpair_data(&rule_new, cmd, flags);
		if (ret < 0)
			retval = -1;
		free(cmd);
	}
    }
    if (retval == -1 && errno == ECONNREFUSED)
		fprintf(stderr,	"The audit system is disabled\n");
    return retval;
}

static char *get_line(FILE *f, char *buf)
{
	if (fgets_unlocked(buf, LINE_SIZE, f)) {
		/* remove newline */
		char *ptr = strchr(buf, 0x0a);
		if (ptr)
			*ptr = 0;
		return buf;
	}
	return NULL;
}


void preprocess(char *buf)
{
	unsigned int i = 0;
	bool esc_ctx = false;

	while (buf[i]) {
		if (buf[i] == '\\' && esc_ctx == false)
			esc_ctx = true;
		else {
			if (esc_ctx == true) {
				if (buf[i] == ' ') {
					buf[i] = 0x07;
					buf[i - 1] = 0x07;
				} else if (buf[i] == '\\') {
					buf[i] = 0x04;
					buf[i - 1] = 0x04;
				}

				esc_ctx = false;
			}
		}

		i++;
	}
}


void postprocess(char *buf)
{
	char *str = strdup(buf);
	char *pos1 = str;
	char *pos2 = buf;

	if (!str)
		return;
    
	while (*pos1) {
		if (*pos1 == 0x07) {
			*pos2 = ' ';
			pos1 += 2;
			pos2++;
			continue;
		} else if (*pos1 == 0x04) {
			*pos2 = '\\';
			pos1 += 2;
			pos2++;
			continue;
		}

		*pos2 = *pos1;
		pos2++;
		pos1++;
	}

	*pos2 = 0;
	free(str);
}


/*
 * This function reads the given file line by line and executes the rule.
 * It returns 0 if everything went OK, 1 if there are problems before reading
 * the file and -1 on error conditions after executing some of the rules.
 * It will abort reading the file if it encounters any problems.
 */
static int fileopt(const char *file)
{
	int i, tfd, rc, lineno = 1;
	struct stat st;
        FILE *f;
        char buf[LINE_SIZE];

	/* Does the file exist? */
	rc = open(file, O_RDONLY);
	if (rc < 0) {
		if (errno != ENOENT) {
			fprintf(stderr,"Error opening %s (%s)\n", 
				file, strerror(errno));
                        return 1;
                }
                fprintf(stderr, "file %s doesn't exist, skipping\n", file);
                return 0;
        }
        tfd = rc;

	/* Is the file permissions sane? */
	if (fstat(tfd, &st) < 0) {
		fprintf(stderr, "Error fstat'ing %s (%s)\n",
			file, strerror(errno));
		close(tfd);
		return 1;
	}
	if (st.st_uid != 0) {
		fprintf(stderr, "Error - %s isn't owned by root\n", file);
		close(tfd);
		return 1;
	} 
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		fprintf(stderr, "Error - %s is world writable\n", file);
		close(tfd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "Error - %s is not a regular file\n", file);
		close(tfd);
		return 1;
	}

        f = fdopen(tfd, "rm");
        if (f == NULL) {
                fprintf(stderr, "Error - fdopen failed (%s)\n",
                        strerror(errno));
		close(tfd);
                return 1;
        }

	/* Read until eof, lineno starts as 1 */
	while (get_line(f, buf)) {
		char *options[NUM_OPTIONS];
		char *ptr;
		int idx=0;

		/* Weed out blank lines */
		while (buf[idx] == ' ')
			idx++;
		if (buf[idx] == 0) {
			lineno++;
			continue;
		}
		
		preprocess(buf);
		ptr = strtok(buf, " ");
		if (ptr == NULL)
			break;
		
		/* allow comments */
		if (ptr[0] == '#') {
			lineno++;
			continue;
		}
		i = 0;
		options[i++] = "auditctl";
		options[i++] = ptr;
		while( (ptr=strtok(NULL, " ")) && i<NUM_OPTIONS-1 ) {
		        postprocess(ptr);
			options[i++] = ptr;
		}
		
		options[i] = NULL;

		/* Parse it */
		if (reset_vars()) {
			fclose(f);
			return -1;
		}
		rc = setopt(i, lineno, options);

		/* handle reply or send rule */
		if (rc != -3) {
			if (handle_request(rc) == -1) {
				if (errno != ECONNREFUSED)
					fprintf(stderr,
					"There was an error in line %d of %s\n",
					lineno, file);
				else {
					fprintf(stderr,
					"The audit system is disabled\n");
					fclose(f);
					return 0;
				}
				if (ignore == 0) {
					fclose(f);
					return -1;
				}
				if (continue_error)
					continue_error = -1;
			}
		}
		lineno++;
	}
	fclose(f);
	return 0;
}

int main(int argc, char *argv[])
{
	int retval = 1;

	set_aumessage_mode(MSG_STDERR, DBG_NO);

	if (argc == 1) {
		usage();
		return 1;
	}
#ifndef DEBUG
	/* Make sure we are root */
	if (geteuid() != 0) {
		fprintf(stderr, "You must be root to run this program.\n");
		return 4;
	}
#endif
	/* Check where the rules are coming from: commandline or file */
	if ((argc == 3) && (strcmp(argv[1], "-R") == 0)) {
		fd = audit_open();
		if (audit_is_enabled(fd) == 2) {
			fprintf(stderr,
				"The audit system is in immutable "
				"mode, no rule changes allowed\n");
			return 0;
		} else if (errno == ECONNREFUSED) {
			fprintf(stderr, "The audit system is disabled\n");
			return 0;
		} else if (fileopt(argv[2]))
			return 1;
		else {
			if (continue_error < 0)
				return 1;
			return 0;
		}
	} else {
		if (reset_vars()) {
			free(rule_new);
			return 1;
		}
		retval = setopt(argc, 0, argv);
		if (retval == -3) {
			free(rule_new);
			return 0;
		}
	}

	if (add != AUDIT_FILTER_UNSET || del != AUDIT_FILTER_UNSET) {
		fd = audit_open();
		if (audit_is_enabled(fd) == 2) {
			fprintf(stderr,
				"The audit system is in immutable "
				"mode, no rule changes allowed\n");
			free(rule_new);
			return 0;
		} else if (errno == ECONNREFUSED) {
			fprintf(stderr, "The audit system is disabled\n");
			free(rule_new);
			return 0;
		}
	}
	retval = handle_request(retval);
	free(rule_new);
	return retval;
}

/*
 * This function is called after setopt to handle the return code.
 * On entry, status = 0 means just get the reply. Greater than 0 means we
 * are adding or deleting a rule or watch. -1 means an error occurred.
 * -2 means everything is OK and no reply needed. Even if there's an 
 * error, we need to call this routine to close up the audit fd.
 * The return code from this function is 0 success and -1 error.
 */
static int handle_request(int status)
{
	if (status == 0) {
		if (_audit_syscalladded) {
			fprintf(stderr, "Error - no list specified\n");
			return -1;
		}
		get_reply();
	} else if (status == -2)
		status = 0;  // report success 
	else if (status > 0) {
		int rc;
		if (add != AUDIT_FILTER_UNSET) {
			// if !task add syscall any if not specified
			if ((add & AUDIT_FILTER_MASK) != AUDIT_FILTER_TASK && 
					_audit_syscalladded != 1) {
					audit_rule_syscallbyname_data(
							rule_new, "all");
			}
			set_aumessage_mode(MSG_QUIET, DBG_NO);
			rc = audit_add_rule_data(fd, rule_new, add, action);
			set_aumessage_mode(MSG_STDERR, DBG_NO);
			/* Retry for legacy kernels */
			if (rc < 0) {
				if (errno == EINVAL &&
				rule_new->fields[0] == AUDIT_DIR) {
					rule_new->fields[0] = AUDIT_WATCH;
					rc = audit_add_rule_data(fd, rule_new,
							add, action);
				} else {
					fprintf(stderr,
				"Error sending add rule data request (%s)\n",
					errno == EEXIST ?
					"Rule exists" : strerror(-rc));
				}
			}
		}
		else if (del != AUDIT_FILTER_UNSET) {
			if ((del & AUDIT_FILTER_MASK) != AUDIT_FILTER_TASK && 
					_audit_syscalladded != 1) {
					audit_rule_syscallbyname_data(
							rule_new, "all");
			}
			set_aumessage_mode(MSG_QUIET, DBG_NO);
			rc = audit_delete_rule_data(fd, rule_new,
								 del, action);
			set_aumessage_mode(MSG_STDERR, DBG_NO);
			/* Retry for legacy kernels */
			if (rc < 0) {
				if (errno == EINVAL &&
					rule_new->fields[0] == AUDIT_DIR) {
					rule_new->fields[0] = AUDIT_WATCH;
					rc = audit_delete_rule_data(fd,rule_new,
								del, action);
				} else {
					fprintf(stderr,
			       "Error sending delete rule data request (%s)\n",
					errno == EEXIST ?
					"Rule exists" : strerror(-rc));
				}
			}
		} else {
        		usage();
	    		audit_close(fd);
			exit(1);
	    	}
		if (rc <= 0) 
			status = -1;
		else
			status = 0;
	} else 
		status = -1;

	audit_close(fd);
	fd = -1;
	return status;
}

/*
 * A reply from the kernel is expected. Get and display it.
 */
static void get_reply(void)
{
	int i, retval;
	int timeout = 40; /* loop has delay of .1 - so this is 4 seconds */
	struct audit_reply rep;
	fd_set read_mask;
	FD_ZERO(&read_mask);
	FD_SET(fd, &read_mask);

	// Reset printing counter
	printed = 0;

	for (i = 0; i < timeout; i++) {
		struct timeval t;

		t.tv_sec  = 0;
		t.tv_usec = 100000; /* .1 second */
		do {
			retval=select(fd+1, &read_mask, NULL, NULL, &t);
		} while (retval < 0 && errno == EINTR);
		// We'll try to read just in case
		retval = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
		if (retval > 0) {
			if (rep.type == NLMSG_ERROR && rep.error->error == 0) {
				i = 0;    /* reset timeout */
				continue; /* This was an ack */
			}
			
			if ((retval = audit_print_reply(&rep)) == 0) 
				break;
			else
				i = 0; /* If getting more, reset timeout */
		}
	}
}

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
 * This function interprets the reply and prints it to stdout. It returns
 * 0 if no more should be read and 1 to indicate that more messages of this
 * type may need to be read. 
 */
static int audit_print_reply(struct audit_reply *rep)
{
	unsigned int i;
	int first;
	int sparse;
	int machine = audit_detect_machine();
	size_t boffset;
	int show_syscall;

	_audit_elf = 0; 
	switch (rep->type) {
		case NLMSG_NOOP:
			return 1;
		case NLMSG_DONE:
			if (printed == 0)
				printf("No rules\n");
			return 0;
		case NLMSG_ERROR: 
		        printf("NLMSG_ERROR %d (%s)\n",
				-rep->error->error, 
				strerror(-rep->error->error));
			printed = 1;
			return 0;
		case AUDIT_GET:
			printf("AUDIT_STATUS: enabled=%d flag=%d pid=%d"
			" rate_limit=%d backlog_limit=%d lost=%d backlog=%u\n",
			rep->status->enabled, rep->status->failure,
			rep->status->pid, rep->status->rate_limit,
			rep->status->backlog_limit, rep->status->lost,
			rep->status->backlog);
			printed = 1;
			return 0;
		case AUDIT_LIST_RULES:
			list_requested = 0;
			boffset = 0;
			show_syscall = 1;
			if (key_match(rep) == 0)
				return 1;
			printed = 1;
			printf("%s: %s,%s", audit_msg_type_to_name(rep->type),
				audit_flag_to_name((int)rep->ruledata->flags),
				audit_action_to_name(rep->ruledata->action));

			for (i = 0; i < rep->ruledata->field_count; i++) {
				const char *name;
				int op = rep->ruledata->fieldflags[i] &
						AUDIT_OPERATORS;
				int field = rep->ruledata->fields[i] &
						~AUDIT_OPERATORS;
                
				name = audit_field_to_name(field);
				if (name) {
					if (strcmp(name, "arch") == 0) { 
						_audit_elf =
						    rep->ruledata->values[i];
						printf(" %s%s%u", name, 
						  audit_operator_to_symbol(op),
					    (unsigned)rep->ruledata->values[i]);
					}
					else if (strcmp(name, "msgtype") == 0) {
						if (!audit_msg_type_to_name(
						      rep->ruledata->values[i]))
							printf(" %s%s%d", name,
								audit_operator_to_symbol(op),
								rep->ruledata->values[i]);
						else {
							printf(" %s%s%s", name,
								audit_operator_to_symbol(op),
								audit_msg_type_to_name(rep->ruledata->values[i]));
						}
					} else if ((field >= AUDIT_SUBJ_USER &&
						  field <= AUDIT_OBJ_LEV_HIGH)
						&& field != AUDIT_PPID &&
					       rep->type == AUDIT_LIST_RULES) {
						printf(" %s%s%.*s", name,
						  audit_operator_to_symbol(op),
						  rep->ruledata->values[i],
						  &rep->ruledata->buf[boffset]);
						boffset +=
						    rep->ruledata->values[i];
					} else if (field == AUDIT_WATCH) {
						printf(" watch=%.*s", 
						  rep->ruledata->values[i],
						  &rep->ruledata->buf[boffset]);
						boffset +=
						    rep->ruledata->values[i];
					} else if (field == AUDIT_DIR) {
						printf(" dir=%.*s", 
						  rep->ruledata->values[i],
						  &rep->ruledata->buf[boffset]);
						boffset +=
						    rep->ruledata->values[i];
					} else if (field == AUDIT_FILTERKEY) {
						char *rkey, *ptr;
						if (asprintf(&rkey, "%.*s",
						      rep->ruledata->values[i],
						      &rep->ruledata->buf[boffset]) < 0)
							rkey = NULL;
						boffset +=
						    rep->ruledata->values[i];
						ptr = strtok(rkey, key_sep);
						while (ptr) {
							printf(" key=%s", ptr);
							ptr = strtok(NULL,
								key_sep);
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
						printf(" perm=%s", perms);
						show_syscall = 0;
					} else if (field == AUDIT_INODE) {
						// Unsigned items
						printf(" %s%s%u", name, 
							audit_operator_to_symbol(op),
							rep->ruledata->values[i]);
					} else if (field == AUDIT_FIELD_COMPARE) {
						switch (rep->ruledata->values[i])
						{
						case AUDIT_COMPARE_UID_TO_OBJ_UID:
							printf(" uid%sobj_uid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_GID_TO_OBJ_GID:
							printf(" gid%sobj_gid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_EUID_TO_OBJ_UID:
							printf(" euid%sobj_uid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_EGID_TO_OBJ_GID:
							printf(" egid%sobj_gid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_AUID_TO_OBJ_UID:
							printf(" auid%sobj_uid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_SUID_TO_OBJ_UID:
							printf(" suid%sobj_uid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_SGID_TO_OBJ_GID:
							printf(" sgid%sobj_gid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_FSUID_TO_OBJ_UID:
							printf(" fsuid%sobj_uid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_FSGID_TO_OBJ_GID:
							printf(" fsgid%sobj_gid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_UID_TO_AUID:
							printf(" uid%sauid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_UID_TO_EUID:
							printf(" uid%seuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_UID_TO_FSUID:
							printf(" uid%sfsuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_UID_TO_SUID:
							printf(" uid%ssuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_AUID_TO_FSUID:
							printf(" auid%sfsuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_AUID_TO_SUID:
							printf(" auid%ssuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_AUID_TO_EUID:
							printf(" auid%seuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_EUID_TO_SUID:
							printf(" euid%ssuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_EUID_TO_FSUID:
							printf(" euid%sfsuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_SUID_TO_FSUID:
							printf(" suid%sfsuid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_GID_TO_EGID:
							printf(" gid%segid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_GID_TO_FSGID:
							printf(" gid%sfsgid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_GID_TO_SGID:
							printf(" gid%ssgid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_EGID_TO_FSGID:
							printf(" egid%sfsgid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_EGID_TO_SGID:
							printf(" egid%ssgid",audit_operator_to_symbol(op));
							break;
						case AUDIT_COMPARE_SGID_TO_FSGID:
							printf(" sgid%sfsgid",audit_operator_to_symbol(op));
							break;
						}
					} else {
						// Signed items
						printf(" %s%s%d", name, 
							audit_operator_to_symbol(op),
							rep->ruledata->values[i]);
					}
				} else { 
					printf(" f%d%s%d", rep->ruledata->fields[i],
						audit_operator_to_symbol(op),
						rep->ruledata->values[i]);
				}
				/* Avoid printing value if the field type is 
				 * known to return a string. */
				if (rep->ruledata->values[i] && 
						(field < AUDIT_SUBJ_USER ||
						 field > AUDIT_SUBJ_CLR) &&
						field != AUDIT_WATCH &&
						field != AUDIT_DIR &&
						field != AUDIT_FILTERKEY &&
						field != AUDIT_PERM &&
						field != AUDIT_FIELD_COMPARE)
					printf(" (0x%x)", rep->ruledata->values[i]);
			}
			if (show_syscall &&
				((rep->ruledata->flags & AUDIT_FILTER_MASK) != 
						AUDIT_FILTER_USER) &&
				((rep->ruledata->flags & AUDIT_FILTER_MASK) !=
						AUDIT_FILTER_TASK) &&
				((rep->ruledata->flags & AUDIT_FILTER_MASK) !=
						AUDIT_FILTER_EXCLUDE)) {
				printf(" syscall=");
				for (sparse = 0, i = 0; 
					i < (AUDIT_BITMASK_SIZE-1); i++) {
					if (rep->ruledata->mask[i] != (uint32_t)~0)
						sparse = 1;
				}
				if (!sparse) {
					printf("all");
				} else for (first = 1, i = 0;
					i < AUDIT_BITMASK_SIZE * 32; i++) {
					int word = AUDIT_WORD(i);
					int bit  = AUDIT_BIT(i);
					if (rep->ruledata->mask[word] & bit) {
						const char *ptr;
						if (_audit_elf)
							machine = 
							audit_elf_to_machine(
								_audit_elf);
						if (machine < 0)
							ptr = NULL;
						else
							ptr = 
							audit_syscall_to_name(i, 
							machine);
						if (ptr)
							printf("%s%s", 
							first ? "" : ",", ptr);
						else
							printf("%s%d", 
							first ? "" : ",", i);
						first = 0;
					}
				}
			}
			printf("\n");
			return 1; /* get more messages until NLMSG_DONE */
		default:
			printf("Unknown: type=%d, len=%d\n", rep->type, 
				rep->nlh->nlmsg_len);
			printed = 1;
			return 0;
	}
}

