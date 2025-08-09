/* auditctl.c --
 * Copyright 2004-2017,20-23 Red Hat Inc.
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
 *     Richard Guy Briggs <rgb@redhat.com>
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
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>	/* For basename */
#include <limits.h>	/* PATH_MAX */
#include <signal.h>
#include <sys/syscall.h> // SYS_pidfd_open
#include <poll.h>
#include "libaudit.h"
#include "auditctl-listing.h"
#include "private.h"
#include "common.h"

/* This define controls the size of the line that we will request when
 * reading in rules from a file.
 */
#define LINE_SIZE 6144

#define NUM_HANDLERS (sizeof(opt_handlers) / sizeof(opt_handlers[0]))
enum {
	OPT_DEPRECATED = -3,
	OPT_SUCCESS_NO_REPLY = -2,
	OPT_ERROR_NO_REPLY = -1,
	OPT_SUCCESS_REPLY = 0,
	OPT_SUCCESS_RULE = 1
};

/* Global functions */
static int handle_request(int status);
static void get_reply(void);
extern int delete_all_rules(int fd);

/* Global vars */
int list_requested = 0, interpret = 0;
char key[AUDIT_MAX_KEY_LEN+1];
const char key_sep[2] = { AUDIT_KEY_SEPARATOR, 0 };
static unsigned int keylen;
static int fd = -1;
static int add = AUDIT_FILTER_UNSET, del = AUDIT_FILTER_UNSET, action = -1;
static int ignore = 0, continue_error = 0;
static int exclude = 0;
static int multiple = 0;
static struct audit_rule_data *rule_new = NULL;

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
	_audit_exeadded = 0;
	_audit_filterfsadded = 0;
	_audit_elf = 0;
	add = AUDIT_FILTER_UNSET;
	del = AUDIT_FILTER_UNSET;
	action = -1;
	exclude = 0;
	multiple = 0;

	audit_rule_free_data(rule_new);
	rule_new = audit_rule_create_data();
	if (fd < 0) {
		if ((fd = audit_open()) < 0) {
			audit_msg(LOG_ERR, "Cannot open netlink audit socket");
			return 1;
		}
	}
	return 0;
}

static void usage(void)
{
    printf(
    "usage: auditctl [options]\n"
     "    -a <l,a>                          Append rule to end of <l>ist with <a>ction\n"
     "    -A <l,a>                          Add rule at beginning of <l>ist with <a>ction\n"
     "    -b <backlog>                      Set max number of outstanding audit buffers\n"
     "                                      allowed Default=64\n"
     "    -c                                Continue through errors in rules\n"
     "    -C f=f                            Compare collected fields if available:\n"
     "                                      Field name, operator(=,!=), field name\n"
     "    -d <l,a>                          Delete rule from <l>ist with <a>ction\n"
     "                                      l=task,exit,user,exclude,filesystem\n"
     "                                      a=never,always\n"
     "    -D                                Delete all rules and watches\n"
     "    -e [0..2]                         Set enabled flag\n"
     "    -f [0..2]                         Set failure flag\n"
     "                                      0=silent 1=printk 2=panic\n"
     "    -F f=v                            Build rule: field name, operator(=,!=,<,>,<=,\n"
     "                                      >=,&,&=) value\n"
     "    -h                                Help\n"
     "    -i                                Ignore errors when reading rules from file\n"
     "    -k <key>                          Set filter key on audit rule\n"
     "    -l                                List rules\n"
     "    -m text                           Send a user-space message\n"
     "    -p [r|w|x|a]                      Set permissions filter on watch\n"
     "                                      r=read, w=write, x=execute, a=attribute\n"
     "    -q <mount,subtree>                make subtree part of mount point's dir watches\n"
     "    -r <rate>                         Set limit in messages/sec (0=none)\n"
     "    -R <file>                         read rules from file\n"
     "    -s                                Report status\n"
     "    -S syscall                        Build rule: syscall name or number\n"
     "    --signal <signal>                 Send the specified signal to the daemon\n"
     "    -t                                Trim directory watches\n"
     "    -v                                Version\n"
     "    -w <path>                         Insert watch at <path>\n"
     "    -W <path>                         Remove watch at <path>\n"
#if HAVE_DECL_AUDIT_FEATURE_VERSION == 1
     "    --loginuid-immutable              Make loginuids unchangeable once set\n"
#endif
#if HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME == 1 || \
    HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME == 1
     "    --backlog_wait_time               Set the kernel backlog_wait_time\n"
#endif
#if defined(HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP)
     "    --reset-lost                      Reset the lost record counter\n"
#endif
#if HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL == 1
     "    --reset_backlog_wait_time_actual  Reset the actual backlog wait time counter\n"
#endif
     );
}

static int lookup_filter(const char *str, int *filter)
{
	*filter = audit_name_to_flag(str);
	if (*filter == AUDIT_FILTER_EXCLUDE)
		exclude = 1;
	if (*filter == -1)
		return 2;
	return 0;
}

static int lookup_action(const char *str, int *act)
{
	if (strcmp(str, "always") == 0)
		*act = AUDIT_ALWAYS;
	else if (strcmp(str, "never") == 0)
		*act = AUDIT_NEVER;
	else if (strcmp(str, "possible") == 0)
		return 1;
	else
		return 2;
	return 0;
}

/*
 * Returns 0 ok, 1 deprecated action, 2 rule error,
 * 3 multiple rule insert/delete
 */
static int audit_rule_setup(char *opt, int *filter, int *act)
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
	if (lookup_action(opt, act) == 2) {
		rc = lookup_filter(opt, filter);
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
		audit_msg(LOG_ERR, "The path passed for the watch is too big");
		return 1;
	}
	if (path[0] != '/') {
		audit_msg(LOG_ERR, "The path must start with '/'");
		return 1;
	}
	ptr = strdup(path);
	base = basename(ptr);
	nlen = strlen(base);
	free(ptr);
	if (nlen > NAME_MAX) {
		audit_msg(LOG_ERR, "The base name of the path is too big");
		return 1;
	}

	/* These are warnings, not errors */
	if (strstr(path, ".."))
		audit_msg(LOG_WARNING, 
			"Warning - relative path notation is not supported");
	if (strchr(path, '*') || strchr(path, '?'))
		audit_msg(LOG_WARNING, 
			"Warning - wildcard notation is not supported");

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
	unsigned int i;

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
	/* Ensure the rule is empty before adding a watch */
	if ((*rulep)->field_count || (*rulep)->action || (*rulep)->flags ||
	    (*rulep)->buflen)
		goto err;
	for (i = 0; i < AUDIT_MAX_FIELDS; i++)
		if ((*rulep)->fields[i] || (*rulep)->values[i] ||
		    (*rulep)->fieldflags[i])
			goto err;
	for (i = 0; i < AUDIT_BITMASK_SIZE; i++)
		if ((*rulep)->mask[i])
			goto err;
	if (audit_add_watch_dir(type, rulep, path))
		return -1;

	if (add != AUDIT_FILTER_UNSET)
		audit_msg(LOG_INFO, "Old style watch rules are slower");
	return 1;
err:
	audit_msg(LOG_ERR, "Watches may not include fields or actions");
	audit_rule_free_data(*rulep);
	*rulep = audit_rule_create_data();
	return -1;
}

/*
 * Setup a watch permissions.
 * Returns a 1 on success & -1 on failure.
 */
static int audit_setup_perms(const char *opt)
{
	unsigned int i, len, val = 0;

	len = strlen(opt);
	if (len > 4) {
		audit_msg(LOG_ERR, "permission %s is too long", opt);
		return -1;
	}

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
				audit_msg(LOG_ERR,
					"Permission %c isn't supported",
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

static int audit_request_rule_list(void)
{
	if (audit_request_rules_list_data(fd) > 0) {
		list_requested = 1;
		get_reply();
		return 1;
	}
	return 0;
}

static int check_rule_mismatch(int lineno, const char *option)
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

	char *ptr, *saved, *tmp = strdup(option);
	if (tmp == NULL)
		return -1;
	ptr = strtok_r(tmp, ",", &saved);
	memset(&tmprule, 0, sizeof(struct audit_rule_data));
	while (ptr) {
		audit_rule_syscallbyname_data(&tmprule, ptr);
		ptr = strtok_r(NULL, ",", &saved);
	}
	if (memcmp(tmprule.mask, rule_new->mask, AUDIT_BITMASK_SIZE * sizeof(tmprule.mask[0])))
		rc = 1;
	free(tmp);

	_audit_elf = old_audit_elf;
	if (rc) {
		if (lineno)
			audit_msg(LOG_WARNING, "WARNING - 32/64 bit syscall mismatch in line %d, you should specify an arch", lineno);
		else
			audit_msg(LOG_WARNING, "WARNING - 32/64 bit syscall mismatch, you should specify an arch");
	}
	return 0;
}

#ifdef SYS_pidfd_open
static int pidfd_open(int pid, unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
			     unsigned int flags)
{
	return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

// This function uses the new pidfd_ family of functions to send
// the signal to auditd. If the signal is SIGTERM, it waits for auditd
// to exit before returning. This is to prevent old and new daemons
// from stepping on each other since auditd shutsdown slowly.
static int sure_kill(int pid, int signal)
{
	int rc = 0;
	int pidfd = pidfd_open(pid, 0);
	if (pidfd < 0)
	       return -1;
	if (pidfd_send_signal(pidfd, signal, NULL, 0) < 0) {
		rc = -1;
		goto out;
	}
	if (signal == SIGTERM) {
		struct pollfd pollfd;
		pollfd.fd = pidfd;
		pollfd.events = POLLIN;
		int ready = poll(&pollfd, 1, -1);
		if (ready == -1) {
			perror("poll");
			rc = -1;
			goto out;
		}
		// Check if it exited or errored
		if (!(pollfd.revents & POLLIN))
			rc = -1;
	}
out:
	close(pidfd);
	return rc;
}
#endif

static int send_signal(const char *optarg)
{
	int signal = 0, retval, i;
	int timeout = 40; /* loop has delay of .1 - so this is 4 seconds */
	struct audit_reply rep;

	fd_set read_mask;
	FD_ZERO(&read_mask);
	FD_SET(fd, &read_mask);

	if (strcasecmp(optarg, "TERM") == 0 ||
	    strcasecmp(optarg, "stop") == 0)
		signal = SIGTERM;
	else if (strcasecmp(optarg, "HUP") == 0 ||
		 strcasecmp(optarg, "reload") == 0)
		signal = SIGHUP;
	else if (strcasecmp(optarg, "USR1") == 0 ||
		 strcasecmp(optarg, "rotate") == 0)
		signal = SIGUSR1;
	else if (strcasecmp(optarg, "USR2") == 0 ||
		 strcasecmp(optarg, "resume") == 0)
		signal = SIGUSR2;
	else if (strcasecmp(optarg, "CONT") == 0 ||
		 strcasecmp(optarg, "state") == 0)
		signal = SIGCONT;

	if (signal == 0) {
		audit_msg(LOG_ERR, "%s is an unsupported signal", optarg);
		exit(1);
	}

	// Request status so that we can find the pid
	retval = audit_request_status(fd);
	if (retval == -1) {
		if (errno == ECONNREFUSED)
			audit_msg(LOG_INFO, "The audit system is disabled");
		exit(1);
	}

	// Receive the netlink info
	for (i = 0; i < timeout; i++) {
		struct timeval t;

		t.tv_sec  = 0;
		t.tv_usec = 100000; /* .1 second */
		do {
			retval = select(fd+1, &read_mask, NULL, NULL, &t);
		} while (retval < 0 && errno == EINTR);

		// We'll try to read just in case
		retval = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
		if (retval > 0) {
			if (rep.type == NLMSG_ERROR && rep.error->error == 0) {
				i = 0;    /* reset timeout */
				continue; /* This was an ack */
			}

			if (rep.type == NLMSG_NOOP) {
				i = 0; /* If getting more, reset timeout */
				continue;
			} else if (rep.type == NLMSG_DONE)
				break;
			else if (rep.type == AUDIT_GET) {
				if (rep.status->pid == 0) {
					audit_msg(LOG_INFO,
						"Auditd is not running");
					exit(2);
				}
#ifdef SYS_pidfd_open
				retval = sure_kill(rep.status->pid, signal);
#else
				retval = kill(rep.status->pid, signal);
#endif
				if (retval < 0) {
					audit_msg(LOG_WARNING,
				        "Failed sending signal to auditd (%s)",
						 strerror(errno));
					exit(1);
				} else
					return -2;
			}
		}
	}
	audit_msg(LOG_WARNING, "Failed sending signal to auditd (timeout)");
	exit(1);
}

static int report_status(void)
{
	int retval;

	retval = audit_request_status(fd);
	if (retval == -1) {
		if (errno == ECONNREFUSED)
			fprintf(stderr,	"The audit system is disabled\n");
		return -1;
	}
	get_reply();
	retval = audit_request_features(fd);
	if (retval == -1) {
		// errno is EINVAL if the kernel does support features API
		if (errno == EINVAL)
			return -2;
		return -1;
	}
	get_reply();
	return -2;
}

#ifdef WITH_IO_URING
// return 0 on success and -1 if unknown op.
static int parse_io_uring(const char *optarg)
{
	if (strchr(optarg, ',')) {
		int retval = -1;
		char *saved, *ptr, *tmp = strdup(optarg);
		if (tmp == NULL)
			return retval;
		ptr = strtok_r(tmp, ",", &saved);
		while (ptr) {
			retval = audit_rule_io_uringbyname_data(rule_new, ptr);
			if (retval != 0)
				break;
			ptr = strtok_r(NULL, ",", &saved);
		}
		free(tmp);
		return retval;
	}
	return audit_rule_io_uringbyname_data(rule_new, optarg);
}
#endif

static const struct option long_opts[] =
{
  {"help", 0, NULL, 'h'},
#if HAVE_DECL_AUDIT_FEATURE_VERSION == 1
  {"loginuid-immutable", 0, NULL, 1},
#endif
#if HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME == 1 || \
    HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME == 1
  {"backlog_wait_time", 1, NULL, 2},
#endif
#if defined(HAVE_STRUCT_AUDIT_STATUS_FEATURE_BITMAP)
  {"reset-lost", 0, NULL, 3},
#endif
#if HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL == 1
  {"reset_backlog_wait_time_actual", 0, NULL, 4},
#endif
  {"signal", 1, NULL, 5},
  {NULL, 0, NULL, 0}
};

typedef struct
{
	int* count;		// number of arguments
	char** vars;	// arguments of the command
	int retval;		// current return value
	int finish;		// do we need to return after parsing this option?
	int lidx;		// index of the long option (applicable to long opts only)
	int lineno;		// line number in the file
} opt_handler_params_t;

static int opt_usage(opt_handler_params_t *args)
{
	usage();
	return OPT_ERROR_NO_REPLY;
}

static int opt_interpret(opt_handler_params_t *args)
{
	ignore = 1;
	return OPT_SUCCESS_NO_REPLY;
}

static int opt_continue(opt_handler_params_t *args)
{
	ignore = 1;
	continue_error = 1;
	return OPT_SUCCESS_NO_REPLY;
}

static int opt_status(opt_handler_params_t *args)
{
	if (*(args->count) > 3) {
		audit_msg(LOG_ERR,
			"Too many options for status command");
		return OPT_ERROR_NO_REPLY;
	} else if (optind == 2 && *(args->count) == 3) { 
		if (strcmp(args->vars[optind], "-i") == 0) {
			interpret = 1;
			*(args->count) -= 1;
		} else {
			audit_msg(LOG_ERR,
				"Only -i option is allowed");
			return OPT_ERROR_NO_REPLY;
		}
	}

	return report_status();
}

static int opt_enabled(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (optarg && ((strcmp(optarg, "0") == 0) ||
				   (strcmp(optarg, "1") == 0) ||
				   (strcmp(optarg, "2") == 0))) {
		if (audit_set_enabled(fd, strtoul(optarg, NULL, 0)) > 0)
			audit_request_status(fd);
		else
			retval = OPT_ERROR_NO_REPLY;
	} else {
		audit_msg(LOG_ERR, "Enable must be 0, 1, or 2 was %s",
				  optarg);
		retval = OPT_ERROR_NO_REPLY;
	}
	return retval;
}

static int opt_failure(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (optarg && ((strcmp(optarg, "0") == 0) ||
				   (strcmp(optarg, "1") == 0) ||
				   (strcmp(optarg, "2") == 0))) {
		if (audit_set_failure(fd, strtoul(optarg, NULL, 0)) > 0)
			audit_request_status(fd);
		else {
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
		}
	} else {
		audit_msg(LOG_ERR, "Failure must be 0, 1, or 2 was %s",
				  optarg);
		retval = OPT_ERROR_NO_REPLY;
	}
	return retval;
}

static int opt_rate(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (optarg && isdigit((unsigned char)optarg[0])) {
		uint32_t rate;
		errno = 0;
		rate = strtoul(optarg, NULL, 0);
		if (errno) {
			args->finish = 1;
			audit_msg(LOG_ERR, "Error converting rate");
			return OPT_ERROR_NO_REPLY;
		}
		if (audit_set_rate_limit(fd, rate) > 0)
			audit_request_status(fd);
		else {
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
		}
	} else {
		audit_msg(LOG_ERR, "Rate must be a numeric value was %s", optarg);
		retval = OPT_ERROR_NO_REPLY;
	}
	return retval;
}

static int opt_backlog(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (optarg && isdigit((unsigned char)optarg[0])) {
		uint32_t limit;
		errno = 0;
		limit = strtoul(optarg, NULL, 0);
		if (errno) {
			audit_msg(LOG_ERR, "Error converting backlog");
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
		}
		if (audit_set_backlog_limit(fd, limit) > 0)
			audit_request_status(fd);
		else {
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
		}
	} else {
		audit_msg(LOG_ERR,
				  "Backlog must be a numeric value was %s",
				  optarg);
		retval = OPT_ERROR_NO_REPLY;
	}
	return retval;
}

static int opt_list(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (*(args->count) > 4) {
		audit_msg(LOG_ERR,
			"Wrong number of options for list request");
		return OPT_ERROR_NO_REPLY;
	}
	if (*(args->count) == 3) {
		if (strcmp(args->vars[optind], "-i") == 0) {
			interpret = 1;
			*(args->count) -= 1;
		} else {
			audit_msg(LOG_ERR,
				"Only -k or -i options are allowed");
			return OPT_ERROR_NO_REPLY;
		}
	} else if (*(args->count) == 4) {
		if (args->vars[optind] && strcmp(args->vars[optind], "-k") == 0) {
			strncat(key, args->vars[3], keylen);
			*(args->count) -= 2;
		} else {
			audit_msg(LOG_ERR,
					  "Only -k or -i options are allowed");
			return OPT_ERROR_NO_REPLY;
		}
	}
	if (audit_request_rule_list()) {
		list_requested = 1;
		retval = OPT_SUCCESS_NO_REPLY;
	} else
		retval = OPT_ERROR_NO_REPLY;

	return retval;
}

static int opt_append(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (strstr(optarg, "task") && _audit_syscalladded) {
		audit_msg(LOG_ERR,
				  "Syscall auditing requested for task list");
		retval = OPT_ERROR_NO_REPLY;
	} else {
		int rc = audit_rule_setup(optarg, &add, &action);
		if (rc == 3) {
			audit_msg(LOG_ERR,
				"Multiple rule insert/delete operations are not allowed\n");
			retval = OPT_ERROR_NO_REPLY;
		} else if (rc == 2) {
			audit_msg(LOG_ERR,
					  "Append rule - bad keyword %s",
					  optarg);
			retval = OPT_ERROR_NO_REPLY;
		} else if (rc == 1) {
			audit_msg(LOG_ERR,
					  "Append rule - possible is deprecated");
			args->finish = 1;
			return OPT_DEPRECATED; /* deprecated - eat it */
		} else
			retval = OPT_SUCCESS_RULE; /* success - please send */
	}
	return retval;
}

static int opt_prepend(opt_handler_params_t *args)
{
	int retval = args->retval, rc;

	if (strstr(optarg, "task") && _audit_syscalladded) {
		audit_msg(LOG_ERR,
			 "Error: syscall auditing requested for task list");
		retval = -1;
	} else {
		rc = audit_rule_setup(optarg, &add, &action);
		if (rc == 3) {
			audit_msg(LOG_ERR,
		"Multiple rule insert/delete operations are not allowed");
			retval = -1;
		} else if (rc == 2) {
			audit_msg(LOG_ERR, "Add rule - bad keyword %s",
				  optarg);
			retval = -1;
		} else if (rc == 1) {
			audit_msg(LOG_WARNING,
				  "Append rule - possible is deprecated");
			return -3; /* deprecated - eat it */
		} else {
			add |= AUDIT_FILTER_PREPEND;
			retval = 1; /* success - please send */
		}
	}
	return retval;
}

static int opt_delete(opt_handler_params_t *args)
{
	int retval = args->retval, rc;
	rc = audit_rule_setup(optarg, &del, &action);
	if (rc == 3) {
		audit_msg(LOG_ERR,
		    "Multiple rule insert/delete operations are not allowed");
		retval = OPT_ERROR_NO_REPLY;
	} else if (rc == 2) {
		audit_msg(LOG_ERR, "Delete rule - bad keyword %s", optarg);
		retval = OPT_ERROR_NO_REPLY;
	} else if (rc == 1) {
		audit_msg(LOG_INFO, "Delete rule - possible is deprecated");
		return OPT_DEPRECATED; /* deprecated - eat it */
	} else
		retval = OPT_SUCCESS_RULE; /* success - please send */
	return retval;
}

static int opt_syscall(opt_handler_params_t *args)
{
	int retval = args->retval, rc;
	int unknown_arch = !_audit_elf;
#ifdef WITH_IO_URING
	if (((add & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_URING_EXIT ||
		 (del & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_URING_EXIT)) {
		// Do io_uring op
		rc = parse_io_uring(optarg);
		switch (rc) {
			case 0:
				_audit_syscalladded = 1;
				retval = OPT_SUCCESS_RULE; /* success - please send */
				break;
			case -1:
				audit_msg(LOG_ERR,
						"io_uring op unknown: %s",
						optarg);
				retval = OPT_ERROR_NO_REPLY;
				break;
			}
		return retval;
	}
#endif

	/* Do some checking to make sure that we are not adding a
	 * syscall rule to a list that does not make sense. */
	if (((add & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_TASK ||
		 (del & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_TASK)) {
			audit_msg(LOG_ERR,
				"Error: syscall auditing being added to task list");
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
	} else if (((add & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_USER ||
				(del & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_USER)) {
			audit_msg(LOG_ERR,
				  "Error: syscall auditing being added to user list");
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
	} else if (((add & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_FS ||
				(del & (AUDIT_FILTER_MASK | AUDIT_FILTER_UNSET)) == AUDIT_FILTER_FS)) {
			audit_msg(LOG_ERR,
				"Error: syscall auditing being added to filesystem list");
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
	} else if (exclude) {
		audit_msg(LOG_ERR,
			"Error: syscall auditing cannot be put on exclude list");
		args->finish = 1;
		return OPT_ERROR_NO_REPLY;
	} else {
		if (unknown_arch) {
			int machine;
			unsigned int elf;
			machine = audit_detect_machine();
			if (machine < 0) {
				audit_msg(LOG_ERR,
						  "Error detecting machine type");
				args->finish = 1;
				return OPT_ERROR_NO_REPLY;
			}
			elf = audit_machine_to_elf(machine);
			if (elf == 0) {
				audit_msg(LOG_ERR,
						  "Error looking up elf type %d",
						  machine);
				args->finish = 1;
				return OPT_ERROR_NO_REPLY;
			}
			_audit_elf = elf;
		}
	}
	rc = _audit_parse_syscall(optarg, rule_new);
	switch (rc) {
		case 0:
			_audit_syscalladded = 1;
			if (unknown_arch && add != AUDIT_FILTER_UNSET)
				if (check_rule_mismatch(args->lineno, optarg) == -1)
					retval = OPT_ERROR_NO_REPLY;
			break;
		case -1:
			audit_msg(LOG_ERR, "Syscall name unknown: %s", optarg);
			retval = OPT_ERROR_NO_REPLY;
			break;
		case -2:
			audit_msg(LOG_ERR, "Elf type unknown: 0x%x", _audit_elf);
			retval = OPT_ERROR_NO_REPLY;
			break;
		case -3: // Error reported - do nothing here
			retval = OPT_ERROR_NO_REPLY;
			break;
	}
	return retval;
}

/*
 * process_key_option - append key string while enforcing limits
 * @optarg: key string to append
 * @key: destination key buffer
 * @keylen: remaining buffer length
 * Returns 0 on success or OPT_ERROR_NO_REPLY on error.
 */
static int process_key_option(const char *optarg, char *key,
			      unsigned int *keylen)
{
	if ((strlen(optarg) + strlen(key) + (!!key[0])) >
			AUDIT_MAX_KEY_LEN) {
		audit_msg(LOG_ERR, "key option exceeds size limit");
		return OPT_ERROR_NO_REPLY;
	}
	if (strchr(optarg, AUDIT_KEY_SEPARATOR))
		audit_msg(LOG_ERR, "key %s has illegal character", optarg);
	if (key[0]) {
		strcat(key, key_sep);
		(*keylen)--;
	}
	strncat(key, optarg, *keylen);
	*keylen = AUDIT_MAX_KEY_LEN - strlen(key);
	return 0;
}

static int opt_field(opt_handler_params_t *args)
{
	int retval = args->retval, rc;
	int flags = AUDIT_FILTER_UNSET;

	if (add != AUDIT_FILTER_UNSET)
		flags = add & AUDIT_FILTER_MASK;
	else if (del != AUDIT_FILTER_UNSET)
		flags = del & AUDIT_FILTER_MASK;
	// if the field is arch & there is a -t option...we can allow it
	else if ((optind >= *(args->count)) || (strstr(optarg, "arch=") == NULL) || (strcmp(args->vars[optind], "-t") != 0)) {
		audit_msg(LOG_ERR, "List must be given before field");
		return OPT_ERROR_NO_REPLY;
	}

	// Keys need to get handled differently
	if (strncmp(optarg, "key=", 4) == 0) {
		optarg += 4;
		rc = process_key_option(optarg, key, &keylen);
		if (rc)
			retval = rc;
		return retval;
	}

	rc = audit_rule_fieldpair_data(&rule_new, optarg, flags);
	if (rc != 0) {
		audit_number_to_errmsg(rc, optarg);
		retval = OPT_ERROR_NO_REPLY;
	} else {
		if (rule_new->fields[rule_new->field_count - 1] ==
			AUDIT_PERM)
			_audit_permadded = 1;
		if (rule_new->fields[rule_new->field_count - 1] ==
			AUDIT_EXE)
			_audit_exeadded = 1;
	}

	return retval;
}

static int opt_compare(opt_handler_params_t *args)
{
	int retval = args->retval, rc;
	int flags = AUDIT_FILTER_UNSET;

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
	return retval;
}

static int opt_message(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (*(args->count) > 3) {
		audit_msg(LOG_ERR,
			"The -m option must be only the only option and takes 1 parameter");
		retval = OPT_ERROR_NO_REPLY;
	} else {
		const char* s = optarg;
		char* umsg;
		while (*s) {
			if (*s < 32) {
				audit_msg(LOG_ERR,
						  "Illegal character in audit event");
				args->finish = 1;
				return OPT_ERROR_NO_REPLY;
			}
			s++;
		}
		if (asprintf(&umsg, "text=%s", optarg) < 0) {
			audit_msg(LOG_ERR, "Can't create user event");
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
		}
		if (audit_log_user_message(fd, AUDIT_USER, umsg, NULL, NULL, NULL, 1) <= 0)
			retval = OPT_ERROR_NO_REPLY;
		else {
			free(umsg);
			args->finish = 1;
			return OPT_SUCCESS_NO_REPLY; // success - no reply for this
		}
		free(umsg);
	}
	return retval;
}

static int opt_read_rules(opt_handler_params_t *args)
{
	audit_msg(LOG_ERR, "Error - nested rule files not supported");
	return OPT_ERROR_NO_REPLY;
}

static int opt_delete_all(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (*(args->count) > 4 || *(args->count) == 3) {
		audit_msg(LOG_ERR,
				  "Wrong number of options for Delete all request");
		return OPT_ERROR_NO_REPLY;
	}
	if (*(args->count) == 4) {
		if (strcmp(args->vars[optind], "-k") == 0) {
			strncat(key, args->vars[3], keylen);
			*(args->count) -= 2;
		} else {
			audit_msg(LOG_ERR,
					  "Only the -k option is allowed");
			return OPT_ERROR_NO_REPLY;
		}
	}
	retval = delete_all_rules(fd);
	if (retval == 0) {
		(void)audit_request_rule_list();
		key[0] = 0;
		retval = -2;
	}
	return retval;
}

static int opt_watch(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (add != AUDIT_FILTER_UNSET || del != AUDIT_FILTER_UNSET) {
		audit_msg(LOG_ERR,
				  "watch option can't be given with a syscall");
		retval = OPT_ERROR_NO_REPLY;
	} else if (optarg) {
		add = AUDIT_FILTER_EXIT;
		action = AUDIT_ALWAYS;
		_audit_syscalladded = 1;
		retval = audit_setup_watch_name(&rule_new, optarg);
	} else {
		audit_msg(LOG_ERR, "watch option needs a path");
		retval = OPT_ERROR_NO_REPLY;
	}
	return retval;
}

static int opt_remove_watch(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (optarg) {
		del = AUDIT_FILTER_EXIT;
		action = AUDIT_ALWAYS;
		_audit_syscalladded = 1;
		retval = audit_setup_watch_name(&rule_new, optarg);
	} else {
		audit_msg(LOG_ERR, "watch option needs a path");
		retval = OPT_ERROR_NO_REPLY;
	}
	return retval;
}

static int opt_key(opt_handler_params_t *args)
{
	int rc, retval = args->retval;
	if (!(_audit_syscalladded || _audit_permadded ||
		_audit_exeadded || _audit_filterfsadded) ||
		(add == AUDIT_FILTER_UNSET && del == AUDIT_FILTER_UNSET)) {
			audit_msg(LOG_ERR,
				  "key option needs a watch or syscall given prior to it");
			return OPT_ERROR_NO_REPLY;
	} else if (!optarg) {
		audit_msg(LOG_ERR, "key option needs a value");
		return OPT_ERROR_NO_REPLY;
	}

	rc = process_key_option(optarg, key, &keylen);
	if (rc)
		retval = rc;
	return retval;
}

static int opt_perms(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (add == AUDIT_FILTER_UNSET && del == AUDIT_FILTER_UNSET) {
		audit_msg(LOG_ERR,
				  "permission option needs a watch given prior to it");
		retval = OPT_ERROR_NO_REPLY;
	} else if (!optarg) {
		audit_msg(LOG_ERR, "permission option needs a filter");
		retval = OPT_ERROR_NO_REPLY;
	} else
		retval = audit_setup_perms(optarg);
	return retval;
}

static int opt_mount(opt_handler_params_t *args)
{
	int retval = args->retval;
	if (_audit_syscalladded) {
		audit_msg(LOG_ERR,
			"Syscall auditing requested for make equivalent");
		retval = OPT_ERROR_NO_REPLY;
	} else {
		char *mp, *sub;
		retval = equiv_parse(optarg, &mp, &sub);
		if (retval < 0) {
			audit_msg(LOG_ERR,
				"Error parsing equivalent parts");
			retval = OPT_ERROR_NO_REPLY;
		} else {
			retval = audit_make_equivalent(fd, mp, sub);
			if (retval <= 0) {
				retval = OPT_ERROR_NO_REPLY;
			} else {
				args->finish = 1;
				return OPT_SUCCESS_NO_REPLY; // success - no reply needed
			}
		}
	}
	return retval;
}

static int opt_trim(opt_handler_params_t *args)
{
	int retval = audit_trim_subtrees(fd);
	if (retval <= 0)
		retval = OPT_ERROR_NO_REPLY;
	else {
		args->finish = 1;
		return OPT_SUCCESS_NO_REPLY; // success - no reply needed
	}
	return retval;
}

static int opt_version(opt_handler_params_t *args)
{
	printf("auditctl version %s\n", VERSION);
	return OPT_SUCCESS_NO_REPLY;
}

static int opt_loginuid(opt_handler_params_t *args)
{

	int retval = audit_set_loginuid_immutable(fd);
	if (retval <= 0)
		retval = OPT_ERROR_NO_REPLY;
	else
		return OPT_SUCCESS_NO_REPLY; // success - no reply for this

	return retval;
}

static int opt_wait_time(opt_handler_params_t *args)
{
	int retval = args->retval;

#if HAVE_DECL_AUDIT_VERSION_BACKLOG_WAIT_TIME == 1 || \
  HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME == 1
	if (optarg && isdigit((unsigned char)optarg[0])) {
		uint32_t bwt;
		errno = 0;
		bwt = strtoul(optarg, NULL, 0);
		if (errno) {
			audit_msg(LOG_ERR,
					  "Error converting backlog_wait_time");
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
		}
		if (audit_set_backlog_wait_time(fd, bwt) > 0)
			audit_request_status(fd);
		else {
			args->finish = 1;
			return OPT_ERROR_NO_REPLY;
		}
	} else {
		audit_msg(LOG_ERR,
				  "Backlog_wait_time must be a numeric value was %s",
				  optarg);
		retval = OPT_ERROR_NO_REPLY;
	}
#else
	audit_msg(LOG_ERR,
			  "backlog_wait_time is not supported on your kernel");
	retval = OPT_ERROR_NO_REPLY;
#endif

	return retval;
}

static int opt_reset_lost(opt_handler_params_t *args)
{

	int retval = args->retval, rc;

	if ((rc = audit_reset_lost(fd)) >= 0) {
		audit_msg(LOG_INFO, "lost: %u", rc);
		return OPT_SUCCESS_NO_REPLY;
	} else {
		audit_number_to_errmsg(rc, long_opts[args->lidx].name);
		retval = OPT_ERROR_NO_REPLY;
	}

	return retval;
}

static int opt_reset_wait_time(opt_handler_params_t *args)
{

	int retval = args->retval, rc;

#if HAVE_DECL_AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL == 1
	if ((rc = audit_reset_backlog_wait_time_actual(fd)) >= 0) {
		audit_msg(LOG_INFO, "backlog_wait_time_actual: %u", rc);
		args->finish = 1;
		return OPT_SUCCESS_NO_REPLY;
	} else {
		audit_number_to_errmsg(rc, long_opts[args->lidx].name);
		retval = OPT_ERROR_NO_REPLY;
	}
#else
	audit_msg(LOG_ERR,
			  "reset_backlog_wait_time_actual is not supported on your kernel");
	retval = OPT_ERROR_NO_REPLY;
#endif

	return retval;
}

static int opt_send_signal(opt_handler_params_t *args)
{
	int retval = args->retval;

	retval = send_signal(optarg);

	return retval;
}

static int opt_default(opt_handler_params_t *args)
{
	int retval = args->retval;
	char *bad_opt;
	if (optind >= 2)
		bad_opt = args->vars[optind - 1];
	else
		bad_opt = " ";
	if (args->lineno)
		audit_msg(LOG_ERR,
			"Option %s on line %d is invalid", bad_opt, args->lineno);
	else
		audit_msg(LOG_ERR, "Option %s is invalid", bad_opt);
	retval = OPT_ERROR_NO_REPLY;
	return retval;
}

struct {
	int option;
	int (*handler)(opt_handler_params_t *args);
} opt_handlers[] = {
	// short options
	{'h', opt_usage},
	{'i', opt_interpret},
	{'c', opt_continue},
	{'s', opt_status},
	{'e', opt_enabled},
	{'f', opt_failure},
	{'r', opt_rate},
	{'b', opt_backlog},
	{'l', opt_list},
	{'a', opt_append},
	{'A', opt_prepend},
	{'d', opt_delete},
	{'S', opt_syscall},
	{'F', opt_field},
	{'C', opt_compare},
	{'m', opt_message},
	{'R', opt_read_rules},
	{'D', opt_delete_all},
	{'w', opt_watch},
	{'W', opt_remove_watch},
	{'k', opt_key},
	{'p', opt_perms},
	{'q', opt_mount},
	{'t', opt_trim},
	{'v', opt_version},

	// long options
	{1, opt_loginuid},
	{2, opt_wait_time},
	{3, opt_reset_lost},
	{4, opt_reset_wait_time},
	{5, opt_send_signal},
};

int handle_option(int option, opt_handler_params_t* args)
{
	for (size_t i = 0; i < NUM_HANDLERS; i++) {
		if (opt_handlers[i].option == option) {
			return opt_handlers[i].handler(args);
		}
	}

	// Default handler if option is not found
	return opt_default(args);
}

/*
 * returns: -3 deprecated, -2 success - no reply, -1 error - noreply,
 * 0 success - reply, > 0 success - rule
 */
static int setopt(int count, int lineno, char *vars[])
{
	int c, lidx = 0;
	int retval = OPT_SUCCESS_REPLY;

	optind = 0;
	opterr = 0;
	key[0] = 0;
	keylen = AUDIT_MAX_KEY_LEN;

	/* Process arguments */
	while ((retval >= 0) && (c = getopt_long(count, vars, "hicslDvtC:e:f:r:b:a:A:d:S:F:m:R:w:W:k:p:q:", long_opts, &lidx)) != EOF) {

		opt_handler_params_t params = {&count, vars, retval, 0, lidx, lineno};
		retval = handle_option(c, &params);
		/* if something went wrong during processing or we are done here */
		if (params.finish)
			return retval;
	}

	/* catch extra args or errors where the user types "- s" */
	if (optind == 1)
		retval = OPT_ERROR_NO_REPLY;
	else if ((optind < count) && (retval != OPT_ERROR_NO_REPLY)) {
		audit_msg(LOG_ERR, "parameter passed without an option given");
		retval = OPT_ERROR_NO_REPLY;
	}

	/* See if we were adding a key */
	if (key[0] && list_requested == 0) {
		int flags = 0;
		char* cmd = NULL;

		/* Get the flag */
		if (add != AUDIT_FILTER_UNSET)
			flags = add & AUDIT_FILTER_MASK;
		else if (del != AUDIT_FILTER_UNSET)
			flags = del & AUDIT_FILTER_MASK;

		/* Build the command */
		if (asprintf(&cmd, "key=%s", key) < 0) {
			cmd = NULL;
			audit_msg(LOG_ERR, "Out of memory adding key");
			retval = OPT_ERROR_NO_REPLY;
		} else {
			/* Add this to the rule */
			int ret = audit_rule_fieldpair_data(&rule_new, cmd, flags);
			if (ret != 0) {
				audit_number_to_errmsg(ret, cmd);
				retval = OPT_ERROR_NO_REPLY;
			}
			free(cmd);
		}
	}

	if (retval == OPT_ERROR_NO_REPLY && errno == ECONNREFUSED)
		audit_msg(LOG_ERR, "The audit system is disabled");
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


static void preprocess(char *buf)
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


static void postprocess(char *buf)
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
 * the file, 2 if the rules file doesn't exist and it should,  and -1 on
 * error conditions after executing some of the rules. It will abort reading
 * the file if it encounters any problems.
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
			audit_msg(LOG_ERR,"Error opening %s (%s)", 
				file, strerror(errno));
                        return 1;
                }
		audit_msg(LOG_ERR, "audit rules file %s doesn't exist", file);
                return 2;
        }
        tfd = rc;

	/* Is the file permissions sane? */
	if (fstat(tfd, &st) < 0) {
		audit_msg(LOG_ERR, "Error fstat'ing %s (%s)",
			file, strerror(errno));
		close(tfd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		audit_msg(LOG_ERR, "Error - %s is not a regular file", file);
		close(tfd);
		return 1;
	}

	f = fdopen(tfd, "rm");
	if (f == NULL) {
		audit_msg(LOG_ERR, "Error - fdopen failed (%s)",
			strerror(errno));
		close(tfd);
		return 1;
	}

	/* Read until eof, lineno starts as 1 */
	while (get_line(f, buf)) {
		char *ptr, **fields;
		unsigned int idx=0, nf = (strlen(buf)/3) + 3;

		/* Weed out blank lines */
		while (buf[idx] == ' ')
			idx++;
		if (buf[idx] == 0) {
			lineno++;
			continue;
		}

		preprocess(buf);
		ptr = audit_strsplit(buf);
		if (ptr == NULL)
			break;

		/* allow comments */
		if (ptr[0] == '#') {
			lineno++;
			continue;
		}
		i = 0;
		fields = malloc(nf * sizeof(char *));
		if (fields == NULL) {
			audit_msg(LOG_ERR, "Out of memory. Check %s file, %d line", __FILE__, __LINE__);
			fclose(f);
			return 1;
		}
		
		fields[i++] = "auditctl";
		fields[i++] = ptr;
		while( (ptr=audit_strsplit(NULL)) && (i < nf-1)) {
		        postprocess(ptr);
			fields[i++] = ptr;
		}

		fields[i] = NULL;

		/* Parse it */
		if (reset_vars()) {
			free(fields);
			fclose(f);
			return -1;
		}
		rc = setopt(i, lineno, fields);
		free(fields);

		/* handle reply or send rule */
		if (rc != OPT_DEPRECATED) {
			if (handle_request(rc) == -1) {
				if (errno != ECONNREFUSED)
					audit_msg(LOG_ERR,
					"There was an error in line %d of %s",
					lineno, file);
				else {
					audit_msg(LOG_ERR,
						"The audit system is disabled");
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

/* Return 1 if ready, 0 otherwise */
static int is_ready(void)
{
	if (audit_is_enabled(fd) == 2) {
		audit_msg(LOG_ERR, "The audit system is in immutable mode,"
			" no rule changes allowed");
		return 0;
	} else if (errno == ECONNREFUSED) {
		audit_msg(LOG_ERR, "The audit system is disabled");
		return 0;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int retval = 1;

	_set_aumessage_mode(MSG_STDERR, DBG_NO);

	if (argc == 1) {
		usage();
		return 1;
	}
#ifndef DEBUG
	/* Make sure we are root if we do anything except help */
	if (!(argc == 2 && (strcmp(argv[1], "--help")==0 ||
			strcmp(argv[1], "-h") == 0 ||
			(strcmp(argv[1], "-l") == 0 && geteuid() == 0))) &&
			!audit_can_control()) {
		audit_msg(LOG_WARNING, "You must be root to run this program.");
		return 4;
	}
#endif
	/* Check where the rules are coming from: commandline or file */
	if ((argc == 3) && (strcmp(argv[1], "-R") == 0)) {
		// If reading a file, its most likely start up. Send problems
		// to syslog where they will persist for later review
		_set_aumessage_mode(MSG_SYSLOG, DBG_NO);
		fd = audit_open();
		if (is_ready() == 0)
			return 1;
		else if (fileopt(argv[2])) {
			free(rule_new);
			return 1;
		} else {
			free(rule_new);
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
		if (retval == OPT_DEPRECATED) {
			free(rule_new);
			return 0;
		}
	}

	if (add != AUDIT_FILTER_UNSET || del != AUDIT_FILTER_UNSET) {
		fd = audit_open();
		if (is_ready() == 0) {
			free(rule_new);
			return 1;
		}
	}
	retval = handle_request(retval);
	if (retval == -1) {
		if (errno != ECONNREFUSED)
			audit_msg(LOG_ERR,
				"There was an error while processing parameters");
		else {
			audit_msg(LOG_ERR,
				"The audit system is disabled");
			return 0;
		}
	}
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
	if (status == OPT_SUCCESS_REPLY) {
		if (_audit_syscalladded) {
			audit_msg(LOG_ERR, "Error - no list specified");
			return -1;
		}
		get_reply();
	} else if (status == OPT_SUCCESS_NO_REPLY)
		status = 0;  // report success 
	else if (status == OPT_SUCCESS_RULE) {
		int rc;
		if (add != AUDIT_FILTER_UNSET) {
			// if !task add syscall any if not specified
			if ((add & AUDIT_FILTER_MASK) != AUDIT_FILTER_TASK && 
					_audit_syscalladded != 1) {
					audit_rule_syscallbyname_data(
							rule_new, "all");
			}
			_set_aumessage_mode(MSG_QUIET, DBG_NO);
			rc = audit_add_rule_data(fd, rule_new, add, action);
			_set_aumessage_mode(MSG_STDERR, DBG_NO);
			/* Retry for legacy kernels */
			if (rc < 0) {
				if (errno == EINVAL &&
				rule_new->fields[0] == AUDIT_DIR) {
					rule_new->fields[0] = AUDIT_WATCH;
					rc = audit_add_rule_data(fd, rule_new,
							add, action);
				} else {
					audit_msg(LOG_ERR,
				"Error sending add rule data request (%s)",
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
			_set_aumessage_mode(MSG_QUIET, DBG_NO);
			rc = audit_delete_rule_data(fd, rule_new,
								 del, action);
			_set_aumessage_mode(MSG_STDERR, DBG_NO);
			/* Retry for legacy kernels */
			if (rc < 0) {
				if (errno == EINVAL &&
					rule_new->fields[0] == AUDIT_DIR) {
					rule_new->fields[0] = AUDIT_WATCH;
					rc = audit_delete_rule_data(fd,rule_new,
								del, action);
				} else {
					audit_msg(LOG_ERR,
			       "Error sending delete rule data request (%s)",
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
	} else // OPT_ERROR_NO_REPLY or OPT_DEPRECATED
		status = -1;

	if (!list_requested)
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
	audit_print_init();

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

			if ((retval = audit_print_reply(&rep, fd)) == 0)
				break;
			else
				i = 0; /* If getting more, reset timeout */
		}
	}
}

