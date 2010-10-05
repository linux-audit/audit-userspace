/*
 * ausearch.c - main file for ausearch utility 
 * Copyright 2005-08,2010 Red Hat Inc., Durham, North Carolina.
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
#include <stdio_ext.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <locale.h>
#include <signal.h>
#include "libaudit.h"
#include "auditd-config.h"
#include "ausearch-options.h"
#include "ausearch-lol.h"
#include "ausearch-lookup.h"


static FILE *log_fd = NULL;
static lol lo;
static int found = 0;
static int input_is_pipe = 0;
static int timeout_interval = 3;	/* timeout in seconds */
static int process_logs(void);
static int process_log_fd(void);
static int process_stdin(void);
static int process_file(char *filename);
static int get_record(llist **);

extern char *user_file;
extern int force_logs;
extern int match(llist *l);
extern void output_record(llist *l);

static int is_pipe(int fd)
{
	struct stat st;
	int pipe_mode=0;

	if (fstat(fd, &st) == 0) {
		if (S_ISFIFO(st.st_mode)) 
			pipe_mode = 1;
	}
	return pipe_mode;
}

int main(int argc, char *argv[])
{
	struct rlimit limit;
	int rc;

	/* Check params and build regexpr */
	setlocale (LC_ALL, "");
	if (check_params(argc, argv))
		return 1;

	/* Raise the rlimits in case we're being started from a shell
	* with restrictions. Not a fatal error.  */
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_CPU, &limit);
	set_aumessage_mode(MSG_STDERR, DBG_NO);
	(void) umask( umask( 077 ) | 027 );

	lol_create(&lo);
	if (user_file)
		rc = process_file(user_file);
	else if (force_logs)
		rc = process_logs();
	else if (is_pipe(0))
		rc = process_stdin();
	else
		rc = process_logs();
	lol_clear(&lo);
	ilist_clear(event_type);
	free(event_type);
	free(user_file);
	free((char *)event_key);
	aulookup_destroy_uid_list();
	aulookup_destroy_gid_list();
	if (rc)
		return rc;
	if (!found) {
		if (report_format != RPT_RAW)
			fprintf(stderr, "<no matches>\n");
		return 1;
	}
	return 0;
}

static int process_logs(void)
{
	struct daemon_conf config;
	char *filename;
	int len, num = 0;

	/* Load config so we know where logs are */
        if (load_config(&config, TEST_SEARCH)) {
                fprintf(stderr,
			"NOTE - using built-in logs: %s\n",
			config.log_file);
	}

	/* for each file */
	len = strlen(config.log_file) + 16;
	filename = malloc(len);
	if (!filename) {
		fprintf(stderr, "No memory\n");
		free_config(&config);
		return 1;
	}
	/* Find oldest log file */
	snprintf(filename, len, "%s", config.log_file);
	do {
		if (access(filename, R_OK) != 0)
			break;
		num++;
		snprintf(filename, len, "%s.%d", config.log_file, num);
	} while (1);
	num--;

	/* Got it, now process logs from last to first */
	if (num > 0)
		snprintf(filename, len, "%s.%d", config.log_file, num);
	else
		snprintf(filename, len, "%s", config.log_file);
	do {
		int ret;
		if ((ret = process_file(filename))) {
			free(filename);
			free_config(&config);
			return ret;
		}
		if (just_one && found)
			break;

		/* Get next log file */
		num--;
		if (num > 0)
			snprintf(filename, len, "%s.%d", config.log_file, num);
		else if (num == 0)
			snprintf(filename, len, "%s", config.log_file);
		else
			break;
	} while (1);
	free(filename);
	free_config(&config);
	return 0;
}

static int process_log_fd(void)
{
	llist *entries; // entries in a record
	int ret;

	/* For each record in file */
	do {
		ret = get_record(&entries);
		if ((ret != 0)||(entries->cnt == 0)) {
			break;
		}
		// FIXME - what about events that straddle files?
		if (match(entries)) {
			output_record(entries);
			found = 1;
			if (just_one) {
				list_clear(entries);
				free(entries);
				break;
			}
			if (line_buffered)
				fflush(stdout);
		}
		list_clear(entries);
		free(entries);
	} while (ret == 0);
	fclose(log_fd);

	return 0;
}

static void alarm_handler(int signal)
{
	/* will interrupt current syscall */
}

static int process_stdin(void)
{
	log_fd = stdin;
	input_is_pipe=1;

	if (signal(SIGALRM, alarm_handler) == SIG_ERR ||
	    siginterrupt(SIGALRM, 1) == -1)
		return -1;

	return process_log_fd();
}

static int process_file(char *filename)
{
	log_fd = fopen(filename, "rm");
	if (log_fd == NULL) {
		fprintf(stderr, "Error opening %s (%s)\n", filename, 
			strerror(errno));
		return 1;
	}

	__fsetlocking(log_fd, FSETLOCKING_BYCALLER);
	return process_log_fd();
}

/*
 * This function returns a malloc'd buffer of the next record in the audit
 * logs. It returns 0 on success, 1 on eof, -1 on error. 
 */
static int get_record(llist **l)
{
	char *rc;
	char *buff = NULL;
	int rcount = 0, timer_running = 0;

	*l = get_ready_event(&lo);
	if (*l)
		return 0;

	while (1) {
		rcount++;

		if (!buff) {
			buff = malloc(MAX_AUDIT_MESSAGE_LENGTH);
			if (!buff)
				return -1;
		}

		if (input_is_pipe && rcount > 1) {
			timer_running = 1;
			alarm(timeout_interval);
		}

		rc = fgets_unlocked(buff, MAX_AUDIT_MESSAGE_LENGTH,
					log_fd);

		if (timer_running) {
			/* timer may have fired but thats ok */
			timer_running = 0;
			alarm(0);
		}

		if (rc) {
			if (lol_add_record(&lo, buff)) {
				*l = get_ready_event(&lo);
				if (*l)
					break;
			}
		} else {
			free(buff);
			if ((ferror_unlocked(log_fd) &&
			     errno == EINTR) || feof_unlocked(log_fd)) {
				terminate_all_events(&lo);
				*l = get_ready_event(&lo);
				if (*l)
					return 0;
				else
					return 1;
			} else 
				return -1;
		}
	}
	free(buff);
	return 0;
}

