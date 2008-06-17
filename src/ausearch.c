/*
 * ausearch.c - main file for ausearch utility 
 * Copyright 2005-08 Red Hat Inc., Durham, North Carolina.
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
#include "libaudit.h"
#include "auditd-config.h"
#include "ausearch-options.h"
#include "ausearch-llist.h"
#include "ausearch-lookup.h"


static FILE *log_fd = NULL;
static int found = 0;
static int pipe_mode = 0;
static int process_logs(void);
static int process_log_fd(void);
static int process_stdin(void);
static int process_file(char *filename);
static int get_record(llist *);
static void extract_timestamp(const char *b, event *e);
static int str2event(char *s, event *e);
static int events_are_equal(event *e1, event *e2);

extern char *user_file;
extern int force_logs;
extern int match(llist *l);
extern void output_record(llist *l);

static int input_is_pipe(void)
{
	struct stat st;

	if (fstat(0, &st) == 0) {
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

	if (user_file)
		rc = process_file(user_file);
	else if (force_logs)
		rc = process_logs();
	else if (input_is_pipe())
		rc = process_stdin();
	else
		rc = process_logs();
	ilist_clear(event_type);
	free(event_type);
	free(user_file);
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
	llist entries; // entries in a record
	int ret;

	/* For each record in file */
	list_create(&entries);
	do {
		ret = get_record(&entries);
		if ((ret < 0)||(entries.cnt == 0)) {
			break;
		}
		if (match(&entries)) {
			output_record(&entries);
			found = 1;
			if (just_one) {
				list_clear(&entries);
				break;
			}
		}
		list_clear(&entries);
	} while (ret == 0);
	fclose(log_fd);

	return 0;
}

static int process_stdin(void)
{
	log_fd = stdin;

	return process_log_fd();
}

static int process_file(char *filename)
{
	log_fd = fopen(filename, "r");
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
static char *saved_buff = NULL;
static int get_record(llist *l)
{
// FIXME: this code needs to be re-organized to keep a linked list of record
// lists. Each time a new record is read, it should be checked to see if it 
// belongs to a list of records that is waiting for its terminal record. If
// so append to list. If the new record is a terminal type, return the list.
// If it does not belong to a list and it is not a terminal record, append the
// record to a new list of records. 
	char *rc;
	char *buff = NULL;
	int first_time = 1;

	while (1) {
		if (saved_buff) {
			buff = saved_buff;
			rc = buff;
			saved_buff = NULL;
		} else {
			if (!buff) {
				buff = malloc(MAX_AUDIT_MESSAGE_LENGTH);
				if (!buff)
					return -1;
			}
			// FIXME: In pipe mode, if there is a waiting buffer
			// and 5 seconds has elapsed, go ahead and process
			// the buffer - nothings coming that's related.
			rc = fgets_unlocked(buff, MAX_AUDIT_MESSAGE_LENGTH,
					log_fd);
		}
		if (rc) {
			lnode n;
			event e;
			char *ptr;

			ptr = strrchr(buff, 0x0a);
			if (ptr)
				*ptr = 0;
			n.message=strdup(buff);
			// FIXME: need to extract the node here
			// and put things on a list of lists
			extract_timestamp(buff, &e);
			if (first_time) {
				l->e.milli = e.milli;
				l->e.sec = e.sec;
				l->e.serial = e.serial;
				first_time = 0;
			}
			if (events_are_equal(&l->e, &e)) { 
				list_append(l, &n);
			} else {
				saved_buff = buff;
				free(n.message);
				buff = NULL;
				break;
			}
		} else {
			free(buff);
			if (feof(log_fd))
				return 1;
			else 
				return -1;
		}
	}
	if (!saved_buff)
		free(buff);
	return 0;
}

/*
 * This function will look at the line and pick out pieces of it.
 */
static void extract_timestamp(const char *b, event *e)
{
	char *ptr, *tmp;

	tmp = strndupa(b, 120);
	ptr = strtok(tmp, " ");
	if (ptr) {
		while (ptr && strncmp(ptr, "type=", 5))
			ptr = strtok(NULL, " ");

		// at this point we have type=
		ptr = strtok(NULL, " ");
		if (ptr) {
			if (*(ptr+9) == '(')
				ptr+=9;
			else
				ptr = strchr(ptr, '(');
			if (ptr) {
			// now we should be pointed at the timestamp
				char *eptr;
				ptr++;
				eptr = strchr(ptr, ')');
				if (eptr)
					*eptr = 0;
				if (str2event(ptr, e)) {
					fprintf(stderr,
					  "Error extracting time stamp (%s)\n",
						ptr);
				}
			}
			// else we have a bad line
		}
		// else we have a bad line
	}
	// else we have a bad line
}

static int str2event(char *s, event *e)
{
	char *ptr;

	errno = 0;
	ptr = strchr(s+10, ':');
	if (ptr) {
		e->serial = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->serial = 0;
	ptr = strchr(s, '.');
	if (ptr) {
		e->milli = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->milli = 0;
	e->sec = strtoul(s, NULL, 10);
	if (errno)
		return -1;
	return 0;
}

static int events_are_equal(event *e1, event *e2)
{
	if (e1->serial == e2->serial && e1->milli == e2->milli &&
			e1->sec == e2->sec)
		return 1;
	else
		return 0;
}

