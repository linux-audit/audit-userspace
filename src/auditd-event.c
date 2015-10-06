/* auditd-event.c -- 
 * Copyright 2004-08,2011,2013,2015 Red Hat Inc., Durham, North Carolina.
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
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>	/* O_NOFOLLOW needs gnu defined */
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <limits.h>     /* POSIX_HOST_NAME_MAX */
#include "auditd-event.h"
#include "auditd-dispatch.h"
#include "auditd-listen.h"
#include "libaudit.h"
#include "private.h"

/* This is defined in auditd.c */
extern volatile int stop;

struct auditd_consumer_data {
    struct daemon_conf *config;
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_nonempty;
    struct auditd_reply_list *head;
    struct auditd_reply_list *tail;
    int log_fd;
    FILE *log_file;
};

/* Local function prototypes */
static void *event_thread_main(void *arg); 
static void handle_event(struct auditd_consumer_data *data);
static void write_to_log(const char *buf, struct auditd_consumer_data *data);
static void check_log_file_size(struct auditd_consumer_data *data);
static void check_space_left(int lfd, struct auditd_consumer_data *data);
static void do_space_left_action(struct auditd_consumer_data *data, int admin);
static void do_disk_full_action(struct auditd_consumer_data *data);
static void do_disk_error_action(const char *func, struct daemon_conf *config,
	int err);
static void check_excess_logs(struct auditd_consumer_data *data); 
static void rotate_logs_now(struct auditd_consumer_data *data);
static void rotate_logs(struct auditd_consumer_data *data, 
		unsigned int num_logs);
static void shift_logs(struct auditd_consumer_data *data);
static int  open_audit_log(struct auditd_consumer_data *data);
static void change_runlevel(const char *level);
static void safe_exec(const char *exe);
static char *format_raw(const struct audit_reply *rep, 
		struct daemon_conf *config);
static void reconfigure(struct auditd_consumer_data *data);


/* Local Data */
static struct auditd_consumer_data consumer_data;
static pthread_t event_thread;
static unsigned int disk_err_warning = 0;
static int fs_space_warning = 0;
static int fs_admin_space_warning = 0;
static int fs_space_left = 1;
static int logging_suspended = 0;
static const char *SINGLE = "1";
static const char *HALT = "0";
static char *format_buf = NULL;
static off_t log_size = 0;


void shutdown_events(void)
{
	/* Give it 5 seconds to clear the queue */
	alarm(5);
	pthread_join(event_thread, NULL);	
	free((void *)format_buf);
	fclose(consumer_data.log_file);
}

int init_event(struct daemon_conf *config)
{
	/* Store the netlink descriptor and config info away */
	consumer_data.config = config;
	consumer_data.log_fd = -1;

	/* Setup IPC mechanisms */
	pthread_mutex_init(&consumer_data.queue_lock, NULL);
	pthread_cond_init(&consumer_data.queue_nonempty, NULL);

	/* Reset the queue */
	consumer_data.head = consumer_data.tail = NULL;

	/* Now open the log */
	if (config->daemonize == D_BACKGROUND) {
		if (open_audit_log(&consumer_data))
			return 1;
	} else {
		consumer_data.log_fd = 1; // stdout
		consumer_data.log_file = fdopen(consumer_data.log_fd, "a");
		if (consumer_data.log_file == NULL) {
			audit_msg(LOG_ERR, 
				"Error setting up stdout descriptor (%s)", 
				strerror(errno));
			return 1;
		}
		/* Set it to line buffering */
		setlinebuf(consumer_data.log_file);
	}

	/* Create the worker thread */
	if (pthread_create(&event_thread, NULL,
			event_thread_main, &consumer_data) < 0) {
		audit_msg(LOG_ERR, "Couldn't create event thread, exiting");
		fclose(consumer_data.log_file);
		return 1;
	}

	if (config->daemonize == D_BACKGROUND) {
		check_log_file_size(&consumer_data);
		check_excess_logs(&consumer_data);
		check_space_left(consumer_data.log_fd, &consumer_data);
	}
	format_buf = (char *)malloc(MAX_AUDIT_MESSAGE_LENGTH +
						 _POSIX_HOST_NAME_MAX);
	if (format_buf == NULL) {
		audit_msg(LOG_ERR, "No memory for formatting, exiting");
		fclose(consumer_data.log_file);
		return 1;
	}
	return 0;
}

/* This function takes a malloc'd rep and places it on the queue. The 
   dequeue'r is responsible for freeing the memory. */
void enqueue_event(struct auditd_reply_list *rep)
{
	char *buf = NULL;
	int len;

	rep->ack_func = 0;
	rep->ack_data = 0;
	rep->sequence_id = 0;

	if (rep->reply.type != AUDIT_DAEMON_RECONFIG) {
		switch (consumer_data.config->log_format)
		{
		case LF_RAW:
			buf = format_raw(&rep->reply, consumer_data.config);
			break;
		case LF_NOLOG:
			// We need the rotate event to get enqueued
			if (rep->reply.type != AUDIT_DAEMON_ROTATE ) {
				// Internal DAEMON messages should be free'd
				if (rep->reply.type >= AUDIT_FIRST_DAEMON &&
				    rep->reply.type <= AUDIT_LAST_DAEMON)
					free((void *)rep->reply.message);
				free(rep);
				return;
			}
			break;
		default:
			audit_msg(LOG_ERR, 
				  "Illegal log format detected %d", 
				  consumer_data.config->log_format);
			// Internal DAEMON messages should be free'd
			if (rep->reply.type >= AUDIT_FIRST_DAEMON &&
			    rep->reply.type <= AUDIT_LAST_DAEMON)
				free((void *)rep->reply.message);
			free(rep);
			return;
		}

		if (buf) {
			len = strlen(buf);
			if (len < MAX_AUDIT_MESSAGE_LENGTH - 1)
				memcpy(rep->reply.msg.data, buf, len+1);
			else {
				// FIXME: is truncation the right thing to do?
				memcpy(rep->reply.msg.data, buf,
						MAX_AUDIT_MESSAGE_LENGTH-1);
				rep->reply.msg.data[MAX_AUDIT_MESSAGE_LENGTH-1] = 0;
			}
		}
	}

	rep->next = NULL; /* new packet goes at end - so zero this */

	pthread_mutex_lock(&consumer_data.queue_lock);
	if (consumer_data.head == NULL) {
		consumer_data.head = consumer_data.tail = rep;
		pthread_cond_signal(&consumer_data.queue_nonempty);
	} else {
		/* FIXME: wait for room on the queue */

		/* OK there's room...add it in */
		consumer_data.tail->next = rep; /* link in at end */
		consumer_data.tail = rep; /* move end to newest */
	}
	pthread_mutex_unlock(&consumer_data.queue_lock);
}

/* This function takes a preformatted message and places it on the
   queue. The dequeue'r is responsible for freeing the memory. */
void enqueue_formatted_event(char *msg, ack_func_type ack_func, void *ack_data, uint32_t sequence_id)
{
	int len;
	struct auditd_reply_list *rep;

	rep = (struct auditd_reply_list *) calloc (1, sizeof (*rep));
	if (rep == NULL) {
		audit_msg(LOG_ERR, "Cannot allocate audit reply");
		return;
	}

	rep->ack_func = ack_func;
	rep->ack_data = ack_data;
	rep->sequence_id = sequence_id;

	len = strlen (msg);
	if (len < MAX_AUDIT_MESSAGE_LENGTH - 1)
		memcpy (rep->reply.msg.data, msg, len+1);
	else {
		/* FIXME: is truncation the right thing to do?  */
		memcpy (rep->reply.msg.data, msg, MAX_AUDIT_MESSAGE_LENGTH-1);
		rep->reply.msg.data[MAX_AUDIT_MESSAGE_LENGTH-1] = 0;
	}

	pthread_mutex_lock(&consumer_data.queue_lock);
	if (consumer_data.head == NULL) {
		consumer_data.head = consumer_data.tail = rep;
		pthread_cond_signal(&consumer_data.queue_nonempty);
	} else {
		/* FIXME: wait for room on the queue */

		/* OK there's room...add it in */
		consumer_data.tail->next = rep; /* link in at end */
		consumer_data.tail = rep; /* move end to newest */
	}
	pthread_mutex_unlock(&consumer_data.queue_lock);
}

void resume_logging(void)
{
	logging_suspended = 0; 
	fs_space_left = 1;
	disk_err_warning = 0;
	fs_space_warning = 0;
	fs_admin_space_warning = 0;
	audit_msg(LOG_ERR, "Audit daemon is attempting to resume logging.");
}

static void *event_thread_main(void *arg) 
{
	struct auditd_consumer_data *data = arg;
	sigset_t sigs;

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGALRM);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	while (1) {
		struct auditd_reply_list *cur;
		int stop_req = 0;
// FIXME: wait for data 
		pthread_mutex_lock(&data->queue_lock);
		while (data->head == NULL) {
			pthread_cond_wait(&data->queue_nonempty, 
				&data->queue_lock);
		}
// FIXME: at this point we can use data->head unlocked since it won't change.
		handle_event(data);
		cur = data->head;
// FIXME: relock at this point
		if (data->tail == data->head)
			data->tail = NULL;
		data->head = data->head->next;
		if (data->head == NULL && stop && 
				( cur->reply.type == AUDIT_DAEMON_END ||
				cur->reply.type == AUDIT_DAEMON_ABORT) )
			stop_req = 1;
		pthread_mutex_unlock(&data->queue_lock);

		/* Internal DAEMON messages should be free'd */
		if (cur->reply.type >= AUDIT_FIRST_DAEMON &&
				cur->reply.type <= AUDIT_LAST_DAEMON) {
			free((void *)cur->reply.message);
		} 
		free(cur);
		if (stop_req)
			break;
	}
	return NULL;
}


/* This function takes the newly dequeued event and handles it. */
static unsigned int count = 0L;
static void handle_event(struct auditd_consumer_data *data)
{
	char *buf = data->head->reply.msg.data;

	if (data->head->reply.type == AUDIT_DAEMON_RECONFIG) {
		reconfigure(data);
		switch (consumer_data.config->log_format)
		{
		case LF_RAW:
			buf = format_raw(&data->head->reply, consumer_data.config);
			break;
		case LF_NOLOG:
			return;
		default:
			audit_msg(LOG_ERR, 
				  "Illegal log format detected %d", 
				  consumer_data.config->log_format);
			return;
		}
	} else if (data->head->reply.type == AUDIT_DAEMON_ROTATE) {
		rotate_logs_now(data);
		if (consumer_data.config->log_format == LF_NOLOG)
			return;
	}
	if (!logging_suspended) {

		write_to_log(buf, data);

		/* See if we need to flush to disk manually */
		if (data->config->flush == FT_INCREMENTAL) {
			count++;
			if ((count % data->config->freq) == 0) {
				int rc;
				errno = 0;
				do {
					rc = fflush(data->log_file);
				} while (rc < 0 && errno == EINTR);
		                if (errno) {
		                	if (errno == ENOSPC && 
					     fs_space_left == 1) {
					     fs_space_left = 0;
					     do_disk_full_action(data);
		        	        } else
					     //EIO is only likely failure mode
					     do_disk_error_action("flush", 
						data->config, errno);
				}

				/* EIO is only likely failure mode */
				if ((data->config->daemonize == D_BACKGROUND)&& 
						(fsync(data->log_fd) != 0)) {
				     do_disk_error_action("fsync",
					data->config, errno);
				}
			}
		}
	}
}

static void send_ack(struct auditd_consumer_data *data, int ack_type,
			const char *msg)
{
	if (data->head->ack_func) {
		unsigned char header[AUDIT_RMW_HEADER_SIZE];

		AUDIT_RMW_PACK_HEADER(header, 0, ack_type, strlen(msg),
					data->head->sequence_id);

		data->head->ack_func(data->head->ack_data, header, msg);
	}
}

/* This function writes the given buf to the current log file */
static void write_to_log(const char *buf, struct auditd_consumer_data *data)
{
	int rc;
	FILE *f = data->log_file;
	struct daemon_conf *config = data->config;
	int ack_type = AUDIT_RMW_TYPE_ACK;
	const char *msg = "";

	/* write it to disk */
	rc = fprintf(f, "%s\n", buf);

	/* error? Handle it */
	if (rc < 0) {
		if (errno == ENOSPC) {
			ack_type = AUDIT_RMW_TYPE_DISKFULL;
			msg = "disk full";
			send_ack(data, ack_type, msg);
			if (fs_space_left == 1) {
				fs_space_left = 0;
				do_disk_full_action(data);
			}
		} else  {
			int saved_errno = errno;
			ack_type = AUDIT_RMW_TYPE_DISKERROR;
			msg = "disk write error";
			send_ack(data, ack_type, msg);
			do_disk_error_action("write", config, saved_errno);
		}
	} else {
		/* check log file size & space left on partition */
		if (config->daemonize == D_BACKGROUND) {
			// If either of these fail, I consider it an
			// inconvenience as opposed to something that is
			// actionable. There may be some temporary condition
			// that the system recovers from. The real error
			// occurs on write.
			log_size += rc;
			check_log_file_size(data);
			check_space_left(data->log_fd, data);
		}

		if (fs_space_warning)
			ack_type = AUDIT_RMW_TYPE_DISKLOW;
		send_ack(data, ack_type, msg);
		disk_err_warning = 0;
	}
}

static void check_log_file_size(struct auditd_consumer_data *data)
{
	struct daemon_conf *config = data->config;

	/* did we cross the size limit? */
	off_t sz = log_size / MEGABYTE;

	if (sz >= config->max_log_size && (config->daemonize == D_BACKGROUND)) {
		switch (config->max_log_size_action)
		{
			case SZ_IGNORE:
				break;
			case SZ_SYSLOG:
				audit_msg(LOG_ERR,
			    "Audit daemon log file is larger than max size");
				break;
			case SZ_SUSPEND:
				audit_msg(LOG_ERR,
		    "Audit daemon is suspending logging due to logfile size.");
				logging_suspended = 1;
				break;
			case SZ_ROTATE:
				if (data->config->num_logs > 1) {
					audit_msg(LOG_NOTICE,
					    "Audit daemon rotating log files");
					rotate_logs(data, 0);
				}
				break;
			case SZ_KEEP_LOGS:
				audit_msg(LOG_NOTICE,
			    "Audit daemon rotating log files with keep option");
					shift_logs(data);
				break;
			default:
				audit_msg(LOG_ALERT, 
  "Audit daemon log file is larger than max size and unknown action requested");
				break;
		}
	}
}

static void check_space_left(int lfd, struct auditd_consumer_data *data)
{
	int rc;
	struct statfs buf;
	struct daemon_conf *config = data->config;

        rc = fstatfs(lfd, &buf);
        if (rc == 0) {
		if (buf.f_bavail < 5) {
			/* we won't consume the last 5 blocks */
			fs_space_left = 0;
			do_disk_full_action(data);
		} else {
			unsigned long blocks;
			unsigned long block_size = buf.f_bsize;
		        blocks = config->space_left * (MEGABYTE/block_size);
        		if (buf.f_bavail < blocks) {
				if (fs_space_warning == 0) {
					do_space_left_action(data, 0);
					fs_space_warning = 1;
				}
			} else if (fs_space_warning &&
					config->space_left_action == FA_SYSLOG){
				// Auto reset only if failure action is syslog
				fs_space_warning = 0;
			}
		        blocks=config->admin_space_left * (MEGABYTE/block_size);
        		if (buf.f_bavail < blocks) {
				if (fs_admin_space_warning == 0) {
					do_space_left_action(data, 1);
					fs_admin_space_warning = 1;
				}
			} else if (fs_admin_space_warning &&
				config->admin_space_left_action == FA_SYSLOG) {
				// Auto reset only if failure action is syslog
				fs_admin_space_warning = 0;
			}
		}
	}
	else audit_msg(LOG_DEBUG, "fstatfs returned:%d, %s", rc, 
			strerror(errno));
}

extern int sendmail(const char *subject, const char *content, 
	const char *mail_acct);
static void do_space_left_action(struct auditd_consumer_data *data, int admin)
{
	int action;
	struct daemon_conf *config = data->config;

	if (admin)
		action = config->admin_space_left_action;
	else
		action = config->space_left_action;

	switch (action)
	{
		case FA_IGNORE:
			break;
		case FA_SYSLOG:
			audit_msg(LOG_ALERT, 
			    "Audit daemon is low on disk space for logging");
			break;
		case FA_ROTATE:
			if (config->num_logs > 1) {
				audit_msg(LOG_NOTICE,
					"Audit daemon rotating log files");
				rotate_logs(data, 0);
			}
			break;
		case FA_EMAIL:
			if (admin == 0) {
				sendmail("Audit Disk Space Alert", 
				"The audit daemon is low on disk space for logging! Please take action\nto ensure no loss of service.",
					config->action_mail_acct);
				audit_msg(LOG_ALERT, 
			    "Audit daemon is low on disk space for logging");
			} else {
				sendmail("Audit Admin Space Alert", 
				"The audit daemon is very low on disk space for logging! Immediate action\nis required to ensure no loss of service.",
					config->action_mail_acct);
				audit_msg(LOG_ALERT, 
			  "Audit daemon is very low on disk space for logging");
			}
			break;
		case FA_EXEC:
			if (admin)
				safe_exec(config->admin_space_left_exe);
			else
				safe_exec(config->space_left_exe);
			break;
		case FA_SUSPEND:
			audit_msg(LOG_ALERT,
			    "Audit daemon is suspending logging due to low disk space.");
			logging_suspended = 1;
			break;
		case FA_SINGLE:
			audit_msg(LOG_ALERT, 
				"The audit daemon is now changing the system to single user mode");
			change_runlevel(SINGLE);
			break;
		case FA_HALT:
			audit_msg(LOG_ALERT, 
				"The audit daemon is now halting the system");
			change_runlevel(HALT);
			break;
		default:
			audit_msg(LOG_ALERT, 
			    "Audit daemon is low on disk space for logging and unknown action requested");
			break;
	}
}

static void do_disk_full_action(struct auditd_consumer_data *data)
{
	struct daemon_conf *config = data->config;

	audit_msg(LOG_ALERT,
			"Audit daemon has no space left on logging partition");
	switch (config->disk_full_action)
	{
		case FA_IGNORE:
		case FA_SYSLOG: /* Message is syslogged above */
			break;
		case FA_ROTATE:
			if (config->num_logs > 1) {
				audit_msg(LOG_NOTICE,
					"Audit daemon rotating log files");
				rotate_logs(data, 0);
			}
			break;
		case FA_EXEC:
			safe_exec(config->disk_full_exe);
			break;
		case FA_SUSPEND:
			audit_msg(LOG_ALERT,
			    "Audit daemon is suspending logging due to no space left on logging partition.");
			logging_suspended = 1;
			break;
		case FA_SINGLE:
			audit_msg(LOG_ALERT, 
				"The audit daemon is now changing the system to single user mode due to no space left on logging partition");
			change_runlevel(SINGLE);
			break;
		case FA_HALT:
			audit_msg(LOG_ALERT, 
				"The audit daemon is now halting the system due to no space left on logging partition");
			change_runlevel(HALT);
			break;
		default:
			audit_msg(LOG_ALERT, "Unknown disk full action requested");
			break;
	} 
}

static void do_disk_error_action(const char * func, struct daemon_conf *config,
	int err)
{
	char text[128];

	switch (config->disk_error_action)
	{
		case FA_IGNORE:
			break;
		case FA_SYSLOG:
			if (disk_err_warning < 5) {
				snprintf(text, sizeof(text), 
			    "%s: Audit daemon detected an error writing an event to disk (%s)",
					func, strerror(err));
				audit_msg(LOG_ALERT, "%s", text);
				disk_err_warning++;
			}
			break;
		case FA_EXEC:
			safe_exec(config->disk_error_exe);
			break;
		case FA_SUSPEND:
			audit_msg(LOG_ALERT,
			    "Audit daemon is suspending logging due to previously mentioned write error");
			logging_suspended = 1;
			break;
		case FA_SINGLE:
			audit_msg(LOG_ALERT, 
				"The audit daemon is now changing the system to single user mode due to previously mentioned write error");
			change_runlevel(SINGLE);
			break;
		case FA_HALT:
			audit_msg(LOG_ALERT, 
				"The audit daemon is now halting the system due to previously mentioned write error.");
			change_runlevel(HALT);
			break;
		default:
			audit_msg(LOG_ALERT, 
				"Unknown disk error action requested");
			break;
	} 
}

static void rotate_logs_now(struct auditd_consumer_data *data)
{
	struct daemon_conf *config = data->config;

	if (config->max_log_size_action == SZ_KEEP_LOGS) 
		shift_logs(data);
	else
		rotate_logs(data, 0);
}

/* Check for and remove excess logs so that we don't run out of room */
static void check_excess_logs(struct auditd_consumer_data *data)
{
	int rc;
	unsigned int i, len;
	char *name;

	// Only do this if rotate is the log size action
	// and we actually have a limit
	if (data->config->max_log_size_action != SZ_ROTATE ||
			data->config->num_logs < 2)
		return;
	
	len = strlen(data->config->log_file) + 16;
	name = (char *)malloc(len);
	if (name == NULL) { /* Not fatal - just messy */
		audit_msg(LOG_ERR, "No memory checking excess logs");
		return;
	}

	// We want 1 beyond the normal logs	
	i=data->config->num_logs;
	rc=0;
	while (rc == 0) {
		snprintf(name, len, "%s.%d", data->config->log_file, i++);
		rc=unlink(name);
		if (rc == 0)
			audit_msg(LOG_NOTICE,
			    "Log %s removed as it exceeds num_logs parameter",
			     name);
	}
	free(name);
}
 
static void rotate_logs(struct auditd_consumer_data *data, 
		unsigned int num_logs)
{
	int rc;
	unsigned int len, i;
	char *oldname, *newname;

	if (data->config->max_log_size_action == SZ_ROTATE &&
				data->config->num_logs < 2)
		return;

	/* Close audit file. fchmod and fchown errors are not fatal because we
	 * already adjusted log file permissions and ownership when opening the
	 * log file. */
	if (fchmod(data->log_fd, data->config->log_group ? S_IRUSR|S_IRGRP :
								S_IRUSR) < 0) {
		audit_msg(LOG_NOTICE, "Couldn't change permissions while "
			"rotating log file (%s)", strerror(errno));
	}
	if (fchown(data->log_fd, 0, data->config->log_group) < 0) {
		audit_msg(LOG_NOTICE, "Couldn't change ownership while "
			"rotating log file (%s)", strerror(errno));
	}
	fclose(data->log_file);
	
	/* Rotate */
	len = strlen(data->config->log_file) + 16;
	oldname = (char *)malloc(len);
	if (oldname == NULL) { /* Not fatal - just messy */
		audit_msg(LOG_ERR, "No memory rotating logs");
		logging_suspended = 1;
		return;
	}
	newname = (char *)malloc(len);
	if (newname == NULL) { /* Not fatal - just messy */
		audit_msg(LOG_ERR, "No memory rotating logs");
		free(oldname);
		logging_suspended = 1;
		return;
	}

	/* If we are rotating, get number from config */
	if (num_logs == 0)
		num_logs = data->config->num_logs;

	/* Handle this case first since it will not enter the for loop */
	if (num_logs == 2) 
		snprintf(oldname, len, "%s.1", data->config->log_file);

	for (i=num_logs - 1; i>1; i--) {
		snprintf(oldname, len, "%s.%d", data->config->log_file, i-1);
		snprintf(newname, len, "%s.%d", data->config->log_file, i);
		/* if the old file exists */
		rc = rename(oldname, newname);
		if (rc == -1 && errno != ENOENT) {
			// Likely errors: ENOSPC, ENOMEM, EBUSY
			int saved_errno = errno;
			audit_msg(LOG_ERR, 
				"Error rotating logs from %s to %s (%s)",
				oldname, newname, strerror(errno));
			if (saved_errno == ENOSPC && fs_space_left == 1) {
				fs_space_left = 0;
				do_disk_full_action(data);
			} else
				do_disk_error_action("rotate", data->config,
							saved_errno);
		}
	}
	free(newname);

	/* At this point, oldname should point to lowest number - use it */
	newname = oldname;
	rc = rename(data->config->log_file, newname);
	if (rc == -1 && errno != ENOENT) {
		// Likely errors: ENOSPC, ENOMEM, EBUSY
		int saved_errno = errno;
		audit_msg(LOG_ERR, "Error rotating logs from %s to %s (%s)",
			data->config->log_file, newname, strerror(errno));
		if (saved_errno == ENOSPC && fs_space_left == 1) {
			fs_space_left = 0;
			do_disk_full_action(data);
		} else
			do_disk_error_action("rotate2", data->config,
						saved_errno);

		/* At this point, we've failed to rotate the original log.
		 * So, let's make the old log writable and try again next
		 * time */
		chmod(data->config->log_file, 
			data->config->log_group ? S_IWUSR|S_IRUSR|S_IRGRP :
			S_IWUSR|S_IRUSR);
	}
	free(newname);

	/* open new audit file */
	if (open_audit_log(data)) {
		int saved_errno = errno;
		audit_msg(LOG_NOTICE, 
			"Could not reopen a log after rotating.");
		logging_suspended = 1;
		do_disk_error_action("reopen", data->config, saved_errno);
	}
}

static int last_log = 1;
static void shift_logs(struct auditd_consumer_data *data)
{
	// The way this has to work is to start scanning from .1 up until
	// no file is found. Then do the rotate algorithm using that number
	// instead of log_max.
	unsigned int num_logs, len;
	char *name;

	len = strlen(data->config->log_file) + 16;
	name = (char *)malloc(len);
	if (name == NULL) { /* Not fatal - just messy */
		audit_msg(LOG_ERR, "No memory shifting logs");
		return;
	}

	// Find last log
	num_logs = last_log;
	while (num_logs) {
		snprintf(name, len, "%s.%d", data->config->log_file, 
						num_logs);
		if (access(name, R_OK) != 0)
			break;
		num_logs++;
	}

	/* Our last known file disappeared, start over... */
	if (num_logs <= last_log && last_log > 1) {
		audit_msg(LOG_WARNING, "Last known log disappeared (%s)", name);
		num_logs = last_log = 1;
		while (num_logs) {
			snprintf(name, len, "%s.%d", data->config->log_file, 
							num_logs);
			if (access(name, R_OK) != 0)
				break;
			num_logs++;
		}
		audit_msg(LOG_INFO, "Next log to use will be %s", name);
	}
	last_log = num_logs;
	rotate_logs(data, num_logs+1);
	free(name);
}

/*
 * This function handles opening a descriptor for the audit log
 * file and ensuring the correct options are applied to the descriptor.
 * It returns 0 on success and 1 on failure.
 */
static int open_audit_log(struct auditd_consumer_data *data)
{
	int flags, lfd;

	flags = O_WRONLY|O_APPEND|O_NOFOLLOW;
	if (data->config->flush == FT_DATA)
		flags |= O_DSYNC;
	else if (data->config->flush == FT_SYNC)
		flags |= O_SYNC;

	// Likely errors for open: Almost anything
	// Likely errors on rotate: ENFILE, ENOMEM, ENOSPC
retry:
	lfd = open(data->config->log_file, flags);
	if (lfd < 0) {
		if (errno == ENOENT) {
			lfd = create_log_file(data->config->log_file);
			if (lfd < 0) {
				audit_msg(LOG_ERR,
					"Couldn't create log file %s (%s)",
					data->config->log_file,
					strerror(errno));
				return 1;
			}
			close(lfd);
			lfd = open(data->config->log_file, flags);
			log_size = 0;
		} else if (errno == ENFILE) {
			// All system descriptors used, try again...
			goto retry;
		}
		if (lfd < 0) {
			audit_msg(LOG_ERR, "Couldn't open log file %s (%s)",
				data->config->log_file, strerror(errno));
			return 1;
		}
	} else {
		// Get initial size
		struct stat st;

		int rc = fstat(lfd, &st);
		if (rc == 0)
			 log_size = st.st_size;
		else {
			close(lfd);
			return 1;
		}
	}

	if (fcntl(lfd, F_SETFD, FD_CLOEXEC) == -1) {
		audit_msg(LOG_ERR, "Error setting log file CLOEXEC flag (%s)",
			strerror(errno));
		close(lfd);
		return 1;
	}
	if (fchmod(lfd, data->config->log_group ? S_IRUSR|S_IWUSR|S_IRGRP :
							S_IRUSR|S_IWUSR) < 0) {
		audit_msg(LOG_ERR,
			"Couldn't change permissions of log file (%s)",
			strerror(errno));
		close(lfd);
		return 1;
	}
	if (fchown(lfd, 0, data->config->log_group) < 0) {
		audit_msg(LOG_ERR, "Couldn't change ownership of log file (%s)",
			strerror(errno));
		close(lfd);
		return 1;
	}

	data->log_fd = lfd;
	data->log_file = fdopen(lfd, "a");
	if (data->log_file == NULL) {
		audit_msg(LOG_ERR, "Error setting up log descriptor (%s)",
			strerror(errno));
		close(lfd);
		return 1;
	}

	/* Set it to line buffering */
	setlinebuf(consumer_data.log_file);
	return 0;
}

static void change_runlevel(const char *level)
{
	char *argv[3];
	int pid;
	struct sigaction sa;
	static const char *init_pgm = "/sbin/init";

	pid = fork();
	if (pid < 0) {
		audit_msg(LOG_ALERT, 
			"Audit daemon failed to fork switching runlevels");
		return;
	}
	if (pid)	/* Parent */
		return;
	/* Child */
	sigfillset (&sa.sa_mask);
	sigprocmask (SIG_UNBLOCK, &sa.sa_mask, 0);

	argv[0] = (char *)init_pgm;
	argv[1] = (char *)level;
	argv[2] = NULL;
	execve(init_pgm, argv, NULL);
	audit_msg(LOG_ALERT, "Audit daemon failed to exec %s", init_pgm);
	exit(1);
}

static void safe_exec(const char *exe)
{
	char *argv[2];
	int pid;
	struct sigaction sa;

	if (exe == NULL) {
		audit_msg(LOG_ALERT,
			"Safe_exec passed NULL for program to execute");
		return;
	}

	pid = fork();
	if (pid < 0) {
		audit_msg(LOG_ALERT, 
			"Audit daemon failed to fork doing safe_exec");
		return;
	}
	if (pid)	/* Parent */
		return;
	/* Child */
        sigfillset (&sa.sa_mask);
        sigprocmask (SIG_UNBLOCK, &sa.sa_mask, 0);

	argv[0] = (char *)exe;
	argv[1] = NULL;
	execve(exe, argv, NULL);
	audit_msg(LOG_ALERT, "Audit daemon failed to exec %s", exe);
	exit(1);
}

/*
* This function will take an audit structure and return a
* text buffer that's unformatted for writing to disk. If there
* is an error the return value is NULL.
*/
static char *format_raw(const struct audit_reply *rep, 
	struct daemon_conf *config)
{
        char *ptr;

        if (rep==NULL) {
		if (config->node_name_format != N_NONE)
			snprintf(format_buf, MAX_AUDIT_MESSAGE_LENGTH +
				_POSIX_HOST_NAME_MAX - 32,
				"node=%s type=DAEMON msg=NULL reply",
                                config->node_name);
		else
	        	snprintf(format_buf, MAX_AUDIT_MESSAGE_LENGTH,
				"type=DAEMON msg=NULL reply");
	} else {
		int len, nlen;
		const char *type, *message;
		char unknown[32];
		type = audit_msg_type_to_name(rep->type);
		if (type == NULL) {
			snprintf(unknown, sizeof(unknown), 
				"UNKNOWN[%d]", rep->type);
			type = unknown;
		}
		if (rep->message == NULL) {
			message = "msg lost";
			len = 8;
		} else {
			message = rep->message;
			len = rep->len;
		}

		// Note: This can truncate messages if 
		// MAX_AUDIT_MESSAGE_LENGTH is too small
		if (config->node_name_format != N_NONE)
			nlen = snprintf(format_buf, MAX_AUDIT_MESSAGE_LENGTH +
				_POSIX_HOST_NAME_MAX - 32,
				"node=%s type=%s msg=%.*s\n",
                                config->node_name, type, len, message);
		else
		        nlen = snprintf(format_buf,
				MAX_AUDIT_MESSAGE_LENGTH - 32,
				"type=%s msg=%.*s", type, len, message);

	        /* Replace \n with space so it looks nicer. */
        	ptr = format_buf;
	        while ((ptr = strchr(ptr, 0x0A)) != NULL)
        	        *ptr = ' ';

		/* Trim trailing space off since it wastes space */
		if (format_buf[nlen-1] == ' ')
			format_buf[nlen-1] = 0;
	}
        return format_buf;
}

static void reconfigure(struct auditd_consumer_data *data)
{
	struct daemon_conf *nconf = data->head->reply.conf;
	struct daemon_conf *oconf = data->config;
	uid_t uid = nconf->sender_uid;
	pid_t pid = nconf->sender_pid;
	const char *ctx = nconf->sender_ctx;
	struct timeval tv;
	char txt[MAX_AUDIT_MESSAGE_LENGTH];
	char date[40];
	unsigned int seq_num;
	int need_size_check = 0, need_reopen = 0, need_space_check = 0;

	snprintf(txt, sizeof(txt),
		"config change requested by pid=%d auid=%u subj=%s",
		pid, uid, ctx);
	audit_msg(LOG_NOTICE, "%s", txt);

	/* Do the reconfiguring. These are done in a specific
	 * order from least invasive to most invasive. We will
	 * start with general system parameters. */

	// start with disk error action.
	oconf->disk_error_action = nconf->disk_error_action;
	free((char *)oconf->disk_error_exe);
	oconf->disk_error_exe = nconf->disk_error_exe;
	disk_err_warning = 0;

	// numlogs is next
	oconf->num_logs = nconf->num_logs;

	// flush freq
	oconf->freq = nconf->freq;

	// priority boost
	if (oconf->priority_boost != nconf->priority_boost) {
		int rc;

		oconf->priority_boost = nconf->priority_boost;
		errno = 0;
		rc = nice(-oconf->priority_boost);
		if (rc == -1 && errno) 
			audit_msg(LOG_NOTICE, "Cannot change priority in "
					"reconfigure (%s)", strerror(errno));
	}

	// log format
	oconf->log_format = nconf->log_format;

	// action_mail_acct
	if (strcmp(oconf->action_mail_acct, nconf->action_mail_acct)) {
		free((void *)oconf->action_mail_acct);
		oconf->action_mail_acct = nconf->action_mail_acct;
	} else
		free((void *)nconf->action_mail_acct);

	// node_name
	if (oconf->node_name_format != nconf->node_name_format || 
			(oconf->node_name && nconf->node_name && 
			strcmp(oconf->node_name, nconf->node_name) != 0)) {
		oconf->node_name_format = nconf->node_name_format;
		free((char *)oconf->node_name);
		oconf->node_name = nconf->node_name;
	}

	/* Now look at audit dispatcher changes */
	oconf->qos = nconf->qos; // dispatcher qos

	// do the dispatcher app change
	if (oconf->dispatcher || nconf->dispatcher) {
		// none before, start new one
		if (oconf->dispatcher == NULL) {
			oconf->dispatcher = strdup(nconf->dispatcher);
			if (oconf->dispatcher == NULL) {
				int saved_errno = errno;
				audit_msg(LOG_NOTICE,
					"Could not allocate dispatcher memory"
					" in reconfigure");
				// Likely errors: ENOMEM
				do_disk_error_action("reconfig", data->config,
							saved_errno);
			}
			if(init_dispatcher(oconf)) {// dispatcher & qos is used
				int saved_errno = errno;
				audit_msg(LOG_NOTICE,
					"Could not start dispatcher %s"
					" in reconfigure", oconf->dispatcher);
				// Likely errors: Socketpairs or exec perms
				do_disk_error_action("reconfig", data->config,
							saved_errno);
			}
		} 
		// have one, but none after this
		else if (nconf->dispatcher == NULL) {
			shutdown_dispatcher();
			free((char *)oconf->dispatcher);
			oconf->dispatcher = NULL;
		} 
		// they are different apps
		else if (strcmp(oconf->dispatcher, nconf->dispatcher)) {
			shutdown_dispatcher();
			free((char *)oconf->dispatcher);
			oconf->dispatcher = strdup(nconf->dispatcher);
			if (oconf->dispatcher == NULL) {
				int saved_errno = errno;
				audit_msg(LOG_NOTICE,
					"Could not allocate dispatcher memory"
					" in reconfigure");
				// Likely errors: ENOMEM
				do_disk_error_action("reconfig", data->config,
							saved_errno);
			}
			if(init_dispatcher(oconf)) {// dispatcher & qos is used
				int saved_errno = errno;
				audit_msg(LOG_NOTICE,
					"Could not start dispatcher %s"
					" in reconfigure", oconf->dispatcher);
				// Likely errors: Socketpairs or exec perms
				do_disk_error_action("reconfig", data->config,
							saved_errno);
			}
		}
		// they are the same app - just signal it
		else {
			reconfigure_dispatcher(oconf);
			free((char *)nconf->dispatcher);
			nconf->dispatcher = NULL;
		}
	}

	// network listener
	auditd_tcp_listen_reconfigure(nconf, oconf);
	
	/* At this point we will work on the items that are related to 
	 * a single log file. */

	// max logfile action
	if (oconf->max_log_size_action != nconf->max_log_size_action) {
		oconf->max_log_size_action = nconf->max_log_size_action;
		need_size_check = 1;
	}

	// max log size
	if (oconf->max_log_size != nconf->max_log_size) {
		oconf->max_log_size = nconf->max_log_size;
		need_size_check = 1;
	}

	if (need_size_check) {
		logging_suspended = 0;
		check_log_file_size(data);
	}

	// flush technique
	if (oconf->flush != nconf->flush) {
		oconf->flush = nconf->flush;
		need_reopen = 1;
	}

	// logfile
	if (strcmp(oconf->log_file, nconf->log_file)) {
		free((void *)oconf->log_file);
		oconf->log_file = nconf->log_file;
		need_reopen = 1;
		need_space_check = 1; // might be on new partition
	} else
		free((void *)nconf->log_file);

	if (need_reopen) {
		fclose(data->log_file);
		if (open_audit_log(data)) {
			int saved_errno = errno;
			audit_msg(LOG_NOTICE, 
				"Could not reopen a log after reconfigure");
			logging_suspended = 1;
			// Likely errors: ENOMEM, ENOSPC
			do_disk_error_action("reconfig", data->config,
						saved_errno);
		} else {
			logging_suspended = 0;
			check_log_file_size(data);
		}
	}

	/* At this point we will start working on items that are 
	 * related to the amount of space on the partition. */

	// space left
	if (oconf->space_left != nconf->space_left) {
		oconf->space_left = nconf->space_left;
		need_space_check = 1;
	}

	// space left action
	if (oconf->space_left_action != nconf->space_left_action) {
		oconf->space_left_action = nconf->space_left_action;
		need_space_check = 1;
	}

	// space left exe
	if (oconf->space_left_exe || nconf->space_left_exe) {
		if (nconf->space_left_exe == NULL)
			; /* do nothing if new one is blank */
		else if (oconf->space_left_exe == NULL && nconf->space_left_exe)
			need_space_check = 1;
		else if (strcmp(oconf->space_left_exe, nconf->space_left_exe))
			need_space_check = 1;
		free((char *)oconf->space_left_exe);
		oconf->space_left_exe = nconf->space_left_exe;
	}

	// admin space left
	if (oconf->admin_space_left != nconf->admin_space_left) {
		oconf->admin_space_left = nconf->admin_space_left;
		need_space_check = 1;
	}

	// admin space action
	if (oconf->admin_space_left_action != nconf->admin_space_left_action) {
		oconf->admin_space_left_action = nconf->admin_space_left_action;
		need_space_check = 1;
	}

	// admin space left exe
	if (oconf->admin_space_left_exe || nconf->admin_space_left_exe) {
		if (nconf->admin_space_left_exe == NULL)
			; /* do nothing if new one is blank */
		else if (oconf->admin_space_left_exe == NULL &&
					 nconf->admin_space_left_exe)
			need_space_check = 1;
		else if (strcmp(oconf->admin_space_left_exe,
					nconf->admin_space_left_exe))
			need_space_check = 1;
		free((char *)oconf->admin_space_left_exe);
		oconf->admin_space_left_exe = nconf->admin_space_left_exe;
	}
	// disk full action
	if (oconf->disk_full_action != nconf->disk_full_action) {
		oconf->disk_full_action = nconf->disk_full_action;
		need_space_check = 1;
	}

	// disk full exe
	if (oconf->disk_full_exe || nconf->disk_full_exe) {
		if (nconf->disk_full_exe == NULL)
			; /* do nothing if new one is blank */
		else if (oconf->disk_full_exe == NULL && nconf->disk_full_exe)
			need_space_check = 1;
		else if (strcmp(oconf->disk_full_exe, nconf->disk_full_exe))
			need_space_check = 1;
		free((char *)oconf->disk_full_exe);
		oconf->disk_full_exe = nconf->disk_full_exe;
	}

	if (need_space_check) {
		/* note save suspended flag, then do space_left. If suspended
		 * is still 0, then copy saved suspended back. This avoids
		 * having to call check_log_file_size to restore it. */
		int saved_suspend = logging_suspended;

		fs_space_warning = 0;
		fs_admin_space_warning = 0;
		fs_space_left = 1;
		logging_suspended = 0;
		check_excess_logs(data);
		check_space_left(data->log_fd, data);
		if (logging_suspended == 0)
			logging_suspended = saved_suspend;
	}

	// Next document the results
	srand(time(NULL));
	seq_num = rand()%10000;
	if (gettimeofday(&tv, NULL) == 0) {
		snprintf(date, sizeof(date), "audit(%lu.%03u:%u)", tv.tv_sec,
			(unsigned)(tv.tv_usec/1000), seq_num);
	} else {
		snprintf(date, sizeof(date),
			"audit(%lu.%03u:%u)", (unsigned long)time(NULL),
			 0, seq_num);
        }

	data->head->reply.len = snprintf(txt, sizeof(txt), 
		"%s config changed, auid=%u pid=%d subj=%s res=success", date, 
		uid, pid, ctx );
	audit_msg(LOG_NOTICE, "%s", txt);
	data->head->reply.type = AUDIT_DAEMON_CONFIG;
	data->head->reply.message = strdup(txt);
	if (!data->head->reply.message) {
		data->head->reply.len = 0;
		audit_msg(LOG_ERR, "Cannot allocate config message");
		// FIXME: Should call some error handler
	}
	free((char *)ctx);
}

