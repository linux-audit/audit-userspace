/* auditd-reconfig.c -- 
 * Copyright 2005,2021 Red Hat Inc.
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
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "libaudit.h"
#include "auditd-event.h"
#include "auditd-config.h"
#include "private.h"

/* externs we need to know about */
extern void reconfig_ready(void);

/* This is the configuration manager code */
static pthread_t config_thread;
static pthread_mutex_t config_lock; // Only let one run at a time
static void *config_thread_main(void *arg);

void init_config_manager(void)
{
	pthread_mutex_init(&config_lock, NULL);
	audit_msg(LOG_DEBUG, "config_manager init complete");
}

/*
 * start_config_manager - start parsing a configuration reload
 * @e: signal information event owned by the caller
 *
 * The caller retains ownership of e when the request is rejected.
 *
 * Returns: 0 when the worker starts, 1 when busy or unable to start.
 */
int start_config_manager(struct auditd_event *e)
{
	int retval, rc = 0;

	retval = pthread_mutex_trylock(&config_lock);
	if (retval == 0) {
		pthread_attr_t detached;

		pthread_attr_init(&detached);
		pthread_attr_setdetachstate(&detached,
			PTHREAD_CREATE_DETACHED);

	        if (pthread_create(&config_thread, &detached,
		                config_thread_main, e) > 0) {
			audit_msg(LOG_ERR,
			"Couldn't create config thread, no config changes");
			pthread_mutex_unlock(&config_lock);
		        rc = 1;
	        }
		pthread_attr_destroy(&detached);
	} else {
		audit_msg(LOG_ERR,
			"Reconfiguration already in progress, no config changes");
		rc = 1;
	}
	return rc;
}

/*
 * finish_config_manager - allow another configuration reload to start
 *
 * The main thread calls this after consuming the worker's completion.
 * Keeping the lock until then prevents a new reload from replacing a
 * configuration that has been parsed but not yet applied.
 *
 * Returns: None.
 */
void finish_config_manager(void)
{
	pthread_mutex_unlock(&config_lock);
}

static void *config_thread_main(void *arg)
{
	sigset_t sigs;
	struct auditd_event *e = (struct auditd_event *)arg;
	struct daemon_conf new_config;

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGCHLD);
	sigaddset(&sigs, SIGCONT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	if (load_config(&new_config, TEST_AUDITD) == 0) {
		/* We will re-use the current reply */
		new_config.sender_uid = e->reply.signal_info->uid;
		new_config.sender_pid = e->reply.signal_info->pid;
		if (e->reply.len > 24)
			new_config.sender_ctx =
				strdup(e->reply.signal_info->ctx);
		else
			new_config.sender_ctx = strdup("?");
		memcpy(e->reply.msg.data, &new_config, sizeof(new_config));
		e->reply.conf = (struct daemon_conf *)e->reply.msg.data;
		e->reply.type = AUDIT_DAEMON_RECONFIG;
	} else {
		free_config(&new_config);
	}

	/* The main thread owns the event and completes either outcome. */
	reconfig_ready();
	return NULL;
}
