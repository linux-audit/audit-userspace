/* audispd.c --
 * Copyright 2007-08,2013,2016-23 Red Hat Inc.
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <pthread.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/uio.h>
#include <getopt.h>

#include "audispd-pconfig.h"
#include "audispd-config.h"
#include "audispd-llist.h"
#include "queue.h"
#include "libaudit.h"
#include "private.h"

/* Global Data */
static volatile int stop = 0;
volatile int disp_hup = 0;

/* Local data */
static daemon_conf_t daemon_config;
static conf_llist plugin_conf;
static pthread_t outbound_thread;
static int need_queue_depth_change = 0;

/* Local function prototypes */
static void signal_plugins(int sig);
static int event_loop(void);
static int safe_exec(plugin_conf_t *conf);
static void *outbound_thread_main(void *arg);
static int write_to_plugin(event_t *e, const char *string, size_t string_len,
			   lnode *conf) __attr_access ((__read_only__, 2, 3));

/*
 * Handle child plugins when they exit
 */
void plugin_child_handler(pid_t pid)
{
	if (pid > 0) {
		// Mark the child pid as 0 in the configs
		lnode *tpconf;
		plist_first(&plugin_conf);
		tpconf = plist_get_cur(&plugin_conf);
		while (tpconf) {
			if (tpconf->p && tpconf->p->pid == pid) {
				tpconf->p->pid = 0;
				break;
			}
			tpconf = plist_next(&plugin_conf);
		}
	}
}

static int count_dots(const char *s)
{
	const char *ptr;
	int cnt = 0;

	while ((ptr = strchr(s, '.'))) {
		cnt++;
		s = ptr + 1;
	}
	return cnt;
}

static void load_plugin_conf(conf_llist *plugin)
{
	DIR *d;

	/* init plugin list */
	plist_create(plugin);

	/* read configs */
	d = opendir(daemon_config.plugin_dir);
	if (d) {
		struct dirent *e;

		while ((e = readdir(d))) {
			plugin_conf_t config;
			char fname[PATH_MAX];

			// Don't run backup files, hidden files, or dirs
			if (e->d_name[0] == '.' || count_dots(e->d_name) > 1)
				continue;

			snprintf(fname, sizeof(fname), "%s/%s",
				daemon_config.plugin_dir, e->d_name);

			clear_pconfig(&config);
			if (load_pconfig(&config, fname) == 0) {
				/* Push onto config list only if active */
				if (config.active == A_YES)
					plist_append(plugin, &config);
				else
					free_pconfig(&config);
			} else
				audit_msg(LOG_ERR,
					"Skipping %s plugin due to errors",
					e->d_name);
		}
		closedir(d);
	}
}

static int start_one_plugin(lnode *conf)
{
	if (conf->p->restart_cnt > daemon_config.max_restarts)
		return 1;

	if (conf->p->type == S_ALWAYS) {
		if (safe_exec(conf->p)) {
			audit_msg(LOG_ERR,
				"Error running %s (%s) continuing without it",
				conf->p->path, strerror(errno));
			conf->p->active = A_NO;
			return 0;
		}

		/* Close the parent's read side */
		close(conf->p->plug_pipe[0]);
		conf->p->plug_pipe[0] = -1;
		/* Avoid leaking descriptor */
		fcntl(conf->p->plug_pipe[1], F_SETFD, FD_CLOEXEC);
	}
	return 1;
}

static int start_plugins(conf_llist *plugin)
{
	/* spawn children */
	lnode *conf;
	int active = 0;

	plist_first(plugin);
	conf = plist_get_cur(plugin);
	if (conf == NULL || conf->p == NULL)
		return active;

	do {
		if (conf->p && conf->p->active == A_YES) {
			if (start_one_plugin(conf))
				active++;
		}
	} while ((conf = plist_next(plugin)));
	return active;
}

static void copy_config(const struct daemon_conf *c)
{
	if (c->q_depth > daemon_config.q_depth)
		need_queue_depth_change = 1;

	daemon_config.q_depth = c->q_depth;
	daemon_config.overflow_action = c->overflow_action;
	daemon_config.max_restarts = c->max_restarts;
	if (daemon_config.plugin_dir == NULL)
		daemon_config.plugin_dir =
				c->plugin_dir ? strdup(c->plugin_dir) : NULL;
	else if (daemon_config.plugin_dir && c->plugin_dir &&
		strcmp(daemon_config.plugin_dir, c->plugin_dir)) {
		free(daemon_config.plugin_dir);
		daemon_config.plugin_dir = strdup(c->plugin_dir);
	} // else c->plugin_dir is NULL or they are the same
	  // Either way, let's leave them alone.
}

static int reconfigure(void)
{
	conf_llist tmp_plugin;
	lnode *tpconf;

	if (need_queue_depth_change) {
		need_queue_depth_change = 0;
		increase_queue_depth(daemon_config.q_depth);
	}
	reset_suspended();

	/* The idea for handling SIGHUP to children goes like this:
	 * 1) load the current config in temp list
	 * 2) mark all in real list unchecked
	 * 3) for each one in tmp list, scan old list
	 * 4) if new, start it, append to list, mark done
	 * 5) else check if there was a change to active state
	 * 6) if so, copy config over and start
	 * 7) If no change, send sighup to non-builtins and mark done
	 * 8) Finally, scan real list for unchecked, terminate and deactivate
	 */
	load_plugin_conf(&tmp_plugin);
	plist_mark_all_unchecked(&plugin_conf);

	plist_first(&tmp_plugin);
	tpconf = plist_get_cur(&tmp_plugin);
	while (tpconf && tpconf->p) {
		lnode *opconf;

		opconf = plist_find_name(&plugin_conf, tpconf->p->name);
		if (opconf == NULL) {
			/* We have a new service */
			if (tpconf->p->active == A_YES) {
				tpconf->p->checked = 1;
				plist_last(&plugin_conf);
				plist_append(&plugin_conf, tpconf->p);
				free(tpconf->p);
				tpconf->p = NULL;
				start_one_plugin(plist_get_cur(&plugin_conf));
			}
		} else {
			if (opconf->p->active == tpconf->p->active) {
				/* If active and no state change, sighup it */
				if (opconf->p->type == S_ALWAYS &&
						opconf->p->active == A_YES) {
					if (opconf->p->inode==tpconf->p->inode){
						if (opconf->p->pid)
						  kill(opconf->p->pid, SIGHUP);
					} else {
						/* Binary changed, restart */
						audit_msg(LOG_INFO,
					"Restarting %s since binary changed",
							opconf->p->path);
						if (opconf->p->pid)
						  kill(opconf->p->pid, SIGTERM);
						usleep(50000); // 50 msecs
						close(opconf->p->plug_pipe[1]);
						opconf->p->plug_pipe[1] = -1;
						opconf->p->pid = 0;
						start_one_plugin(opconf);
						opconf->p->inode =
							tpconf->p->inode;
					}
				}
				opconf->p->checked = 1;
			} else {
				/* A change in state */
				if (tpconf->p->active == A_YES) {
					/* starting - copy config and exec */
					free_pconfig(opconf->p);
					free(opconf->p);
					opconf->p = tpconf->p;
					opconf->p->checked = 1;
					start_one_plugin(opconf);
					tpconf->p = NULL;
				}
			}
		}

		tpconf = plist_next(&tmp_plugin);
	}

	/* Now see what's left over */
	while ( (tpconf = plist_find_unchecked(&plugin_conf)) ) {
		/* Anything not checked is something removed from the config */
		tpconf->p->active = A_NO;
		audit_msg(LOG_INFO, "Terminating %s because its now inactive",
				tpconf->p->path);
		if (tpconf->p->type == S_ALWAYS) {
			if (tpconf->p->pid)
				kill(tpconf->p->pid, SIGTERM);
			close(tpconf->p->plug_pipe[1]);
		}
		tpconf->p->plug_pipe[1] = -1;
		tpconf->p->pid = 0;
		tpconf->p->checked = 1;
	}

	/* Release memory from temp config */
	plist_first(&tmp_plugin);
	tpconf = plist_get_cur(&tmp_plugin);
	while (tpconf) {
		free_pconfig(tpconf->p);
		tpconf = plist_next(&tmp_plugin);
	}
	plist_clear(&tmp_plugin);
	return plist_count_active(&plugin_conf);
}

/*
 * Return 0 on success and 1 on failure
 *
 * Call tree:	auditd.c main
 *		auditd-dispatch.c init_dispatcher
 *
 * And:		auditd-event.c reconfigure
 *		auditd-dispatch.c reconfigure_dispatcher
 *
 * */
int libdisp_init(const struct daemon_conf *c)
{
	int i;

	/* Init the dispatcher's config */
	copy_config(c);

	/* Load all plugin configs */
	load_plugin_conf(&plugin_conf);

	/* If no plugins - exit */
	if (plist_count(&plugin_conf) == 0) {
		free(daemon_config.plugin_dir);
		daemon_config.plugin_dir = NULL;
		audit_msg(LOG_NOTICE,
			"No plugins found, not dispatching events");
		return 0;
	}

	/* Plugins are started with the auditd priority */
	i = start_plugins(&plugin_conf);

	/* Let the queue initialize */
	init_queue(daemon_config.q_depth);
	audit_msg(LOG_INFO,
	  "audit dispatcher initialized with q_depth=%d and %d active plugins",
		daemon_config.q_depth, i);

	/* Create outbound thread */
	pthread_create(&outbound_thread, NULL, outbound_thread_main, NULL);
	pthread_detach(outbound_thread);
	return 0;
}

/* outbound thread - dequeue data to plugins */
static void *outbound_thread_main(void *arg)
{
	lnode *conf;
	sigset_t sigs;

	/* This is a worker thread. Don't handle signals. */
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGCHLD);
	sigaddset(&sigs, SIGCONT);
	pthread_sigmask(SIG_SETMASK, &sigs, NULL);

	/* Start event loop */
	while (event_loop()) {
		if (reconfigure() == 0) {
			audit_msg(LOG_INFO,
		"After reconfigure, there are no active plugins, exiting");
			break;
		}
		disp_hup = 0;
	}

	/* Tell plugins we are going down */
	signal_plugins(SIGTERM);

	/* Release configs */
	plist_first(&plugin_conf);
	conf = plist_get_cur(&plugin_conf);
	while (conf) {
		free_pconfig(conf->p);
		conf = plist_next(&plugin_conf);
	}
	plist_clear(&plugin_conf);

	/* Cleanup the queue */
	destroy_queue();
	free(daemon_config.plugin_dir);
	daemon_config.plugin_dir = NULL;
	audit_msg(LOG_DEBUG, "Finished cleaning up dispatcher");

	return 0;
}

static int safe_exec(plugin_conf_t *conf)
{
	char **argv;
	int pid, i;

	/* Set up IPC with child */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, conf->plug_pipe) != 0)
		return -1;

	pid = fork();
	if (pid > 0) {
		conf->pid = pid;
		return 0;	/* Parent...normal exit */
	}
	if (pid < 0) {
		close(conf->plug_pipe[0]);
		close(conf->plug_pipe[1]);
		conf->pid = 0;
		return -1;	/* Failed to fork */
	}

	/* Set up comm with child */
	if (dup2(conf->plug_pipe[0], 0) < 0) {
		close(conf->plug_pipe[0]);
		close(conf->plug_pipe[1]);
		conf->pid = 0;
		return -1;	/* Failed to fork */
	}
	for (i=3; i<24; i++)	 /* Arbitrary number */
		close(i);

	argv = calloc(conf->nargs + 2, sizeof(char *));
	if (argv == NULL) {
		return -1;
	}

	/* Child */
	argv[0] = (char *)conf->path;
	for (i = 0; i < conf->nargs; i++) {
		argv[i+1] = conf->args[conf->nargs-i-1];
	}
	argv[conf->nargs+1] = NULL;

	execve(conf->path, argv, NULL);
	exit(1);		/* Failed to exec */
}

static void signal_plugins(int sig)
{
	lnode *conf;

	plist_first(&plugin_conf);
	conf = plist_get_cur(&plugin_conf);
	while (conf) {
		if (conf->p && conf->p->pid && conf->p->type == S_ALWAYS)
			kill(conf->p->pid, sig);
		conf = plist_next(&plugin_conf);
	}
}

static int write_to_plugin(event_t *e, const char *string, size_t string_len,
			   lnode *conf)
{
	int rc;

	if (conf->p->format == F_STRING) {
		do {
			rc = write(conf->p->plug_pipe[1], string, string_len);
		} while (rc < 0 && errno == EINTR);
	} else {
		struct iovec vec[2];

		vec[0].iov_base = &e->hdr;
		vec[0].iov_len = sizeof(struct audit_dispatcher_header);

		vec[1].iov_base = e->data;
		vec[1].iov_len = MAX_AUDIT_MESSAGE_LENGTH;
		do {
			rc = writev(conf->p->plug_pipe[1], vec, 2);
		} while (rc < 0 && errno == EINTR);
	}
	return rc;
}

/* Returns 0 on stop, and 1 on HUP */
static int event_loop(void)
{
	/* Figure out the format for the af_unix socket */
	while (stop == 0) {
		event_t *e;
		char *v, *ptr, unknown[32];
		int len;
		lnode *conf;

		/* This is where we block until we have an event */
		e = dequeue();
		if (e == NULL) {
			if (disp_hup)
				return 1;
			continue;
		}

		// Protocol 1 is not formatted
		if (e->hdr.ver == AUDISP_PROTOCOL_VER) {
			const char *type;

			/* Get the event formatted */
			type = audit_msg_type_to_name(e->hdr.type);
			if (type == NULL) {
				snprintf(unknown, sizeof(unknown),
					"UNKNOWN[%u]", e->hdr.type);
				type = unknown;
			}
			len = asprintf(&v, "type=%s msg=%.*s\n",
					type, e->hdr.size, e->data);
		// Protocol 2 events are already formatted
		} else if (e->hdr.ver == AUDISP_PROTOCOL_VER2) {
			len = asprintf(&v, "%.*s\n", e->hdr.size, e->data);
		} else
			len = 0;
		if (len <= 0) {
			v = NULL;
			free(e); /* Either corrupted event or no memory */
			continue;
		}

		/* Strip newlines from event record */
		ptr = v;
		while ((ptr = strchr(ptr, 0x0A)) != NULL) {
			if (ptr != &v[len-1])
				*ptr = ' ';
			else
				break; /* Done - exit loop */
		}

		/* Distribute event to the plugins */
		plist_first(&plugin_conf);
		conf = plist_get_cur(&plugin_conf);
		do {
			if (conf == NULL || conf->p == NULL)
				continue;
			if (conf->p->active == A_NO || stop)
				continue;

			/* Now send the event to the child */
			if (conf->p->type == S_ALWAYS && !stop) {
				int rc;
				rc = write_to_plugin(e, v, len, conf);
				if (rc < 0 && errno == EPIPE) {
					/* Child disappeared ? */
					if (!stop)
						audit_msg(LOG_ERR,
					"plugin %s terminated unexpectedly",
								conf->p->path);
					conf->p->pid = 0;
					conf->p->restart_cnt++;
					close(conf->p->plug_pipe[1]);
					conf->p->plug_pipe[1] = -1;
					conf->p->active = A_NO;
					if (!stop && conf->p->restart_cnt >
						daemon_config.max_restarts) {
						audit_msg(LOG_ERR,
					"plugin %s has exceeded max_restarts",
								conf->p->path);
					}
					if (!stop && start_one_plugin(conf)) {
						rc = write_to_plugin(e, v, len,
								     conf);
						audit_msg(LOG_NOTICE,
						"plugin %s was restarted",
							conf->p->path);
						conf->p->active = A_YES;
					}
				}
			}
		} while (!stop && (conf = plist_next(&plugin_conf)));

		/* Done with the memory...release it */
		free(v);
		free(e);
		if (disp_hup)
			break;
	}
	audit_msg(LOG_DEBUG, "Dispatcher event loop exit");
	if (stop)
		return 0;
	else
		return 1;
}

/* returns > 0 if plugins and 0 if none */
int libdisp_active(void)
{
	// If there's no plugins, the other thread is dead
	return plist_count(&plugin_conf);
}

/* returns 0 on success and -1 on error */
int libdisp_enqueue(event_t *e)
{
	return enqueue(e, &daemon_config);
}

void libdisp_nudge_queue(void)
{
	// Only nudge if there is something to nudge
	if (plist_count(&plugin_conf))
		nudge_queue();
}

/*
 * Called by:	auditd-event.c reconfigure
 *		auditd-dispatch.c reconfigure_dispatcher
 */
void libdisp_reconfigure(const struct daemon_conf *c)
{
	// If the dispatcher thread is dead, start a new one
	if (plist_count(&plugin_conf) == 0)
		libdisp_init(c);
	else { // Otherwise we do a reconfigure
			copy_config(c);
			disp_hup = 1;
			nudge_queue();
	}
}

void libdisp_write_queue_state(FILE *f)
{
	fprintf(f, "Number of active plugins = %u\n",
			plist_count(&plugin_conf));
	write_queue_state(f);
}

void libdisp_resume(void)
{
	resume_queue();
}

/* Used during startup and something failed */
void libdisp_shutdown(void)
{
	stop = 1;
	libdisp_nudge_queue();
}

