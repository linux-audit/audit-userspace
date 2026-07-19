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
#include <getopt.h>

#include "audispd-pconfig.h"
#include "audispd-config.h"
#include "audispd-llist.h"
#include "queue.h"
#include "libaudit.h"
#include "common.h"	// For ATOMIC_LOAD/STORE
#include "private.h"

/* Global Data */
#ifdef HAVE_ATOMIC
static ATOMIC_INT stop = 0;
ATOMIC_INT disp_hup = 0;
static ATOMIC_INT plugin_child_pending = 0;
#else
static volatile ATOMIC_INT stop = 0;
volatile ATOMIC_INT disp_hup = 0;
static volatile ATOMIC_INT plugin_child_pending = 0;
#endif

/* Local data */
static daemon_conf_t daemon_config;
static daemon_conf_t saved_daemon_config;
static int saved_daemon_config_valid = 0;
static conf_llist plugin_conf;
static pthread_t outbound_thread;
static int need_queue_depth_change = 0;
static int saved_need_queue_depth_change = 0;

/* Local function prototypes */
static int event_loop(void);
static int safe_exec(plugin_conf_t *conf);
static void *outbound_thread_main(void *arg);
static void reap_plugin_children(void);
static int stop_plugin(plugin_conf_t *conf);
static int stop_plugins(void);
static void free_plugin_list(conf_llist *list);
static int write_all(int fd, const void *buf, size_t len)
	__attr_access ((__read_only__, 2, 3));
static int write_to_plugin(event_t *e, const char *string, size_t string_len,
			   lnode *conf) __attr_access ((__read_only__, 2, 3));

/*
 * Free dispatcher-owned string fields in config.
 * Returns nothing.
 */
static void free_disp_config(daemon_conf_t *config)
{
	free(config->plugin_dir);
	config->plugin_dir = NULL;
}

/*
 * Save daemon_config before staging reload values.
 * Returns 0 on success and 1 on allocation failure.
 */
static int save_daemon_config(void)
{
	if (saved_daemon_config_valid)
		return 0;

	saved_daemon_config = daemon_config;
	saved_daemon_config.plugin_dir = NULL;
	if (daemon_config.plugin_dir) {
		saved_daemon_config.plugin_dir =
					strdup(daemon_config.plugin_dir);
		if (saved_daemon_config.plugin_dir == NULL)
			return 1;
	}
	saved_need_queue_depth_change = need_queue_depth_change;
	saved_daemon_config_valid = 1;
	return 0;
}

/*
 * Drop the saved dispatcher config after a successful reload.
 * Returns nothing.
 */
static void discard_saved_daemon_config(void)
{
	if (!saved_daemon_config_valid)
		return;
	free_disp_config(&saved_daemon_config);
	saved_need_queue_depth_change = 0;
	saved_daemon_config_valid = 0;
}

/*
 * Restore daemon_config after a failed reload.
 * Returns nothing.
 */
static void restore_daemon_config(void)
{
	if (!saved_daemon_config_valid)
		return;
	free_disp_config(&daemon_config);
	daemon_config = saved_daemon_config;
	need_queue_depth_change = saved_need_queue_depth_change;
	memset(&saved_daemon_config, 0, sizeof(saved_daemon_config));
	saved_need_queue_depth_change = 0;
	saved_daemon_config_valid = 0;
}

/*
 * Report a possible plugin exit to the dispatcher worker.
 * Returns nothing. The worker owns waitpid() and all plugin PID state.
 */
void libdisp_child_changed(void)
{
#ifdef HAVE_ATOMIC
	atomic_store_explicit(&plugin_child_pending, 1, memory_order_relaxed);
#else
	__atomic_store_n(&plugin_child_pending, 1, __ATOMIC_RELAXED);
#endif
	nudge_queue();
}

/*
 * Plugin child ownership and replacement contract
 * ------------------------------------------------
 * The dispatcher worker is the only code that reaps plugin children or
 * changes plugin_conf->pid. auditd's SIGCHLD callback only sets the atomic
 * notification above. Since a plugin normally has external side effects,
 * such as delivering to syslog, an AF_UNIX listener, the SELinux
 * troubleshooter, or a remote collector, two generations of the same plugin
 * must never run at once. Keep the old PID in its original plugin_conf until
 * exact-PID waitpid() confirms that it is gone; only then may reconfiguration
 * or automatic restart start its replacement.
 * Reconfiguration is therefore a generation barrier: queued events remain
 * in the dispatcher while every child from the old list stops, then the old
 * list is freed and the complete new list is started.
 *
 * Besides preserving event order, leaving an exited child waitable prevents
 * its PID from being reused before the dispatcher clears plugin_conf->pid.
 * Plugin installations normally contain zero, one, or two entries, so an
 * exact-PID scan of the existing list is deliberately preferred over more
 * child-tracking state or cross-thread locking.
 * A plugin that ignores both EOF and SIGTERM blocks replacement rather than
 * allowing two generations to overlap.
 */

/*
 * Reap a tracked plugin child if it has exited.
 * @pid: PID owned by the dispatcher
 *
 * Returns 1 after reaping it or observing ECHILD, 0 for a running child,
 * and -1 on other errors.
 */
static int reap_plugin_child(pid_t pid)
{
	pid_t rc;

	do {
		rc = waitpid(pid, NULL, WNOHANG);
	} while (rc < 0 && errno == EINTR);
	if (rc == 0)
		return 0;
	if (rc == pid || (rc < 0 && errno == ECHILD))
		return 1;
	return -1;
}

/*
 * Reap exited plugin children from the original configuration list.
 * Returns nothing. Direct link traversal preserves plugin_conf's cursor.
 */
static void reap_plugin_children(void)
{
	lnode *conf;

	AUDIT_ATOMIC_STORE(plugin_child_pending, 0);
	for (conf = plugin_conf.head; conf; conf = conf->next) {
		if (conf->p && conf->p->pid > 0 &&
		    reap_plugin_child(conf->p->pid) > 0)
			conf->p->pid = 0;
	}
}

/*
 * Stop and reap one plugin before its configuration is replaced or freed.
 * @conf: plugin configuration that owns the child
 *
 * Closing the input first gives the plugin a chance to consume data already
 * written to its socket. If it does not exit on EOF, SIGTERM requests the
 * plugin's normal shutdown. Returns 0 after reaping it and 1 on error.
 */
static int stop_plugin(plugin_conf_t *conf)
{
	int state;
	pid_t pid = conf->pid;
	pid_t rc;

	if (conf->plug_pipe[1] >= 0) {
		close(conf->plug_pipe[1]);
		conf->plug_pipe[1] = -1;
	}
	if (pid <= 0)
		return 0;

	/* Let EOF terminate a cooperative plugin before signalling it. */
	usleep(50000);
	state = reap_plugin_child(pid);
	if (state > 0) {
		conf->pid = 0;
		return 0;
	}
	if (state < 0)
		return 1;

	if (kill(pid, SIGTERM) != 0 && errno != ESRCH)
		return 1;
	do {
		rc = waitpid(pid, NULL, 0);
	} while (rc < 0 && errno == EINTR);
	if (rc != pid && !(rc < 0 && errno == ECHILD))
		return 1;
	conf->pid = 0;
	return 0;
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

static int load_plugin_conf(conf_llist *plugin)
{
	DIR *d;
	int failures = 0;

	/* init plugin list */
	plist_create(plugin);

	/* read configs */
	d = opendir(daemon_config.plugin_dir);
	if (d) {
		int dfd = dirfd(d);
		if (dfd < 0) {
			closedir(d);
			return 1;
		}

		struct dirent *e;

		while ((e = readdir(d))) {
			plugin_conf_t config;
			const char *ext, *reason = NULL;

			if (e->d_name[0] == '.')
				reason = "hidden file";
			else if (count_dots(e->d_name) > 1)
				reason = "backup file";
			else if ((ext = strrchr(e->d_name, '.')) && strcmp(ext, ".conf") != 0)
				reason = "file without .conf suffix";

			if (reason) {
				audit_msg(LOG_DEBUG,
					  "Skipping %s plugin due to %s",
					  e->d_name, reason);
				continue;
			}

			clear_pconfig(&config);
			if (load_pconfig(&config, dfd, e->d_name) == 0) {
				/* Push onto config list only if active */
				if (config.active == A_YES) {
					if (plist_append(plugin, &config) != 0) {
						audit_msg(LOG_ERR,
					    "Failed adding %s plugin to list",
								e->d_name);
						free_pconfig(&config);
						failures = 1;
					}
				} else
					free_pconfig(&config);
			} else {
				audit_msg(LOG_ERR,
					"Skipping %s plugin due to errors",
					e->d_name);
				failures = 1;
			}
		}
		closedir(d);
	} else
		failures = 1;
	return failures;
}

/*
 * Free every configuration and node in a plugin list.
 * Returns nothing.
 */
static void free_plugin_list(conf_llist *list)
{
	lnode *conf;

	for (conf = list->head; conf; conf = conf->next)
		free_pconfig(conf->p);
	plist_clear(list);
}

static int start_one_plugin(lnode *conf)
{
	if (conf->p->restart_cnt > daemon_config.max_restarts) {
		/* Do not mark active when max restarts exceeded */
		conf->p->active = A_NO;
		return 0;
	}

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

/*
 * Copy the audit daemon dispatcher settings into daemon_config.
 * Returns 0 on success and 1 on allocation failure.
 */
static int copy_config(const struct daemon_conf *c)
{
	char *plugin_dir = NULL;

	if (c->plugin_dir) {
		plugin_dir = strdup(c->plugin_dir);
		if (plugin_dir == NULL) {
			audit_msg(LOG_ERR,
				  "Cannot duplicate dispatcher plugin_dir");
			return 1;
		}
	}

	if (c->q_depth > daemon_config.q_depth)
		need_queue_depth_change = 1;

	daemon_config.q_depth = c->q_depth;
	daemon_config.overflow_action = c->overflow_action;
	daemon_config.max_restarts = c->max_restarts;
	free(daemon_config.plugin_dir);
	daemon_config.plugin_dir = plugin_dir;
	return 0;
}

static int reconfigure(void)
{
	conf_llist tmp_plugin;
	int active;

	reap_plugin_children();
	if (load_plugin_conf(&tmp_plugin)) {
		audit_msg(LOG_ERR,
			"Plugin configuration reload failed, keeping old state");
		restore_daemon_config();
		free_plugin_list(&tmp_plugin);
		return plist_count_active(&plugin_conf);
	}
	discard_saved_daemon_config();
	if (need_queue_depth_change) {
		need_queue_depth_change = 0;
		increase_queue_depth(daemon_config.q_depth);
	}
	reset_suspended();

	/* The old generation must be gone before the new list is installed. */
	if (stop_plugins()) {
		audit_msg(LOG_ERR,
			  "Cannot stop old plugin generation, disabling plugins");
		free_plugin_list(&tmp_plugin);
		return 0;
	}
	free_plugin_list(&plugin_conf);
	plugin_conf = tmp_plugin;
	active = start_plugins(&plugin_conf);
	return active;
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
	if (copy_config(c))
		return 1;

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
		AUDIT_ATOMIC_STORE(disp_hup, 0);
	}

	/* Stop and reap plugins before releasing their configurations. */
	stop_plugins();
	free_plugin_list(&plugin_conf);

	/* Cleanup the queue */
	destroy_queue();
	free(daemon_config.plugin_dir);
	daemon_config.plugin_dir = NULL;
	audit_msg(LOG_INFO, "Dispatcher plugins cleaned up");

	return 0;
}

static int safe_exec(plugin_conf_t *conf)
{
	char **argv;
	int i, saved_errno;
	pid_t pid;
	sigset_t sigs;

	conf->pid = 0;
	conf->plug_pipe[0] = -1;
	conf->plug_pipe[1] = -1;
	argv = calloc(conf->nargs + 2, sizeof(char *));
	if (argv == NULL)
		return -1;
	argv[0] = (char *)conf->path;
	for (i = 0; i < conf->nargs; i++)
		argv[i + 1] = conf->args[conf->nargs - i - 1];
	argv[conf->nargs + 1] = NULL;
	sigfillset(&sigs);

	/* Set up IPC with child */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, conf->plug_pipe) != 0) {
		saved_errno = errno;
		conf->plug_pipe[0] = -1;
		conf->plug_pipe[1] = -1;
		free(argv);
		errno = saved_errno;
		return -1;
	}

	pid = fork();
	if (pid > 0) {
		conf->pid = pid;
		free(argv);
		return 0;	/* Parent...normal exit */
	}
	if (pid < 0) {
		saved_errno = errno;
		close(conf->plug_pipe[0]);
		close(conf->plug_pipe[1]);
		conf->plug_pipe[0] = -1;
		conf->plug_pipe[1] = -1;
		conf->pid = 0;
		free(argv);
		errno = saved_errno;
		return -1;	/* Failed to fork */
	}

	/* Set up comm with child. It reads stdin so put the pipe there. */
	if (dup2(conf->plug_pipe[0], 0) < 0) {
		_exit(1);
	}
#ifdef HAVE_CLOSE_RANGE
	close_range(3, ~0U, 0);	/* close all past stderr */
#else
	for (i=3; i<24; i++)	 /* Arbitrary number */
		close(i);
#endif

	/* Child */
	sigprocmask(SIG_UNBLOCK, &sigs, NULL);

	execve(conf->path, argv, NULL);
	_exit(1);		/* Failed to exec */
}

/*
 * Stop every plugin child serially before dispatcher-owned state is freed.
 * Returns 0 on success and 1 if a child could not be stopped.
 */
static int stop_plugins(void)
{
	lnode *conf;
	int rc = 0;

	audit_msg(LOG_INFO, "Terminating plugins");
	for (conf = plugin_conf.head; conf; conf = conf->next) {
		if (conf->p && conf->p->type == S_ALWAYS &&
		    stop_plugin(conf->p)) {
			audit_msg(LOG_ERR, "Cannot stop child for %s",
				  conf->p->path);
			rc = 1;
		}
	}
	return rc;
}

static int write_all(int fd, const void *buf, size_t len)
{
	const char *ptr = buf;

	while (len) {
		ssize_t rc;

		do {
			rc = write(fd, ptr, len);
		} while (rc < 0 && errno == EINTR);
		if (rc <= 0) {
			if (rc == 0)
				errno = EIO;
			return -1;
		}
		ptr += rc;
		len -= rc;
	}
	return 0;
}

static int write_to_plugin(event_t *e, const char *string, size_t string_len,
			   lnode *conf)
{
	if (conf->p->format == F_STRING)
		return write_all(conf->p->plug_pipe[1], string, string_len);

	// The other path used writev. This simulates what writev used to do
	// Header
	if (write_all(conf->p->plug_pipe[1], &e->hdr,
			  sizeof(struct audit_dispatcher_header)) < 0)
		return -1;
	// Data
	return write_all(conf->p->plug_pipe[1], e->data, e->hdr.size);
}

/*
 * finish_plugin_restart - deliver the pending event after a plugin restart
 * @e: event that exposed the failed plugin
 * @string: formatted event data for string plugins
 * @string_len: length of the formatted event data
 * @conf: restarted plugin configuration
 *
 * Returns nothing. The plugin is marked active only after a complete write.
 * A plugin that cannot accept the pending event is stopped so it cannot remain
 * blocked and inactive until dispatcher shutdown.
 */
static void finish_plugin_restart(event_t *e, const char *string,
				  size_t string_len, lnode *conf)
{
	if (write_to_plugin(e, string, string_len, conf) < 0) {
		int saved_errno = errno;

		audit_msg(LOG_ERR, "plugin %s failed after restart: %s",
			  conf->p->path, strerror(saved_errno));
		if (stop_plugin(conf->p))
			audit_msg(LOG_ERR, "Cannot stop restarted child for %s",
				  conf->p->path);
		return;
	}

	audit_msg(LOG_NOTICE, "plugin %s was restarted (%ux)", conf->p->path,
		  conf->p->restart_cnt);
	conf->p->active = A_YES;
}

/* Returns 0 on stop, and 1 on HUP */
static char fmt_buf[FORMAT_BUF_LEN];
static int event_loop(void)
{
	/* Figure out the format for the af_unix socket */
	while (AUDIT_ATOMIC_LOAD(stop) == 0) {
		event_t *e;
		char *ptr, unknown[32];
		int len;
		lnode *conf;

		/* A child can exit before the queue is ready to be nudged. */
		if (AUDIT_ATOMIC_LOAD(plugin_child_pending))
			reap_plugin_children();

		/* This is where we block until we have an event */
		e = dequeue();
		if (e == NULL) {
			if (AUDIT_ATOMIC_LOAD(disp_hup))
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
			len = snprintf(fmt_buf, sizeof(fmt_buf),
				       "type=%s msg=%.*s\n",
					type, e->hdr.size, e->data);
		// Protocol 2 events are already formatted - just copy
		} else if (e->hdr.ver == AUDISP_PROTOCOL_VER2) {
			size_t to_copy = e->hdr.size;

			if (to_copy > MAX_AUDIT_MESSAGE_LENGTH)
				to_copy = MAX_AUDIT_MESSAGE_LENGTH;

			// was snprintf, this is faster
			memcpy(fmt_buf, e->data, to_copy);

			fmt_buf[to_copy]     = '\n';
			fmt_buf[to_copy + 1] = '\0';
			len = (int)(to_copy + 1);
		} else
			len = 0;
		if (len <= 0) {
			free(e); /* Either corrupted event or no memory */
			continue;
		}

		/* Strip newlines from event record except the last one */
		ptr = fmt_buf;
		while ((ptr = strchr(ptr, 0x0A)) != NULL) {
			if (ptr != &fmt_buf[len-1])
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
			if (conf->p->active == A_NO || AUDIT_ATOMIC_LOAD(stop))
				continue;

			/* Now send the event to the child */
			if (conf->p->type == S_ALWAYS &&
					!AUDIT_ATOMIC_LOAD(stop)) {
				int rc;
				rc = write_to_plugin(e, fmt_buf, len, conf);
				if (rc < 0 && errno == EPIPE) {
					/* Child disappeared ? */
					if (!AUDIT_ATOMIC_LOAD(stop))
						audit_msg(LOG_ERR,
					"plugin %s terminated unexpectedly",
								conf->p->path);
					conf->p->restart_cnt++;
					conf->p->active = A_NO;
					if (stop_plugin(conf->p)) {
						audit_msg(LOG_ERR,
						 "Cannot stop old child for %s",
						 conf->p->path);
					} else if (!AUDIT_ATOMIC_LOAD(stop) &&
					    conf->p->restart_cnt >
					    daemon_config.max_restarts) {
						audit_msg(LOG_ERR,
					"plugin %s has exceeded max_restarts",
								conf->p->path);
					} else if (!AUDIT_ATOMIC_LOAD(stop) &&
						   start_one_plugin(conf)) {
						finish_plugin_restart(e, fmt_buf, len,
								      conf);
					}
				}
			}
		} while (!AUDIT_ATOMIC_LOAD(stop) &&
			 (conf = plist_next(&plugin_conf)));

		/* Done with the memory...release it */
		free(e);
		if (AUDIT_ATOMIC_LOAD(disp_hup))
			break;
	}
	audit_msg(LOG_DEBUG, "Dispatcher event loop exit");
	if (AUDIT_ATOMIC_LOAD(stop))
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

/*
 * returns 0 on success,
 * 1 if the event could not be queued due to overflow or
 * when processing is suspended, and
 * -1 on other errors
 */
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
			if (save_daemon_config()) {
				audit_msg(LOG_ERR,
					  "Cannot save dispatcher config");
				return;
			}
			if (copy_config(c)) {
				restore_daemon_config();
				return;
			}
			AUDIT_ATOMIC_STORE(disp_hup, 1);
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
	discard_saved_daemon_config();
	AUDIT_ATOMIC_STORE(stop, 1);
	libdisp_nudge_queue();
}
