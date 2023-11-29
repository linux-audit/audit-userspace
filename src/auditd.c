/* auditd.c -- 
 * Copyright 2004-09,2011,2013,2016-18,2021 Red Hat Inc.
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
 *   Rickard E. (Rik) Faith <faith@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/utsname.h>
#include <getopt.h>

#include "libaudit.h"
#include "auditd-event.h"
#include "auditd-config.h"
#include "auditd-dispatch.h"
#include "auditd-listen.h"
#include "libdisp.h"
#include "private.h"

#include "ev.h"

#if EV_CHILD_ENABLE
#error "LIBEV must not have EV_CHILD_ENABLE set"
#endif

#define EV_STOP() ev_unloop (ev_default_loop (EVFLAG_AUTO), EVUNLOOP_ALL), stop = 1;

#define DEFAULT_BUF_SZ	448
#define DMSG_SIZE (DEFAULT_BUF_SZ + 48) 
#define SUCCESS 0
#define FAILURE 1
#define SUBJ_LEN 4097

/* Global Data */
volatile int stop = 0;

/* Local data */
static int fd = -1, pipefds[2] = {-1, -1};
static struct daemon_conf config;
static const char *pidfile = "/var/run/auditd.pid";
static const char *state_file = "/var/run/auditd.state";
static int init_pipe[2];
static int do_fork = 1, opt_aggregate_only = 0, config_dir_set = 0;
static struct auditd_event *cur_event = NULL, *reconfig_ev = NULL;
static int hup_info_requested = 0;
static int usr1_info_requested = 0, usr2_info_requested = 0;
static char subj[SUBJ_LEN];
static uint32_t session;

/* Local function prototypes */
int send_audit_event(int type, const char *str);
static void clean_exit(void);
static int get_reply(int fd, struct audit_reply *rep, int seq);
static char *getsubj(char *subj);

enum startup_state {startup_disable=0, startup_enable, startup_nochange,
	startup_INVALID};
static const char *startup_states[] = {"disable", "enable", "nochange"};

/*
 * Output a usage message
 */
static void usage(void)
{
	fprintf(stderr,
		"Usage: auditd [-f] [-l] [-n] [-s %s|%s|%s] "
		"[-c <config_file>]\n",
		startup_states[startup_disable],
		startup_states[startup_enable],
		startup_states[startup_nochange]);

	exit(2);
}


/*
 * SIGTERM handler
 */ 
static void term_handler(struct ev_loop *loop, struct ev_signal *sig,
			int revents)
{
	EV_STOP ();
}


/*
 * Used to reconfigure the daemon
 */
static void hup_handler( struct ev_loop *loop, struct ev_signal *sig, int revents )
{
	int rc;

	rc = audit_request_signal_info(fd);
	if (rc < 0)
		send_audit_event(AUDIT_DAEMON_CONFIG, 
	  "op=reconfigure state=no-change auid=-1 pid=-1 subj=? res=failed");
	else
		hup_info_requested = 1;
}

/*
 * Used to force log rotation
 */
static void user1_handler(struct ev_loop *loop, struct ev_signal *sig,
			int revents)
{
	int rc;

	rc = audit_request_signal_info(fd);
	if (rc < 0)
		send_audit_event(AUDIT_DAEMON_ROTATE, 
			 "op=rotate-logs auid=-1 pid=-1 subj=? res=failed");
	else
		usr1_info_requested = 1;
}

/*
 * Used to resume logging
 */
static void user2_handler( struct ev_loop *loop, struct ev_signal *sig, int revents )
{
	int rc;

	rc = audit_request_signal_info(fd);
	if (rc < 0) {
		resume_logging();
		send_audit_event(AUDIT_DAEMON_RESUME, 
			 "op=resume-logging auid=-1 pid=-1 subj=? res=success");
	} else
		usr2_info_requested = 1;
}

/*
 * Used with email alerts to cleanup
 */
static void child_handler(struct ev_loop *loop, struct ev_signal *sig,
			int revents)
{
	int pid;

	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
		if (pid == dispatcher_pid())
			dispatcher_reaped();
	}
}

static void child_handler2( int sig )
{
	child_handler(NULL, NULL, 0);
}

/*
 * Used to dump internal state information
 */
static void cont_handler(struct ev_loop *loop, struct ev_signal *sig,
			int revents)
{
	char buf[64];
	mode_t u = umask(0137);	// allow 0640
	FILE *f = fopen(state_file, "w");
	umask(u);
	if (f == NULL)
		return;

	fprintf(f, "audit version = %s\n", VERSION);
	time_t now = time(0);
	strftime(buf, sizeof(buf), "%x %X", localtime(&now));
	fprintf(f, "current time = %s\n", buf);
	fprintf(f, "process priority = %d\n", getpriority(PRIO_PROCESS, 0));
	write_logging_state(f);
	libdisp_write_queue_state(f);
#ifdef USE_LISTENER
	write_connection_state(f);
#endif
	fclose(f);
}

static int extract_type(const char *str)
{
	char tmp, *ptr2, *ptr = (char *)str;
	int type;
	if (*str == 'n') {
		ptr = strchr(str+1, ' ');
		if (ptr == NULL)
			return -1; // Malformed - bomb out
		ptr++;
	}

	// ptr should be at 't'
	ptr2 = strchr(ptr, ' ');
	if (ptr2 == NULL)
		return -1; // Malformed - bomb out

	// find =
	str = strchr(ptr, '=');
	if (str == NULL || str >= ptr2)
		return -1; // Malformed - bomb out

	// name is 1 past
	str++;

	// Save character & terminate string
	tmp = *ptr2;
	*ptr2 = 0;

	type = audit_name_to_msg_type(str);

	*ptr2 = tmp; // Restore character

	return type;
}

void distribute_event(struct auditd_event *e)
{
	int route = 1, proto;

	if (config.log_format == LF_ENRICHED)
		proto = AUDISP_PROTOCOL_VER2;
	else
		proto = AUDISP_PROTOCOL_VER;

	/* If type is 0, then its a network originating event */
	if (e->reply.type == 0) {
		// See if we are distributing network originating events
		if (!dispatch_network_events())
			route = 0;
		else {	// We only need the original type if its being routed
			e->reply.type = extract_type(e->reply.message);

			// Treat everything from the network as VER2
			// because they are already formatted. This is
			// important when it gets to the dispatcher which
			// can strip node= when its VER1.
			proto = AUDISP_PROTOCOL_VER2;
		}
	} else if (e->reply.type != AUDIT_DAEMON_RECONFIG) {
		// All other local events need formatting
		format_event(e);

		// If the event has been formatted with node, upgrade
		// to VER2 so that the dispatcher honors the formatting
		if (config.node_name_format != N_NONE)
			proto = AUDISP_PROTOCOL_VER2;
	} else
		route = 0; // Don't DAEMON_RECONFIG events until after enqueue

	/* End of Event is for realtime interface - skip local logging of it */
	if (e->reply.type != AUDIT_EOE)
		handle_event(e); /* Write to local disk */

	/* Next, send to plugins */
	if (route)
		dispatch_event(&e->reply, proto);

	/* Free msg and event memory */
	cleanup_event(e);
}

/*
 * This function is used to send start, stop, and abort messages 
 * to the audit log.
 */
static unsigned seq_num = 0;
int send_audit_event(int type, const char *str)
{
	struct auditd_event *e;
	struct timeval tv;

	e = create_event(NULL, 0, NULL, 0);
	if (e == NULL) {
		audit_msg(LOG_ERR, "Cannot allocate audit reply");
		return 1;
	}

	e->reply.type = type;
	if (seq_num == 0) {
		// seq_num does not have to cryptographically secure
		srandom(time(NULL));
		seq_num = random()%10000;
	} else
		seq_num++;
	// Write event into netlink area like normal events
	if (gettimeofday(&tv, NULL) == 0) {
		e->reply.len = snprintf((char *)e->reply.msg.data,
			DMSG_SIZE, "audit(%lld.%03u:%u): %s",
			(long long int)tv.tv_sec, (unsigned)(tv.tv_usec/1000),
			seq_num, str);
	} else {
		e->reply.len = snprintf((char *)e->reply.msg.data,
			DMSG_SIZE, "audit(%lld.%03d:%u): %s",
			(long long int)time(NULL), 0, seq_num, str);
	}
	// Point message at the netlink buffer like normal events
	e->reply.message = e->reply.msg.data;
	if (e->reply.len > DMSG_SIZE)
		e->reply.len = DMSG_SIZE;

	distribute_event(e);
	return 0;
}

static int write_pid_file(void)
{
	int pidfd, len;
	char val[16];

	len = snprintf(val, sizeof(val), "%u\n", getpid());
	if (len <= 0) {
		audit_msg(LOG_ERR, "Pid error (%s)", strerror(errno));
		pidfile = 0;
		return 1;
	}
	pidfd = open(pidfile, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
	if (pidfd < 0) {
		audit_msg(LOG_ERR, "Unable to set pidfile (%s)",
			strerror(errno));
		pidfile = 0;
		return 1;
	}
	if (write(pidfd, val, (unsigned int)len) != len) {
		audit_msg(LOG_ERR, "Unable to write pidfile (%s)",
			strerror(errno));
		close(pidfd);
		pidfile = 0;
		return 1;
	}
	close(pidfd);
	return 0;
}

static void avoid_oom_killer(void)
{
	int oomfd, len, rc;
	char *score = NULL;

	/* New kernels use different technique */	
	if ((oomfd = open("/proc/self/oom_score_adj",
				O_NOFOLLOW | O_WRONLY)) >= 0) {
		score = "-1000";
	} else if ((oomfd = open("/proc/self/oom_adj",
				O_NOFOLLOW | O_WRONLY)) >= 0) {
		score = "-17";
	} else {
		audit_msg(LOG_NOTICE, "Cannot open out of memory adjuster");
		return;
	}

	len = strlen(score);
	rc = write(oomfd, score, len);
	if (rc != len)
		audit_msg(LOG_NOTICE, "Unable to adjust out of memory score");

	close(oomfd);
}

/*
 * This function will take care of becoming a daemon. The parent
 * will wait until the child notifies it by writing into a special
 * pipe to signify that it successfully initialized. This prevents
 * a race in the init script where rules get loaded before the daemon
 * is ready and they wind up in syslog. The child returns 0 on success
 * and nonzero on failure. The parent returns nonzero on failure. On
 * success, the parent calls _exit with 0.
 */
static int become_daemon(void)
{
	int nfd, rc;
	pid_t pid;
	int status;

	if (do_fork) {
		if (pipe(init_pipe) ||
				fcntl(init_pipe[0], F_SETFD, FD_CLOEXEC) ||
				fcntl(init_pipe[1], F_SETFD, FD_CLOEXEC))
			return -1;
		pid = fork();
	} else
		pid = 0;

	switch (pid)
	{
		case 0:
			/* No longer need this...   */
			if (do_fork)
				close(init_pipe[0]);

			/* Open stdin,out,err to /dev/null */
			nfd = open("/dev/null", O_RDWR);
			if (nfd < 0) {
				audit_msg(LOG_ERR, "Cannot open /dev/null");
				return -1;
			}
			if ((dup2(nfd, 0) < 0) || (dup2(nfd, 1) < 0) ||
							(dup2(nfd, 2) < 0)) {
				audit_msg(LOG_ERR,
				    "Cannot reassign descriptors to /dev/null");
				close(nfd);
				return -1;
			}
			close(nfd);

			/* Change to '/' */
			rc = chdir("/");
			if (rc < 0) {
				audit_msg(LOG_ERR,
					"Cannot change working directory to /");
				return -1;
			}

			/* Become session/process group leader */
			setsid();
			break;
		case -1:
			return -1;
		default:
			/* Wait for the child to say its done */
			do {
				rc = read(init_pipe[0], &status,sizeof(status));
			} while (rc < 0 && errno == EINTR);
			if (rc < 0)
				return -1;

			/* Success - die a happy death */
			if (status == SUCCESS) {
				free_config(&config);
				_exit(0);
			}
			return -1;
	}

	return 0;
}

static void tell_parent(int status)
{
	ssize_t rc;

	if (config.daemonize != D_BACKGROUND || do_fork == 0)
		return;
	do {
		rc = write(init_pipe[1], &status, sizeof(status));
	} while (rc < 0 && errno == EINTR);
}

static void netlink_handler(struct ev_loop *loop, struct ev_io *io,
			int revents)
{
	int rc = 1, cnt = 0;

	// Try to get all the events that are waiting but yield after 5 to
	// let other handlers run. Five should cover PATH events.
	// FIXME: backing down to 3 until IPC is faster
	while (rc > 0 && cnt < 3) {
		if (cur_event == NULL) {
			if ((cur_event = malloc(sizeof(*cur_event))) == NULL) {
				char emsg[DEFAULT_BUF_SZ];
				if (*subj)
					snprintf(emsg, sizeof(emsg),
			"op=error-halt auid=%u pid=%d subj=%s res=failed",
						audit_getloginuid(),
						getpid(), subj);
				else
					snprintf(emsg, sizeof(emsg),
				 "op=error-halt auid=%u pid=%d res=failed",
						 audit_getloginuid(),
						 getpid());
				EV_STOP ();
				send_audit_event(AUDIT_DAEMON_ABORT, emsg);
				audit_msg(LOG_ERR,
				  "Cannot allocate audit reply, exiting");
				shutdown_events();
				if (pidfile)
					unlink(pidfile);
				shutdown_dispatcher();
				return;
			}
			cur_event->ack_func = NULL;
		}

		rc = audit_get_reply(fd, &cur_event->reply,
			    GET_REPLY_NONBLOCKING, 0);
		if (rc > 0) {
			switch (cur_event->reply.type)
			{	/* Don't process these */
			case NLMSG_NOOP:
			case NLMSG_DONE:
			case NLMSG_ERROR:
			case AUDIT_GET: /* Or these */
			case AUDIT_WATCH_INS...AUDIT_WATCH_LIST:
			case AUDIT_ADD_RULE...AUDIT_GET_FEATURE:
			case AUDIT_FIRST_DAEMON...AUDIT_LAST_DAEMON:
			case AUDIT_REPLACE:
				break;
			case AUDIT_SIGNAL_INFO:
				if (hup_info_requested) {
					char hup[MAX_AUDIT_MESSAGE_LENGTH];
					audit_msg(LOG_DEBUG,
				    "HUP detected, starting config manager");
					reconfig_ev = cur_event;
					if (start_config_manager(cur_event)) {
						audit_format_signal_info(hup,
								 sizeof(hup),
						 "reconfigure state=no-change",
							 &cur_event->reply,
								 "failed");
					send_audit_event(AUDIT_DAEMON_CONFIG,
							 hup);
					}
					cur_event = NULL;
					hup_info_requested = 0;
				} else if (usr1_info_requested) {
					char usr1[MAX_AUDIT_MESSAGE_LENGTH];
				audit_format_signal_info(usr1, sizeof(usr1),
							 "rotate-logs",
							 &cur_event->reply,
							 "success");
				send_audit_event(AUDIT_DAEMON_ROTATE, usr1);
					usr1_info_requested = 0;
				} else if (usr2_info_requested) {
					char usr2[MAX_AUDIT_MESSAGE_LENGTH];
				audit_format_signal_info(usr2, sizeof(usr2),
							 "resume-logging",
							 &cur_event->reply,
							 "success");
					resume_logging();
					libdisp_resume();
					send_audit_event(AUDIT_DAEMON_RESUME,
							 usr2);
					usr2_info_requested = 0;
				}
				break;
			default:
				distribute_event(cur_event);
				cur_event = NULL;
				break;
			}
		}
		cnt++;
	}
}

static void pipe_handler(struct ev_loop *loop, struct ev_io *io,
                        int revents)
{
	char buf[16];

	// Drain the pipe - won't block because libev sets non-blocking mode
	if (read(pipefds[0], buf, sizeof(buf)) < 0)
		; /* Intentionally blank - nothing we can do */
	enqueue_event(reconfig_ev);
	reconfig_ev = NULL;
}

void reconfig_ready(void)
{
	const char *msg = "ready\n";
	if (write(pipefds[1], msg, strlen(msg)) < 0)
		; /* Intentionally empty - nothing we can do */
}

static void close_pipes(void)
{
	close(pipefds[0]);
	close(pipefds[1]);
}

struct ev_loop *loop;
int main(int argc, char *argv[])
{
	struct sigaction sa;
	struct rlimit limit;
	int i, c, rc;
	static const struct option opts[] = {
		{"foreground", no_argument, NULL, 'f'},
		{"allow_links", no_argument, NULL, 'l'},
		{"disable_fork", no_argument, NULL, 'n'},
		{"enable_state", required_argument, NULL, 's'},
		{"config_file", required_argument, NULL, 'c'},
		{NULL, 0, NULL, 0}
	};
	int opt_foreground = 0, opt_allow_links = 0;
	enum startup_state opt_startup = startup_enable;
	extern char *optarg;
	extern int optind;
	struct ev_io netlink_watcher;
	struct ev_io pipe_watcher;
	struct ev_signal sigterm_watcher;
	struct ev_signal sighup_watcher;
	struct ev_signal sigusr1_watcher;
	struct ev_signal sigusr2_watcher;
	struct ev_signal sigchld_watcher;
	struct ev_signal sigcont_watcher;

	/* Get params && set mode */
	while ((c = getopt_long(argc, argv, "flns:c:", opts, NULL)) != -1) {
		switch (c) {
		case 'f':
			opt_foreground = 1;
			break;
		case 'l':
			opt_allow_links = 1;
			break;
		case 'n':
			do_fork = 0;
			break;
		case 's':
			for (i=0; i<startup_INVALID; i++) {
				if (strncmp(optarg, startup_states[i],
					strlen(optarg)) == 0) {
					opt_startup = i;
					break;
				}
			}
			if (i == startup_INVALID) {
				fprintf(stderr, "unknown startup mode '%s'\n",
					optarg);
				usage();
			}
			break;
 		case 'c':
			if (set_config_dir(optarg) != 0) {
				usage();
			}
			config_dir_set = 1;
			break;
		default:
			usage();
		}
	}

	/* check for trailing command line following options */
	if (optind < argc) {
		usage();
	}

	if (opt_allow_links)
		set_allow_links(1);

	if (opt_foreground) {
		config.daemonize = D_FOREGROUND;
		set_aumessage_mode(MSG_STDERR, DBG_YES);
	} else {
		config.daemonize = D_BACKGROUND;
		set_aumessage_mode(MSG_SYSLOG, DBG_NO);
		(void) umask( umask( 077 ) | 022 );
	}
	session = audit_get_session();

#ifndef DEBUG
	/* Make sure we can do our job. Containers may not give you
	 * capabilities, so we revert to a uid check for that case. */
	if (!audit_can_control()) {
		if (!config.local_events && geteuid() == 0)
			;
		else {
			fprintf(stderr,
		"You must be root or have capabilities to run this program.\n");
			return 4;
		}
	}
#endif

	/* Register sighandlers */
	sa.sa_flags = 0 ;
	sigemptyset( &sa.sa_mask ) ;
	/* Ignore all signals by default */
	sa.sa_handler = SIG_IGN;
	for (i=1; i<NSIG; i++)
		sigaction( i, &sa, NULL );

	/* This signal handler gets replaced later. Its here in case
	 * the dispatcher exits before libev is in control */
	sa.sa_handler = child_handler2;
	sigaction(SIGCHLD, &sa, NULL);

	atexit(clean_exit);

	/* Raise the rlimits in case we're being started from a shell
         * with restrictions. Not a fatal error.  */
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_CPU, &limit);

	/* Load the Configuration File */
	if (load_config(&config, TEST_AUDITD)) {
		free_config(&config);
		return 6;
	}
	if (config.daemonize == D_FOREGROUND)
		config.write_logs = 0;

	// This can only be set at start up
	opt_aggregate_only = !config.local_events;

	if (config.priority_boost != 0) {
		errno = 0;
		if (nice((int)-config.priority_boost))
			; /* Intentionally blank, we have to check errno */
		if (errno) {
			audit_msg(LOG_ERR, "Cannot change priority (%s)", 
					strerror(errno));
			free_config(&config);
			return 1;
		}
	} 
	
	/* Daemonize or stay in foreground for debugging */
	if (config.daemonize == D_BACKGROUND) {
		if (become_daemon() != 0) {
			audit_msg(LOG_ERR, "Cannot daemonize (%s)",
				strerror(errno));
			tell_parent(FAILURE);
			free_config(&config);
			return 1;
		} 
		openlog("auditd", LOG_PID, LOG_DAEMON);
	}

	/* Init netlink */
	if ((fd = audit_open()) < 0) {
        	audit_msg(LOG_ERR, "Cannot open netlink audit socket");
		tell_parent(FAILURE);
		free_config(&config);
		return 1;
	}

	/* Init the event handler thread */
	write_pid_file();
	if (init_event(&config)) {
		if (pidfile)
			unlink(pidfile);
		tell_parent(FAILURE);
		free_config(&config);
		return 1;
	}

	/* Startup libev. If we are not aggregating events, use the select
	 * backend which is faster for small numbers of descriptors. This
	 * will fallback to the epoll backend otherwise. */
	{
	int flags = EVFLAG_NOENV;
	if (config.tcp_listen_port == 0)
		flags |= EVBACKEND_SELECT;
	loop = ev_default_loop(flags);
	}

	/* Startup dispatcher */
	if (init_dispatcher(&config)) {
		if (pidfile)
			unlink(pidfile);
		tell_parent(FAILURE);
		free_config(&config);
		ev_default_destroy();
		return 1;
	}

	/* Get machine name ready for use */
	if (resolve_node(&config)) {
		if (pidfile)
			unlink(pidfile);
		shutdown_dispatcher();
		tell_parent(FAILURE);
		free_config(&config);
		ev_default_destroy();
		return 1;
	}

	/* Setup the reconfig notification pipe */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipefds)) {
        	audit_msg(LOG_ERR, "Cannot open reconfig socket");
		if (pidfile)
			unlink(pidfile);
		shutdown_dispatcher();
		tell_parent(FAILURE);
		free_config(&config);
		ev_default_destroy();
		return 1;
	}
	fcntl(pipefds[0], F_SETFD, FD_CLOEXEC);
	fcntl(pipefds[1], F_SETFD, FD_CLOEXEC);

	/* Write message to log that we are alive */
	{
		struct utsname ubuf;
		char start[DEFAULT_BUF_SZ];
		const char *fmt = audit_lookup_format((int)config.log_format);
		if (fmt == NULL)
			fmt = "UNKNOWN";
		if (uname(&ubuf) != 0) {
			if (pidfile)
				unlink(pidfile);
			shutdown_dispatcher();
			tell_parent(FAILURE);
			close_pipes();
			free_config(&config);
			ev_default_destroy();
			return 1;
		}
		if (getsubj(subj))
			snprintf(start, sizeof(start),
				"op=start ver=%s format=%s "
				"kernel=%.56s auid=%u pid=%d "
				"uid=%u ses=%u subj=%s res=success",
				VERSION, fmt, ubuf.release,
				audit_getloginuid(), getpid(),
				getuid(), session,  subj);
		else
			snprintf(start, sizeof(start),
				"op=start ver=%s format=%s "
				"kernel=%.56s auid=%u pid=%d "
				"uid=%u ses=%u res=success",
				VERSION, fmt, ubuf.release,
				audit_getloginuid(), getpid(),
				getuid(), session);
		if (send_audit_event(AUDIT_DAEMON_START, start)) {
        		audit_msg(LOG_ERR, "Cannot send start message");
			if (pidfile)
				unlink(pidfile);
			shutdown_dispatcher();
			tell_parent(FAILURE);
			close_pipes();
			free_config(&config);
			ev_default_destroy();
			return 1;
		}
	}

	/* Tell kernel not to kill us */
	avoid_oom_killer();

	/* let config manager init */
	init_config_manager();

	/* Depending on value of opt_startup (-s) set initial audit state */
	if (opt_startup != startup_nochange && !opt_aggregate_only &&
			(audit_is_enabled(fd) < 2) &&
			audit_set_enabled(fd, (int)opt_startup) < 0) {
		char emsg[DEFAULT_BUF_SZ];
		if (*subj)
			snprintf(emsg, sizeof(emsg),
				"op=set-enable auid=%u pid=%d uid=%u "
				"ses=%u subj=%s res=failed",
				audit_getloginuid(), getpid(), getuid(),
				session, subj);
		else
			snprintf(emsg, sizeof(emsg),
				"op=set-enable auid=%u pid=%d uid=%u "
				"ses=%u res=failed",
				audit_getloginuid(), getpid(),
				getuid(), session);
		stop = 1;
		send_audit_event(AUDIT_DAEMON_ABORT, emsg);
		audit_msg(LOG_ERR,
		"Unable to set initial audit startup state to '%s', exiting",
			startup_states[opt_startup]);
		shutdown_events();
		if (pidfile)
			unlink(pidfile);
		shutdown_dispatcher();
		tell_parent(FAILURE);
		close_pipes();
		free_config(&config);
		ev_default_destroy();
		return 1;
	}

	/* Tell the kernel we are alive */
	if (!opt_aggregate_only && audit_set_pid(fd, getpid(), WAIT_YES) < 0) {
		char emsg[DEFAULT_BUF_SZ];
		if (*subj)
			snprintf(emsg, sizeof(emsg),
				"op=set-pid auid=%u pid=%d uid=%u "
				"ses=%u subj=%s res=failed",
				audit_getloginuid(), getpid(), getuid(),
				session, subj);
		else
			snprintf(emsg, sizeof(emsg),
				"op=set-pid auid=%u pid=%d uid=%u "
				"ses=%u res=failed",
				audit_getloginuid(), getpid(),
				getuid(), session);
		stop = 1;
		send_audit_event(AUDIT_DAEMON_ABORT, emsg);
		audit_msg(LOG_ERR, "Unable to set audit pid, exiting");
		shutdown_events();
		if (pidfile)
			unlink(pidfile);
		shutdown_dispatcher();
		tell_parent(FAILURE);
		close_pipes();
		free_config(&config);
		ev_default_destroy();
		return 1;
	}

	/* Start up all the handlers */
	if (!opt_aggregate_only) {
		ev_io_init (&netlink_watcher, netlink_handler, fd, EV_READ);
		ev_io_start (loop, &netlink_watcher);
	}

	ev_signal_init (&sigterm_watcher, term_handler, SIGTERM);
	ev_signal_start (loop, &sigterm_watcher);

	ev_signal_init (&sighup_watcher, hup_handler, SIGHUP);
	ev_signal_start (loop, &sighup_watcher);

	ev_signal_init (&sigusr1_watcher, user1_handler, SIGUSR1);
	ev_signal_start (loop, &sigusr1_watcher);

	ev_signal_init (&sigusr2_watcher, user2_handler, SIGUSR2);
	ev_signal_start (loop, &sigusr2_watcher);

	ev_signal_init (&sigchld_watcher, child_handler, SIGCHLD);
	ev_signal_start (loop, &sigchld_watcher);

	ev_signal_init (&sigcont_watcher, cont_handler, SIGCONT);
	ev_signal_start (loop, &sigcont_watcher);

	ev_io_init (&pipe_watcher, pipe_handler, pipefds[0], EV_READ);
	ev_io_start (loop, &pipe_watcher);

	if (auditd_tcp_listen_init(loop, &config)) {
		char emsg[DEFAULT_BUF_SZ];
		if (*subj)
			snprintf(emsg, sizeof(emsg),
				"op=network-init auid=%u pid=%d uid=%u "
				"ses=%u subj=%s res=failed",
				audit_getloginuid(), getpid(),
				getuid(), session, subj);
		else
			snprintf(emsg, sizeof(emsg),
				"op=network-init auid=%u pid=%d uid=%u "
				"ses=%u res=failed",
				audit_getloginuid(), getpid(),
				getuid(), session);
		stop = 1;
		send_audit_event(AUDIT_DAEMON_ABORT, emsg);
		tell_parent(FAILURE);
	} else {
		/* Now tell parent that everything went OK */
		tell_parent(SUCCESS);
		audit_msg(LOG_NOTICE,
	    "Init complete, auditd %s listening for events (startup state %s)",
			VERSION,
			startup_states[opt_startup]);
	}

	/* Parent should be gone by now...   */
	if (do_fork)
		close(init_pipe[1]);

	// Init complete, start event loop
	if (!stop)
		ev_loop (loop, 0);

	// Event loop finished, clean up everything
	auditd_tcp_listen_uninit (loop, &config);

	// Tear down IO watchers Part 1
	ev_signal_stop (loop, &sighup_watcher);
	ev_signal_stop (loop, &sigusr1_watcher);
	ev_signal_stop (loop, &sigusr2_watcher);
	ev_signal_stop (loop, &sigterm_watcher);
	ev_signal_stop (loop, &sigcont_watcher);

	/* Write message to log that we are going down */
	rc = audit_request_signal_info(fd);
	if (rc > 0) {
		struct audit_reply trep;

		rc = get_reply(fd, &trep, rc);
		if (rc > 0) {
			char txt[MAX_AUDIT_MESSAGE_LENGTH];
			audit_format_signal_info(txt, sizeof(txt), "terminate",
						 &trep, "success");
			send_audit_event(AUDIT_DAEMON_END, txt);
		} 
	} 
	if (rc <= 0)
		send_audit_event(AUDIT_DAEMON_END, 
		"op=terminate auid=-1 uid=-1 ses=-1 pid=-1 subj=? res=success");
	free(cur_event);

	// Tear down IO watchers Part 2
	if (!opt_aggregate_only)
		ev_io_stop (loop, &netlink_watcher);
	ev_io_stop (loop, &pipe_watcher);
	close_pipes();

	// Give DAEMON_END event a little time to be sent in case
	// of remote logging
	usleep(10000); // 10 milliseconds
	libdisp_shutdown();
	usleep(20000); // 20 milliseconds

	// Tear down IO watchers Part 3
	ev_signal_stop(loop, &sigchld_watcher);

	shutdown_events();
	free_config(&config);
	ev_default_destroy();

	return 0;
}


/*
 * A clean exit means : 
 * 1) we log that we are going down
 * 2) deregister with kernel
 * 3) close the netlink socket
 */
static void clean_exit(void)
{
	audit_msg(LOG_INFO, "The audit daemon is exiting.");
	if (fd >= 0) {
		if (!opt_aggregate_only)
			if (audit_set_pid(fd, 0, WAIT_NO))
				; // intentionally empty
		audit_close(fd);
	}
	if (pidfile)
		unlink(pidfile);
	unlink(state_file);
	closelog();
}

/*
 * This function is used to get the reply for term info.
 * Returns 1 on success & -1 on failure.
 */
static int get_reply(int rfd, struct audit_reply *rep, int seq)
{
        int rc, i;
        int timeout = 30; /* tenths of seconds */

	for (i = 0; i < timeout; i++) {
		struct timeval t;
		fd_set read_mask;

		t.tv_sec  = 0;
		t.tv_usec = 100000; /* .1 second */
		FD_ZERO(&read_mask);
		FD_SET(rfd, &read_mask);
		do {
			rc = select(rfd+1, &read_mask, NULL, NULL, &t);
		} while (rc < 0 && errno == EINTR);
		rc = audit_get_reply(rfd, rep,
			GET_REPLY_NONBLOCKING, 0);
		if (rc > 0) {
			/* Don't make decisions based on wrong packet */
			if (rep->nlh->nlmsg_seq != seq)
				continue;

			/* If its not what we are expecting, keep looping */
			if (rep->type == AUDIT_SIGNAL_INFO)
				return 1;

			/* If we get done or error, break out */
			if (rep->type == NLMSG_DONE || rep->type == NLMSG_ERROR)
				break;
		}
	}
	return -1;
}

// Get the subj label of the daemon
static char *getsubj(char *dsubj)
{
	pid_t pid = getpid();
	char filename[48];
	ssize_t num_read;
	int sfd;

	snprintf(filename, sizeof(filename), "/proc/%u/attr/current", pid);
	sfd = open(filename, O_RDONLY);
	if(sfd == -1) {
		dsubj[0] = 0;
		return NULL;
	}
	do {
		num_read = read(sfd, dsubj, SUBJ_LEN-1);
	} while (num_read < 0 && errno == EINTR);
	close(sfd);
	if(num_read <= 0) {
		dsubj[0] = 0;
		return NULL;
	}
	dsubj[num_read] = '\0';
	return dsubj;
}
