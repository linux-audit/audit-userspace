/* auditd.c -- 
 * Copyright 2004-09,2011,2013 Red Hat Inc., Durham, North Carolina.
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
#include "private.h"

#include "ev.h"

#define EV_STOP() ev_unloop (ev_default_loop (EVFLAG_AUTO), EVUNLOOP_ALL), stop = 1;

#define DEFAULT_BUF_SZ	448
#define DMSG_SIZE (DEFAULT_BUF_SZ + 48) 
#define SUCCESS 0
#define FAILURE 1
#define SUBJ_LEN 4097

/* Global Data */
volatile int stop = 0;

/* Local data */
static int fd = -1;
static struct daemon_conf config;
static const char *pidfile = "/var/run/auditd.pid";
static int init_pipe[2];
static int do_fork = 1;
static struct auditd_reply_list *rep = NULL;
static int hup_info_requested = 0;
static int usr1_info_requested = 0, usr2_info_requested = 0;
static char subj[SUBJ_LEN];

/* Local function prototypes */
int send_audit_event(int type, const char *str);
static void close_down(void);
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
	fprintf(stderr, "Usage: auditd [-f] [-l] [-n] [-s %s|%s|%s]\n",
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
 * Used with sigalrm to force exit
 */
static void thread_killer( int sig )
{
	exit(0);
}

/*
 * Used with sigalrm to force exit
 */
static void hup_handler( struct ev_loop *loop, struct ev_signal *sig, int revents )
{
	int rc;

	rc = audit_request_signal_info(fd);
	if (rc < 0)
		send_audit_event(AUDIT_DAEMON_CONFIG, 
				 "auditd error getting hup info - no change, sending auid=? pid=? subj=? res=failed");
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
				 "auditd error getting usr1 info - no change, sending auid=? pid=? subj=? res=failed");
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
			 "auditd resuming logging, sending auid=? pid=? subj=? res=success");
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

static void distribute_event(struct auditd_reply_list *rep)
{
	int attempt = 0;

	/* Make first attempt to send to plugins */
	if (dispatch_event(&rep->reply, attempt) == 1)
		attempt++; /* Failed sending, retry after writing to disk */

	/* End of Event is for realtime interface - skip local logging of it */
	if (rep->reply.type != AUDIT_EOE) {
		int yield = rep->reply.type <= AUDIT_LAST_DAEMON &&
				rep->reply.type >= AUDIT_FIRST_DAEMON ? 1 : 0;
		/* Write to local disk */
		enqueue_event(rep);
		if (yield) {
			struct timespec ts;
			ts.tv_sec = 0;
			ts.tv_nsec = 2 * 1000 * 1000; // 2 milliseconds
			nanosleep(&ts, NULL); // Let other thread try to log it
		}
	} else
		free(rep);	// This function takes custody of the memory

	// FIXME: This is commented out since it fails to work. The
	// problem is that the logger thread free's the buffer. Probably
	// need a way to flag in the buffer if logger thread should free or
	// move the free to this function.

	/* Last chance to send...maybe the pipe is empty now. */
//	if (attempt) 
//		dispatch_event(&rep->reply, attempt);
}

/*
 * This function is used to send start, stop, and abort messages 
 * to the audit log.
 */
static unsigned seq_num = 0;
int send_audit_event(int type, const char *str)
{
	struct auditd_reply_list *rep;
	struct timeval tv;
	
	if ((rep = malloc(sizeof(*rep))) == NULL) {
		audit_msg(LOG_ERR, "Cannot allocate audit reply");
		return 1;
	}

	rep->reply.type = type;
	rep->reply.message = (char *)malloc(DMSG_SIZE);
	if (rep->reply.message == NULL) {
		free(rep);
		audit_msg(LOG_ERR, "Cannot allocate local event message");
		return 1;
	}
	if (seq_num == 0) {
		srand(time(NULL));
		seq_num = rand()%10000;
	} else
		seq_num++;
	if (gettimeofday(&tv, NULL) == 0) {
		rep->reply.len = snprintf((char *)rep->reply.message,
			DMSG_SIZE, "audit(%lu.%03u:%u): %s", 
			tv.tv_sec, (unsigned)(tv.tv_usec/1000), seq_num, str);
	} else {
		rep->reply.len = snprintf((char *)rep->reply.message,
			DMSG_SIZE, "audit(%lu.%03u:%u): %s", 
			(unsigned long)time(NULL), 0, seq_num, str);
	}
	if (rep->reply.len > DMSG_SIZE)
		rep->reply.len = DMSG_SIZE;

	distribute_event(rep);
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
	int fd, rc;
	pid_t pid;
	int status;

	if (do_fork) {
		if (pipe(init_pipe) || 
				fcntl(init_pipe[0], F_SETFD, FD_CLOEXEC) ||
				fcntl(init_pipe[0], F_SETFD, FD_CLOEXEC))
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
			fd = open("/dev/null", O_RDWR);
			if (fd < 0) {
				audit_msg(LOG_ERR, "Cannot open /dev/null");
				return -1;
			}
			if ((dup2(fd, 0) < 0) || (dup2(fd, 1) < 0) ||
							(dup2(fd, 2) < 0)) {
				audit_msg(LOG_ERR,
				    "Cannot reassign descriptors to /dev/null");
				close(fd);
				return -1;
			}
			close(fd);

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
			break;
		default:
			/* Wait for the child to say its done */
			rc = read(init_pipe[0], &status, sizeof(status));
			if (rc < 0)
				return -1;

			/* Success - die a happy death */
			if (status == SUCCESS)
				_exit(0);
			else
				return -1;
			break;
	}

	return 0;
}

static void tell_parent(int status)
{
	int rc;

	if (config.daemonize != D_BACKGROUND || do_fork == 0)
		return;
	do {
		rc = write(init_pipe[1], &status, sizeof(status));
	} while (rc < 0 && errno == EINTR);
}

static void netlink_handler(struct ev_loop *loop, struct ev_io *io,
			int revents)
{
	if (rep == NULL) { 
		if ((rep = malloc(sizeof(*rep))) == NULL) {
			char emsg[DEFAULT_BUF_SZ];
			if (*subj)
				snprintf(emsg, sizeof(emsg),
			"auditd error halt, auid=%u pid=%d subj=%s res=failed",
					audit_getloginuid(), getpid(), subj);
			else
				snprintf(emsg, sizeof(emsg),
				 "auditd error halt, auid=%u pid=%d res=failed",
					 audit_getloginuid(), getpid());
			EV_STOP ();
			send_audit_event(AUDIT_DAEMON_ABORT, emsg);
			audit_msg(LOG_ERR, 
				  "Cannot allocate audit reply, exiting");
			close_down();
			if (pidfile)
				unlink(pidfile);
			shutdown_dispatcher();
			return;
		}
	}
	if (audit_get_reply(fd, &rep->reply, 
			    GET_REPLY_NONBLOCKING, 0) > 0) {
		switch (rep->reply.type)
		{	/* For now dont process these */
		case NLMSG_NOOP:
		case NLMSG_DONE:
		case NLMSG_ERROR:
		case AUDIT_GET: /* Or these */
		case AUDIT_LIST_RULES:
		case AUDIT_FIRST_DAEMON...AUDIT_LAST_DAEMON:
			break;
		case AUDIT_SIGNAL_INFO:
			if (hup_info_requested) {
				audit_msg(LOG_DEBUG,
				    "HUP detected, starting config manager");
				if (start_config_manager(rep)) {
					send_audit_event(
						AUDIT_DAEMON_CONFIG, 
				  "auditd error getting hup info - no change,"
				  " sending auid=? pid=? subj=? res=failed");
				}
				rep = NULL;
				hup_info_requested = 0;
			} else if (usr1_info_requested) {
				char usr1[MAX_AUDIT_MESSAGE_LENGTH];
				if (rep->reply.len == 24) {
					snprintf(usr1, sizeof(usr1),
					 "auditd sending auid=? pid=? subj=?");
				} else {
					snprintf(usr1, sizeof(usr1),
				 "auditd sending auid=%u pid=%d subj=%s",
						 rep->reply.signal_info->uid, 
						 rep->reply.signal_info->pid,
						 rep->reply.signal_info->ctx);
				}
				send_audit_event(AUDIT_DAEMON_ROTATE, usr1);
				usr1_info_requested = 0;
			} else if (usr2_info_requested) {
				char usr2[MAX_AUDIT_MESSAGE_LENGTH];
				if (rep->reply.len == 24) {
					snprintf(usr2, sizeof(usr2), 
						"auditd resuming logging, "
						"sending auid=? pid=? subj=? "
						"res=success");
				} else {
					snprintf(usr2, sizeof(usr2),
						"auditd resuming logging, "
				  "sending auid=%u pid=%d subj=%s res=success",
						 rep->reply.signal_info->uid, 
						 rep->reply.signal_info->pid,
						 rep->reply.signal_info->ctx);
				}
				resume_logging();
				send_audit_event(AUDIT_DAEMON_RESUME, usr2); 
				usr2_info_requested = 0;
			}
			break;
		default:
			distribute_event(rep);
			rep = NULL;
			break;
		}
	} else {
		if (errno == EFBIG) {
			// FIXME do err action
		}
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	struct rlimit limit;
	int i, c, rc;
	int opt_foreground = 0, opt_allow_links = 0;
	enum startup_state opt_startup = startup_enable;
	extern char *optarg;
	extern int optind;
	struct ev_loop *loop;
	struct ev_io netlink_watcher;
	struct ev_signal sigterm_watcher;
	struct ev_signal sighup_watcher;
	struct ev_signal sigusr1_watcher;
	struct ev_signal sigusr2_watcher;
	struct ev_signal sigchld_watcher;

	/* Get params && set mode */
	while ((c = getopt(argc, argv, "flns:")) != -1) {
		switch (c) {
		case 'f':
			opt_foreground = 1;
			break;
		case 'l':
			opt_allow_links=1;
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

#ifndef DEBUG
	/* Make sure we are root */
	if (getuid() != 0) {
		fprintf(stderr, "You must be root to run this program.\n");
		return 4;
	}
#endif

	/* Register sighandlers */
	sa.sa_flags = 0 ;
	sigemptyset( &sa.sa_mask ) ;
	/* Ignore all signals by default */
	sa.sa_handler = SIG_IGN;
	for (i=1; i<NSIG; i++)
		sigaction( i, &sa, NULL );

	atexit(clean_exit);

	/* Raise the rlimits in case we're being started from a shell
         * with restrictions. Not a fatal error.  */
	limit.rlim_cur = RLIM_INFINITY;
	limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_CPU, &limit);

	/* Load the Configuration File */
	if (load_config(&config, TEST_AUDITD))
		return 6;

	if (config.priority_boost != 0) {
		errno = 0;
		rc = nice((int)-config.priority_boost);
		if (rc == -1 && errno) {
			audit_msg(LOG_ERR, "Cannot change priority (%s)", 
					strerror(errno));
			return 1;
		}
	} 
	
	/* Daemonize or stay in foreground for debugging */
	if (config.daemonize == D_BACKGROUND) {
		if (become_daemon() != 0) {
			audit_msg(LOG_ERR, "Cannot daemonize (%s)",
				strerror(errno));
			tell_parent(FAILURE);
			return 1;
		} 
		openlog("auditd", LOG_PID, LOG_DAEMON);
	}

	/* Init netlink */
	if ((fd = audit_open()) < 0) {
        	audit_msg(LOG_ERR, "Cannot open netlink audit socket");
		tell_parent(FAILURE);
		return 1;
	}

	/* Init the event handler thread */
	write_pid_file();
	if (init_event(&config)) {
		if (pidfile)
			unlink(pidfile);
		tell_parent(FAILURE);
		return 1;
	}

	if (init_dispatcher(&config)) {
		if (pidfile)
			unlink(pidfile);
		tell_parent(FAILURE);
		return 1;
	}

	/* Get machine name ready for use */
	if (resolve_node(&config)) {
		if (pidfile)
			unlink(pidfile);
		tell_parent(FAILURE);
		return 1;
	}

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
			tell_parent(FAILURE);
			return 1;
		}
		if (getsubj(subj))
			snprintf(start, sizeof(start),
				"auditd start, ver=%s format=%s "
			    "kernel=%.56s auid=%u pid=%d subj=%s res=success",
				VERSION, fmt, ubuf.release,
				audit_getloginuid(), getpid(), subj);
		else
			snprintf(start, sizeof(start),
				"auditd start, ver=%s format=%s "
				"kernel=%.56s auid=%u pid=%d res=success",
				VERSION, fmt, ubuf.release,
				audit_getloginuid(), getpid());
		if (send_audit_event(AUDIT_DAEMON_START, start)) {
        		audit_msg(LOG_ERR, "Cannot send start message");
			if (pidfile)
				unlink(pidfile);
			shutdown_dispatcher();
			tell_parent(FAILURE);
			return 1;
		}
	}

	/* Tell kernel not to kill us */
	avoid_oom_killer();

	/* let config manager init */
	init_config_manager();

	if (opt_startup != startup_nochange && (audit_is_enabled(fd) < 2) &&
	    audit_set_enabled(fd, (int)opt_startup) < 0) {
		char emsg[DEFAULT_BUF_SZ];
		if (*subj)
			snprintf(emsg, sizeof(emsg),
			"auditd error halt, auid=%u pid=%d subj=%s res=failed",
				audit_getloginuid(), getpid(), subj);
		else
			snprintf(emsg, sizeof(emsg),
				"auditd error halt, auid=%u pid=%d res=failed",
				audit_getloginuid(), getpid());
		stop = 1;
		send_audit_event(AUDIT_DAEMON_ABORT, emsg);
		audit_msg(LOG_ERR,
		"Unable to set initial audit startup state to '%s', exiting",
			startup_states[opt_startup]);
		close_down();
		if (pidfile)
			unlink(pidfile);
		shutdown_dispatcher();
		tell_parent(FAILURE);
		return 1;
	}

	/* Tell the kernel we are alive */
	if (audit_set_pid(fd, getpid(), WAIT_YES) < 0) {
		char emsg[DEFAULT_BUF_SZ];
		if (*subj)
			snprintf(emsg, sizeof(emsg),
			"auditd error halt, auid=%u pid=%d subj=%s res=failed",
				audit_getloginuid(), getpid(), subj);
		else
			snprintf(emsg, sizeof(emsg),
				"auditd error halt, auid=%u pid=%d res=failed",
				audit_getloginuid(), getpid());
		stop = 1;
		send_audit_event(AUDIT_DAEMON_ABORT, emsg);
		audit_msg(LOG_ERR, "Unable to set audit pid, exiting");
		close_down();
		if (pidfile)
			unlink(pidfile);
		shutdown_dispatcher();
		tell_parent(FAILURE);
		return 1;
	}

	/* Depending on value of opt_startup (-s) set initial audit state */
	loop = ev_default_loop (EVFLAG_NOENV);

	ev_io_init (&netlink_watcher, netlink_handler, fd, EV_READ);
	ev_io_start (loop, &netlink_watcher);

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

	if (auditd_tcp_listen_init (loop, &config)) {
		char emsg[DEFAULT_BUF_SZ];
		if (*subj)
			snprintf(emsg, sizeof(emsg),
			"auditd error halt, auid=%u pid=%d subj=%s res=failed",
				audit_getloginuid(), getpid(), subj);
		else
			snprintf(emsg, sizeof(emsg),
				"auditd error halt, auid=%u pid=%d res=failed",
				audit_getloginuid(), getpid());
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

	auditd_tcp_listen_uninit (loop, &config);

	// Tear down IO watchers Part 1
	ev_signal_stop (loop, &sighup_watcher);
	ev_signal_stop (loop, &sigusr1_watcher);
	ev_signal_stop (loop, &sigusr2_watcher);
	ev_signal_stop (loop, &sigterm_watcher);

	/* Write message to log that we are going down */
	rc = audit_request_signal_info(fd);
	if (rc > 0) {
		struct audit_reply trep;

		rc = get_reply(fd, &trep, rc);
		if (rc > 0) {
			char txt[MAX_AUDIT_MESSAGE_LENGTH];
			snprintf(txt, sizeof(txt),
				"auditd normal halt, sending auid=%u "
				"pid=%d subj=%s res=success",
				 trep.signal_info->uid,
				 trep.signal_info->pid, 
				 trep.signal_info->ctx); 
			send_audit_event(AUDIT_DAEMON_END, txt);
		} 
	} 
	if (rc <= 0)
		send_audit_event(AUDIT_DAEMON_END, 
				"auditd normal halt, sending auid=? "
				"pid=? subj=? res=success");
	free(rep);

	// Tear down IO watchers Part 2
	ev_io_stop (loop, &netlink_watcher);

	// Give DAEMON_END event a little time to be sent in case
	// of remote logging
	usleep(10000); // 10 milliseconds
	shutdown_dispatcher();

	// Tear down IO watchers Part 3
	ev_signal_stop (loop, &sigchld_watcher);

	close_down();
	free_config(&config);
	ev_default_destroy();

	return 0;
}

static void close_down(void)
{
	struct sigaction sa;

	/* We are going down. Give the event thread a chance to shutdown.
	   Just in case it hangs, set a timer to get us out of trouble. */
	sa.sa_flags = 0 ;
	sigemptyset( &sa.sa_mask ) ;
	sa.sa_handler = thread_killer;
	sigaction( SIGALRM, &sa, NULL );
	shutdown_events();
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
		audit_set_pid(fd, 0, WAIT_NO);
		audit_close(fd);
	}
	if (pidfile)
		unlink(pidfile);
	closelog();
}

/*
 * This function is used to get the reply for term info.
 * Returns 1 on success & -1 on failure.
 */
static int get_reply(int fd, struct audit_reply *rep, int seq)
{
        int rc, i;
        int timeout = 30; /* tenths of seconds */

	for (i = 0; i < timeout; i++) {
		struct timeval t;
		fd_set read_mask;

		t.tv_sec  = 0;
		t.tv_usec = 100000; /* .1 second */
		FD_ZERO(&read_mask);
		FD_SET(fd, &read_mask);
		do {
			rc = select(fd+1, &read_mask, NULL, NULL, &t);
		} while (rc < 0 && errno == EINTR);
		rc = audit_get_reply(fd, rep, 
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

//get the subj of the daemon
static char *getsubj(char *subj)
{
	pid_t pid = getpid();
	char filename[48];
	ssize_t num_read;
	int fd;

	snprintf(filename, sizeof(filename), "/proc/%u/attr/current", pid);
	fd = open(filename, O_RDONLY);
	if(fd == -1) {
		subj[0] = 0;
		return NULL;
	}
	do {
		num_read = read(fd, subj, SUBJ_LEN-1);
	} while (num_read < 0 && errno == EINTR);
	close(fd);
	if(num_read <= 0) {
		subj[0] = 0;
		return NULL;
	}
	subj[num_read] = '\0';
	return subj;
}

