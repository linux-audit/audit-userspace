/* queue.c --
 * Copyright 2007,2013,2015,2018,2022,2025 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "queue.h"
#include "common.h"

/*
 * Audisp uses a simple ring buffer to pass events from auditd to its
 * plugin dispatcher thread.  The goal is to avoid blocking producers
 * and consumers on a mutex.  The semaphore below tracks how many events
 * are queued while the atomic indices maintain the next slot to use for
 * enqueueing and dequeueing.  A mutex is only required when the queue is
 * resized.
 */

static volatile event_t **q;
static pthread_mutex_t queue_lock;
static sem_t queue_nonempty;
/*
 * q_next points to the next free slot for the producer.
 * q_last points to the next item the consumer should read.
 * Both are updated atomically and wrap at q_depth.
 */
#ifdef HAVE_ATOMIC
static atomic_uint q_next, q_last;
extern ATOMIC_INT disp_hup;
#else
static unsigned int q_next, q_last; /* Fallback when atomics are absent */
extern volatile ATOMIC_INT disp_hup;
#endif
static unsigned int q_depth, processing_suspended, overflowed;
static ATOMIC_UNSIGNED currently_used, max_used;
static const char *SINGLE = "1";
static const char *HALT = "0";
static int queue_full_warning = 0;
static int persist_fd = -1;
static int persist_sync = 0;
#define QUEUE_FULL_LIMIT 5

void reset_suspended(void)
{
	processing_suspended = 0;
	queue_full_warning = 0;
}

static int queue_load_file(int fd)
{
	FILE *f;
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	unsigned int count = 0;

	if (fd < 0)
		return -1;

	f = fdopen(dup(fd), "r");
	if (f == NULL)
		return -1;

	while (count < q_depth && fgets(buf, sizeof(buf), f)) {
		event_t *e = calloc(1, sizeof(*e));
		if (e == NULL)
			break;
		strncpy(e->data, buf, MAX_AUDIT_MESSAGE_LENGTH);
		e->data[MAX_AUDIT_MESSAGE_LENGTH-1] = '\0';
		e->hdr.size = strlen(e->data);
		e->hdr.ver = AUDISP_PROTOCOL_VER2;
		q[count] = e;
		sem_post(&queue_nonempty);
		count++;
	}

	#ifdef HAVE_ATOMIC
	atomic_store_explicit(&q_next, count % q_depth, memory_order_relaxed);
	atomic_store_explicit(&q_last, 0, memory_order_relaxed);
	#else
	q_next = count % q_depth;
	q_last = 0;
	#endif
	currently_used = count;
	if (max_used < count)
		max_used = count;

	fclose(f);
	return 0;
}

int init_queue_extended(unsigned int size, int flags, const char *path)
{
	// The global variables are initialized to zero by the
	// compiler. We can sometimes get here by a reconfigure.
	// If the queue was already initialized, q_depth will be
	// non-zero. In that case, leave everything alone. If the
	// queue was destroyed due to lack of plugins, q_depth,
	// as well as other queue variables, is set to zero so
	// they do not need reinitializing.
	if (q_depth == 0) {
		unsigned int i;

		q_depth = size;
		q = malloc(q_depth * sizeof(event_t *));
		if (q == NULL) {
			processing_suspended = 1;
			return -1;
		}

		for (i=0; i < q_depth; i++)
			q[i] = NULL;

		/* Setup IPC mechanisms */
		pthread_mutex_init(&queue_lock, NULL);
		sem_init(&queue_nonempty, 0, 0);
#ifdef HAVE_ATOMIC
		atomic_init(&q_next, 0);
		atomic_init(&q_last, 0);
#else
		q_next = 0;
		q_last = 0;
#endif
		reset_suspended();
	}
	if (flags & Q_IN_FILE) {
		int oflag = O_RDWR | O_APPEND;
		if (flags & Q_CREAT)
			oflag |= O_CREAT;
		if (flags & Q_EXCL)
			oflag |= O_EXCL;
		persist_fd = open(path, oflag, 0600);
		if (persist_fd < 0)
			return -1;
		persist_sync = (flags & Q_SYNC) ? 1 : 0;
		queue_load_file(persist_fd);
	}
	return 0;
}

int init_queue(unsigned int size)
{
	return init_queue_extended(size, Q_IN_MEMORY, NULL);
}

static void change_runlevel(const char *level)
{
	char *argv[3];
	int pid;
	static const char *init_pgm = "/sbin/init";

	// In case of halt, we need to log the message before we halt
	if (strcmp(level, HALT) == 0) {
		write_to_console("audit: will try to change runlevel to %s\n", level);
	}

	pid = fork();
	if (pid < 0) {
		syslog(LOG_ALERT, "Audispd failed to fork switching runlevels");
		return;
	}

	if (pid) { /* Parent */
		int status;

		// Wait until child exits
		if (waitpid(pid, &status, 0) < 0) {
			return;
		}

		// Check if child exited normally, runlevel change was successful
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			write_to_console("audit: changed runlevel to %s\n", level);
		}

		return;
	}

	/* Child */
	argv[0] = (char *)init_pgm;
	argv[1] = (char *)level;
	argv[2] = NULL;
	execve(init_pgm, argv, NULL);
	syslog(LOG_ALERT, "Audispd failed to exec %s", init_pgm);
	exit(1);
}

static int do_overflow_action(struct disp_conf *config)
{
	int rc = -1;
	overflowed = 1;
        switch (config->overflow_action)
        {
                case O_IGNORE:
			rc = 0;
			break;
                case O_SYSLOG:
			if (queue_full_warning < QUEUE_FULL_LIMIT) {
				syslog(LOG_ERR,
				  "queue to plugins is full - dropping event");
				queue_full_warning++;
				if (queue_full_warning == QUEUE_FULL_LIMIT)
					syslog(LOG_ERR,
						"auditd queue full reporting "
						"limit reached - ending "
						"dropped event notifications");
			}
                        break;
                case O_SUSPEND:
                        syslog(LOG_ALERT,
                            "Auditd is suspending event passing to plugins due to overflowing its queue.");
                        processing_suspended = 1;
                        break;
                case O_SINGLE:
                        syslog(LOG_ALERT,
                                "Auditd is now changing the system to single user mode due to overflowing its queue");
                        change_runlevel(SINGLE);
                        break;
                case O_HALT:
                        syslog(LOG_ALERT,
                                "Auditd is now halting the system due to overflowing its queue");
                        change_runlevel(HALT);
                        break;
                default:
                        syslog(LOG_ALERT, "Unknown overflow action requested");
                        break;
        }
	return rc;
}

/* returns 0 on success and -1 on error */
int enqueue(event_t *e, struct disp_conf *config)
{
	unsigned int n, retry_cnt = 0;

	if (processing_suspended) {
		free(e);
		return 0;
	}

retry:
	/* We allow 3 retries and then its over */
	if (retry_cnt > 3) {
		free(e);
		return do_overflow_action(config);
	}

#ifdef HAVE_ATOMIC
	/*
	* Load the producer index with relaxed ordering.  sem_post() acts
	* as a release barrier and sem_wait() in dequeue() provides the
	* matching acquire barrier.  Because the threads synchronize on
	* the semaphore, a relaxed load of q_next is sufficient here.
	*/
	n = atomic_load_explicit(&q_next, memory_order_relaxed) % q_depth;
#else
	n = q_next % q_depth;
#endif
	if (q[n] == NULL) {
		q[n] = e;
#ifdef HAVE_ATOMIC
		/*
		* Store the updated producer index with release semantics.
		* The event was written to q[n] above and sem_post() will be
		* issued next.  sem_post() itself is a release barrier and
		* sem_wait() in dequeue() will acquire it, so the combination
		* guarantees the consumer sees the event before noticing that
		* q_next advanced.
		*/
		atomic_store_explicit(&q_next, (n+1) % q_depth,
			memory_order_release);
#else
		q_next = (n+1) % q_depth;
#endif
		currently_used++;
		if (currently_used > max_used)
			max_used = currently_used;
		if (persist_fd >= 0) {
			if (write(persist_fd, e->data, e->hdr.size) < 0) {
				/* Log error but continue - persistence is not critical */
				syslog(LOG_WARNING, "Failed to write event to persistent queue");
			}
			if (persist_sync)
				fdatasync(persist_fd);
		}
		sem_post(&queue_nonempty);
	} else {
		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = 2 * 1000 * 1000; /* 2 milliseconds */
		nanosleep(&ts, NULL); /* Let other thread try to log it. */
		retry_cnt++;
		goto retry;
	}
	return 0;
}

/* Common dequeue logic after semaphore wait */
static event_t *dequeue_common(void)
{
	event_t *e;
	unsigned int n;

	if (AUDIT_ATOMIC_LOAD(disp_hup))
		return NULL;

#ifdef HAVE_ATOMIC
	/*
	* The consumer waits on sem_wait() above which provides an acquire
	* barrier for the producer's sem_post().  Because of that
	* synchronization a relaxed load of the consumer index is safe here.
	*/
	n = atomic_load_explicit(&q_last, memory_order_relaxed) % q_depth;
#else
	n = q_last % q_depth;
#endif

	if (q[n] != NULL) {
		e = (event_t *)q[n];
		q[n] = NULL;
#ifdef HAVE_ATOMIC
		/*
		* Release ensures the slot is cleared before we advance the
		* consumer index.  The following sem_post() pairs with the
		* producer's sem_wait(), so the semaphore again provides the
		* cross-thread ordering needed for the queue operations.
		*/
		atomic_store_explicit(&q_last, (n+1) % q_depth,
			memory_order_release);
#else
		q_last = (n+1) % q_depth;
#endif
		currently_used--;
	} else
		e = NULL;

	return e;
}

event_t *dequeue(void)
{
	/* Wait until there is something in the queue */
	while (sem_wait(&queue_nonempty) == -1 && errno == EINTR)
		;

	return dequeue_common();
}

event_t *dequeue_timed(const struct timespec *timeout)
{
	int result;

	/* Wait until there is something in the queue */
	while ((result = sem_timedwait(&queue_nonempty, timeout)) == -1 && errno == EINTR)
		;

	if (result == -1)
		return NULL;

	return dequeue_common();
}

void nudge_queue(void)
{
	sem_post(&queue_nonempty);
}

void increase_queue_depth(unsigned int size)
{
	pthread_mutex_lock(&queue_lock);
	if (size > q_depth) {
		unsigned int i;
		void *tmp_q;

		tmp_q = realloc(q, size * sizeof(event_t *));
		if (tmp_q == NULL) {
			fprintf(stderr, "Out of Memory. Check %s file, %d line",
				__FILE__, __LINE__);
			pthread_mutex_unlock(&queue_lock);
			return;
		}
		q = tmp_q;
		for (i=q_depth; i<size; i++)
			q[i] = NULL;
		q_depth = size;
		overflowed = 0;
	}
	pthread_mutex_unlock(&queue_lock);
}

void write_queue_state(FILE *f)
{
	fprintf(f, "current plugin queue depth = %u\n", currently_used);
	fprintf(f, "max plugin queue depth used = %u\n", max_used);
	fprintf(f, "plugin queue size = %u\n", q_depth);
	fprintf(f, "plugin queue overflow detected = %s\n",
				overflowed ? "yes" : "no");
	fprintf(f, "plugin queueing suspended = %s\n",
				processing_suspended ? "yes" : "no");
}

void resume_queue(void)
{
	processing_suspended = 0;
}

void destroy_queue(void)
{
	unsigned int i;

	for (i=0; i<q_depth; i++)
		free((void *)q[i]);

	free(q);
	pthread_mutex_destroy(&queue_lock);
	sem_destroy(&queue_nonempty);
	if (persist_fd >= 0) {
		if (currently_used == 0) {
			if (ftruncate(persist_fd, 0) < 0) {
				/* Log error but continue - cleanup is not critical */
				syslog(LOG_WARNING, "Failed to truncate persistent queue file");
			}
		}
		close(persist_fd);
		persist_fd = -1;
	}
#ifdef HAVE_ATOMIC
	/*
	* Queue teardown is single threaded and no longer interacts with the
	* semaphore.  A relaxed store is therefore sufficient when resetting
	* the indices.
	*/
	atomic_store_explicit(&q_next, 0, memory_order_relaxed);
	atomic_store_explicit(&q_last, 0, memory_order_relaxed);
#else
	q_next = 0;
	q_last = 0;
#endif
	q_depth = 0;
	processing_suspended = 1;
	currently_used = 0;
	max_used = 0;
	overflowed = 0;
}

unsigned int queue_current_depth(void)
{
       return currently_used;
}

unsigned int queue_max_depth(void)
{
       return max_used;
}

int queue_overflowed_p(void)
{
       return overflowed;
}

