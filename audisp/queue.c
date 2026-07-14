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
#include <sched.h>
#include "queue.h"
#include "common.h"

/*
 * Audisp uses a single-producer / single-consumer ring buffer to pass events
 * from the auditd main thread to the audisp dispatcher thread. The producer is
 * enqueue(), which runs on the same libev thread that handles SIGHUP and sets
 * need_queue_depth_change. Note that the libev thread multiplexes the netlink
 * and network originating events. The consumer is dequeue(), which runs on
 * the dispatcher thread; that same dispatcher thread is also the only thread
 * that calls increase_queue_depth(). The transient config-loading thread never
 * touches the queue.
 *
 * The queue's normal producer/consumer synchronization is driven by the
 * semaphore below. enqueue() stores the event in the ring and then posts the
 * semaphore; dequeue() waits on that semaphore before reading the next entry.
 * Because only one thread advances q_next and only one thread advances q_last,
 * the indices need only atomic load/store operations in the steady state.
 *
 * A resize needs additional synchronization because the resizer must copy the
 * live entries out of the old array and then free that array while enqueue()
 * may be trying to publish another event. The semaphore does not help there:
 * it orders producer vs. consumer visibility of queued events, but it does not
 * prevent the producer from writing into the old ring while the dispatcher is
 * copying or freeing it.
 *
 * To make the grow path race-free, enqueue() and increase_queue_depth() use a
 * two-flag handshake. enqueue() first stores enqueue_in_progress = 1 and then
 * loads processing_suspended. increase_queue_depth() first stores
 * processing_suspended = 1 and then loads enqueue_in_progress until it sees 0.
 * Under HAVE_ATOMIC both operations use memory_order_seq_cst so the C11 memory
 * model gives them one total order. That total order rules out the bad case
 * where enqueue() misses processing_suspended while increase_queue_depth()
 * simultaneously misses enqueue_in_progress: at least one side must observe the
 * other side's store and back off. Once the resizer sees
 * enqueue_in_progress == 0 after publishing processing_suspended == 1, no
 * producer is still writing into the old array, so the copy and free are safe.
 *
 * The spin in increase_queue_depth() is bounded. enqueue_in_progress only spans
 * the tiny critical section that stores an event pointer, advances q_next,
 * updates accounting, optionally mirrors the event to the persistence file, and
 * posts the semaphore. It does not include any allocation or retry loop, so in
 * practice the dispatcher spins for at most a few instructions or a brief
 * sched_yield().
 *
 * The old queue_lock mutex was removed because it never serialized the real
 * producer/resizer race. There is only one resizer, since the dispatcher thread
 * alone calls increase_queue_depth(), and higher-level reconfiguration already
 * ensures only one config thread runs at a time via config_lock. A separate
 * resize mutex therefore provided no useful protection.
 */

static volatile event_t **q;
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
static ATOMIC_UNSIGNED q_depth, overflowed;
static ATOMIC_UNSIGNED processing_suspended;
static ATOMIC_UNSIGNED enqueue_in_progress;
static ATOMIC_UNSIGNED currently_used, max_used;
static ATOMIC_UNSIGNED queue_initialized;
static int queue_full_warning = 0;
static int persist_fd = -1;
static int persist_sync = 0;
#define QUEUE_FULL_LIMIT 5

void reset_suspended(void)
{
	AUDIT_ATOMIC_STORE(processing_suspended, 0);
	queue_full_warning = 0;
}

/*
 * Increment the queue depth counter and preserve the largest value seen.
 * The max update is best-effort and uses compare-exchange to avoid losing
 * concurrent updates from the producer and consumer threads.
 */
static unsigned int increase_used_count(void)
{
	unsigned int used;
	unsigned int max;

#ifdef HAVE_ATOMIC
	used = atomic_fetch_add_explicit(&currently_used, 1,
			memory_order_relaxed) + 1;
	max = atomic_load_explicit(&max_used, memory_order_relaxed);
	while (used > max &&
	       !atomic_compare_exchange_weak_explicit(&max_used, &max, used,
			memory_order_relaxed, memory_order_relaxed))
		;
#else
	used = ++currently_used;
	if (used > max_used)
		max_used = used;
#endif
	return used;
}

/*
 * Decrement the queue depth counter after the consumer removes an event.
 */
static void decrease_used_count(void)
{
#ifdef HAVE_ATOMIC
	atomic_fetch_sub_explicit(&currently_used, 1, memory_order_relaxed);
#else
	currently_used--;
#endif
}

static int queue_load_file(int fd)
{
	FILE *f;
	int dup_fd;
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	unsigned int count = 0;

	if (fd < 0)
		return -1;

	if (AUDIT_ATOMIC_LOAD(q_depth) == 0) {
		syslog(LOG_ERR, "Queue depth is zero, cannot restore queue");
		return -1;
	}
	dup_fd = dup(fd);
	if (dup_fd < 0)
		return -1;
	f = fdopen(dup_fd, "r");
	if (f == NULL) {
		close(dup_fd);
		return -1;
	}

	while (count < AUDIT_ATOMIC_LOAD(q_depth) &&
	       fgets(buf, sizeof(buf), f)) {
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
	atomic_store_explicit(&q_next,
		count % AUDIT_ATOMIC_LOAD(q_depth), memory_order_relaxed);
	atomic_store_explicit(&q_last, 0, memory_order_relaxed);
	#else
	q_next = count % AUDIT_ATOMIC_LOAD(q_depth);
	q_last = 0;
	#endif
	AUDIT_ATOMIC_STORE(currently_used, count);
	AUDIT_ATOMIC_STORE(max_used, count);

	fclose(f);
	return 0;
}

int init_queue_extended(unsigned int size, int flags, const char *path)
{
	int new_queue = 0;

	if (size == 0) {
		errno = EINVAL;
		return -1;
	}

	// The global variables are initialized to zero by the
	// compiler. We can sometimes get here by a reconfigure.
	// If the queue was already initialized, leave everything alone.
	// If the queue was destroyed due to lack of plugins, its state
	// has been reset and the IPC objects need reinitializing.
	if (!AUDIT_ATOMIC_LOAD(queue_initialized)) {
		volatile event_t **new_q;

		new_q = calloc(size, sizeof(event_t *));
		if (new_q == NULL)
			return -1;

		/* Setup IPC mechanisms before publishing the ring. */
		if (sem_init(&queue_nonempty, 0, 0) != 0) {
			free((void *)new_q);
			return -1;
		}
#ifdef HAVE_ATOMIC
		atomic_init(&q_next, 0);
		atomic_init(&q_last, 0);
		atomic_init(&enqueue_in_progress, 0);
#else
		q_next = 0;
		q_last = 0;
		enqueue_in_progress = 0;
#endif
		q = new_q;
		AUDIT_ATOMIC_STORE(q_depth, size);
		AUDIT_ATOMIC_STORE(queue_initialized, 1);
		new_queue = 1;
		reset_suspended();
	}
	if (flags & Q_IN_FILE) {
		int oflag = O_RDWR | O_APPEND;
		if (flags & Q_CREAT)
			oflag |= O_CREAT;
		if (flags & Q_EXCL)
			oflag |= O_EXCL;
		persist_fd = open(path, oflag, 0600);
		if (persist_fd < 0) {
			if (new_queue)
				destroy_queue();
			return -1;
		}
		persist_sync = (flags & Q_SYNC) ? 1 : 0;
		if (queue_load_file(persist_fd) != 0) {
			close(persist_fd);
			persist_fd = -1;
			if (new_queue)
				destroy_queue();
			return -1;
		}
	}
	return 0;
}

int init_queue(unsigned int size)
{
	return init_queue_extended(size, Q_IN_MEMORY, NULL);
}

static int do_overflow_action(struct disp_conf *config)
{
	int rc = -1;
	AUDIT_ATOMIC_STORE(overflowed, 1);
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
                        AUDIT_ATOMIC_STORE(processing_suspended, 1);
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

/*
 * returns 0 on success,
 * 1 if the event could not be queued due to overflow or
 * when processing is suspended, and
 * -1 on other errors
 */
int enqueue(event_t *e, struct disp_conf *config)
{
	unsigned int n, retry_cnt = 0;

	if (!AUDIT_ATOMIC_LOAD(queue_initialized)) {
		free(e);
		errno = ESHUTDOWN;
		return -1;
	}

	/*
	 * First half of the producer/resizer handshake: publish that enqueue()
	 * is entering the ring-buffer write path before reading
	 * processing_suspended. The seq_cst store/load pair is required so the
	 * resizer cannot miss this store after making its own seq_cst store.
	 */
#ifdef HAVE_ATOMIC
	atomic_store_explicit(&enqueue_in_progress, 1, memory_order_seq_cst);
	/*
	 * If the resizer has already suspended processing, abort before touching
	 * the ring. Clearing enqueue_in_progress on this path tells the resizer
	 * that this enqueue() did not write into the old array, so dropping the
	 * event through the normal overflow/suspend path is safe.
	 */
	if (atomic_load_explicit(&processing_suspended, memory_order_seq_cst)) {
		atomic_store_explicit(&enqueue_in_progress, 0,
			memory_order_seq_cst);
		free(e);
		return 1;
	}
#else
	enqueue_in_progress = 1;
	if (processing_suspended) {
		enqueue_in_progress = 0;
		free(e);
		return 1;
	}
#endif

retry:
	/* We allow 3 retries and then its over */
	if (retry_cnt > 3) {
#ifdef HAVE_ATOMIC
		atomic_store_explicit(&enqueue_in_progress, 0,
			memory_order_seq_cst);
#else
		enqueue_in_progress = 0;
#endif
		free(e);
		do_overflow_action(config);
		return 1;
	}

#ifdef HAVE_ATOMIC
	/*
	* Load the producer index with relaxed ordering.  sem_post() acts
	* as a release barrier and sem_wait() in dequeue() provides the
	* matching acquire barrier.  Because the threads synchronize on
	* the semaphore, a relaxed load of q_next is sufficient here.
	*/
	n = atomic_load_explicit(&q_next, memory_order_relaxed) %
		AUDIT_ATOMIC_LOAD(q_depth);
#else
	n = q_next % AUDIT_ATOMIC_LOAD(q_depth);
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
		atomic_store_explicit(&q_next,
			(n+1) % AUDIT_ATOMIC_LOAD(q_depth),
			memory_order_release);
#else
		q_next = (n+1) % AUDIT_ATOMIC_LOAD(q_depth);
#endif
		increase_used_count();
		if (persist_fd >= 0) {
			if (write(persist_fd, e->data, e->hdr.size) < 0) {
				/* Log error but continue - persistence is not critical */
				syslog(LOG_WARNING,
					"Failed to write event to persistent queue");
			}
			if (persist_sync)
				fdatasync(persist_fd);
		}
		sem_post(&queue_nonempty);
#ifdef HAVE_ATOMIC
		/*
		 * The ring-buffer write is now complete. If increase_queue_depth()
		 * was spinning on enqueue_in_progress, this seq_cst clear lets it
		 * proceed knowing the old array is no longer being written.
		 */
		atomic_store_explicit(&enqueue_in_progress, 0,
			memory_order_seq_cst);
#else
		enqueue_in_progress = 0;
#endif
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

	if (!AUDIT_ATOMIC_LOAD(queue_initialized) ||
	    AUDIT_ATOMIC_LOAD(disp_hup))
		return NULL;

#ifdef HAVE_ATOMIC
	/*
	* The consumer waits on sem_wait() above which provides an acquire
	* barrier for the producer's sem_post().  Because of that
	* synchronization a relaxed load of the consumer index is safe here.
	*/
	n = atomic_load_explicit(&q_last, memory_order_relaxed) %
		AUDIT_ATOMIC_LOAD(q_depth);
#else
	n = q_last % AUDIT_ATOMIC_LOAD(q_depth);
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
		atomic_store_explicit(&q_last,
			(n+1) % AUDIT_ATOMIC_LOAD(q_depth),
			memory_order_release);
#else
		q_last = (n+1) % AUDIT_ATOMIC_LOAD(q_depth);
#endif
		decrease_used_count();
	} else
		e = NULL;

	return e;
}

event_t *dequeue(void)
{
	if (!AUDIT_ATOMIC_LOAD(queue_initialized))
		return NULL;

	/* Wait until there is something in the queue */
	while (sem_wait(&queue_nonempty) == -1 && errno == EINTR)
		;

	return dequeue_common();
}

event_t *dequeue_timed(const struct timespec *timeout)
{
	int result;

	if (!AUDIT_ATOMIC_LOAD(queue_initialized))
		return NULL;

	/* Wait until there is something in the queue */
	while ((result = sem_timedwait(&queue_nonempty, timeout)) == -1 &&
	       errno == EINTR)
		;

	if (result == -1)
		return NULL;

	return dequeue_common();
}

void nudge_queue(void)
{
	if (AUDIT_ATOMIC_LOAD(queue_initialized))
		sem_post(&queue_nonempty);
}

void increase_queue_depth(unsigned int size)
{
	if (AUDIT_ATOMIC_LOAD(queue_initialized) &&
	    size > AUDIT_ATOMIC_LOAD(q_depth)) {
		volatile event_t **tmp_q;
		unsigned int count, i, old_depth, old_last;

#ifdef HAVE_ATOMIC
		/*
		 * First half of the resizer/producers handshake: publish that the
		 * queue is suspended before checking enqueue_in_progress. seq_cst
		 * makes this store visible in the same total order as enqueue()'s
		 * seq_cst load, so one side must observe the other's store.
		 */
		atomic_store_explicit(&processing_suspended, 1,
			memory_order_seq_cst);
		/*
		 * Once this spin sees enqueue_in_progress == 0 after suspending the
		 * queue, no producer is mid-write into the old ring allocation.
		 * That invariant makes the copy, free, and pointer swap below safe.
		 */
		while (atomic_load_explicit(&enqueue_in_progress,
			memory_order_seq_cst))
			sched_yield();
#else
		processing_suspended = 1;
		while (enqueue_in_progress)
			sched_yield();
#endif
		old_depth = AUDIT_ATOMIC_LOAD(q_depth);
		count = AUDIT_ATOMIC_LOAD(currently_used);
#ifdef HAVE_ATOMIC
		old_last = atomic_load_explicit(&q_last,
				memory_order_relaxed) % old_depth;
#else
		old_last = q_last % old_depth;
#endif

		tmp_q = calloc(size, sizeof(event_t *));
		if (tmp_q == NULL) {
			fprintf(stderr, "Out of Memory. Check %s file, %d line",
				__FILE__, __LINE__);
#ifdef HAVE_ATOMIC
			atomic_store_explicit(&processing_suspended, 0,
				memory_order_seq_cst);
#else
			processing_suspended = 0;
#endif
			return;
		}

		/*
		 * Preserve FIFO order across a grow. Once the ring has wrapped,
		 * simply extending the backing array strands the entries stored
		 * at the start of the old allocation.
		 */
		for (i = 0; i < count; i++)
			tmp_q[i] = q[(old_last + i) % old_depth];

		/*
		 * The handshake guarantees no thread still holds a writable path into
		 * the old ring array, so freeing it here cannot race with enqueue().
		 */
		free((void *)q);
		q = tmp_q;
		AUDIT_ATOMIC_STORE(q_depth, size);
#ifdef HAVE_ATOMIC
		atomic_store_explicit(&q_last, 0, memory_order_relaxed);
		atomic_store_explicit(&q_next, count, memory_order_relaxed);
#else
		q_last = 0;
		q_next = count;
#endif
		AUDIT_ATOMIC_STORE(overflowed, 0);
#ifdef HAVE_ATOMIC
		/*
		 * Re-open the queue after publishing the new array pointer and depth.
		 * New enqueue() calls that pass the handshake will now observe the
		 * resized ring buffer state.
		 */
		atomic_store_explicit(&processing_suspended, 0,
			memory_order_seq_cst);
#else
		processing_suspended = 0;
#endif
	}
}

void write_queue_state(FILE *f)
{
	fprintf(f, "current plugin queue depth = %u\n",
		AUDIT_ATOMIC_LOAD(currently_used));
	fprintf(f, "max plugin queue depth used = %u\n",
		AUDIT_ATOMIC_LOAD(max_used));
	fprintf(f, "plugin queue size = %u\n", AUDIT_ATOMIC_LOAD(q_depth));
	fprintf(f, "plugin queue overflow detected = %s\n",
				AUDIT_ATOMIC_LOAD(overflowed) ? "yes" : "no");
	fprintf(f, "plugin queueing suspended = %s\n",
				AUDIT_ATOMIC_LOAD(processing_suspended) ?
				"yes" : "no");
}

void resume_queue(void)
{
	AUDIT_ATOMIC_STORE(processing_suspended, 0);
}

void destroy_queue(void)
{
	unsigned int i;

	if (!AUDIT_ATOMIC_LOAD(queue_initialized))
		return;

	for (i=0; i<AUDIT_ATOMIC_LOAD(q_depth); i++)
		free((void *)q[i]);

	free(q);
	q = NULL;
	sem_destroy(&queue_nonempty);
	if (persist_fd >= 0) {
		if (AUDIT_ATOMIC_LOAD(currently_used) == 0) {
			if (ftruncate(persist_fd, 0) < 0) {
				/* Log error but continue - cleanup is not critical */
				syslog(LOG_WARNING,
					"Failed to truncate persistent queue file");
			}
		}
		close(persist_fd);
		persist_fd = -1;
	}
	persist_sync = 0;
#ifdef HAVE_ATOMIC
	/*
	* Queue teardown is single threaded and no longer interacts with the
	* semaphore.  A relaxed store is therefore sufficient when resetting
	* the indices.
	*/
	atomic_store_explicit(&q_next, 0, memory_order_relaxed);
	atomic_store_explicit(&q_last, 0, memory_order_relaxed);
	atomic_store_explicit(&enqueue_in_progress, 0, memory_order_relaxed);
#else
	q_next = 0;
	q_last = 0;
	enqueue_in_progress = 0;
#endif
	AUDIT_ATOMIC_STORE(q_depth, 0);
	AUDIT_ATOMIC_STORE(processing_suspended, 1);
	AUDIT_ATOMIC_STORE(currently_used, 0);
	AUDIT_ATOMIC_STORE(max_used, 0);
	AUDIT_ATOMIC_STORE(overflowed, 0);
	AUDIT_ATOMIC_STORE(queue_initialized, 0);
}

unsigned int queue_current_depth(void)
{
	return AUDIT_ATOMIC_LOAD(currently_used);
}

unsigned int queue_max_depth(void)
{
	return AUDIT_ATOMIC_LOAD(max_used);
}

int queue_overflowed_p(void)
{
	return AUDIT_ATOMIC_LOAD(overflowed);
}
