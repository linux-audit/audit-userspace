/* test-queue.c -- audit dispatcher queue tests
 * Copyright 2025-26 Red Hat Inc.
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
 */

#include "config.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "queue.h"
#include "common.h"

#ifdef HAVE_ATOMIC
ATOMIC_INT disp_hup = 0;
ATOMIC_INT dropped = 0;
#else
volatile ATOMIC_INT disp_hup = 0;
volatile ATOMIC_INT dropped = 0;
#endif

static event_t *make_event(const char *str)
{
	event_t *e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;
	e->hdr.ver = AUDISP_PROTOCOL_VER;
	e->hdr.hlen = sizeof(struct audit_dispatcher_header);
	e->hdr.type = 0;
	e->hdr.size = strnlen(str, MAX_AUDIT_MESSAGE_LENGTH - 1);
	memcpy(e->data, str, e->hdr.size);
	e->data[e->hdr.size] = '\0';
	return e;
}

static int basic_test(const char *logfile)
{
	FILE *f = fopen(logfile, "r");
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	event_t *e = NULL;
	struct disp_conf conf;
	int rc = 1;

	if (!f) {
		fprintf(stderr, "basic_test: cannot open %s\n", logfile);
		return rc;
	}
	memset(&conf, 0, sizeof(conf));
	conf.overflow_action = O_IGNORE;

	if (init_queue(16)) {
		fprintf(stderr, "basic_test: init_queue failed\n");
		goto out;
	}

	while (fgets(buf, sizeof(buf), f)) {
		size_t len = strlen(buf);
		if (len && buf[len-1] == '\n')
			buf[len-1] = '\0';
		e = make_event(buf);
		if (!e || enqueue(e, &conf)) {
			fprintf(stderr, "basic_test: enqueue failed\n");
			goto out_q;
		}
		e = NULL;
	}

	rewind(f);
	while (fgets(buf, sizeof(buf), f)) {
		size_t len = strlen(buf);
		if (len && buf[len-1] == '\n')
			buf[len-1] = '\0';
		e = dequeue();
		if (!e) {
			fprintf(stderr, "basic_test: queue underflow\n");
			goto out_q;
		}
		if (strcmp(e->data, buf) != 0) {
			fprintf(stderr, "basic_test: data mismatch\n");
			goto out_free;
		}
		free(e);
		e = NULL;
	}
	if (queue_current_depth() != 0) {
		fprintf(stderr, "basic_test: depth not zero\n");
		goto out_q;
	}
	rc = 0;
out_free:
	free(e);
	e = NULL;
out_q:
	destroy_queue();
out:
	fclose(f);
	return rc;
}

static int invalid_depth_test(void)
{
	struct disp_conf conf;
	event_t *e = NULL;
	int rc = 1;

	memset(&conf, 0, sizeof(conf));
	conf.overflow_action = O_IGNORE;

	if (init_queue(0) == 0) {
		fprintf(stderr, "invalid_depth_test: accepted zero depth\n");
		goto out;
	}
	destroy_queue();
	if (init_queue(2)) {
		fprintf(stderr,
			"invalid_depth_test: valid initialization failed\n");
		goto out;
	}

	e = make_event("valid-after-zero");
	if (e == NULL || enqueue(e, &conf)) {
		fprintf(stderr, "invalid_depth_test: enqueue failed\n");
		goto out_q;
	}
	e = dequeue();
	if (e == NULL || strcmp(e->data, "valid-after-zero") != 0) {
		fprintf(stderr, "invalid_depth_test: dequeue failed\n");
		free(e);
		goto out_q;
	}
	free(e);
	rc = 0;
out_q:
	destroy_queue();
out:
	return rc;
}

struct prod_arg {
	const char **lines;
	int count;
	struct disp_conf *conf;
};

struct resize_prod_arg {
	struct disp_conf *conf;
	unsigned int start;
	unsigned int count;
};

struct resize_cons_arg {
	unsigned int start;
	unsigned int count;
	unsigned int resize_after;
	unsigned int resize_size;
	int failed;
};

static void *resize_handshake_producer(void *a)
{
	struct resize_prod_arg *pa = a;
	unsigned int i;

	for (i = 0; i < pa->count; i++) {
		event_t *e;
		char buf[32];

		snprintf(buf, sizeof(buf), "resize-%06u", pa->start + i);
		e = make_event(buf);
		if (!e)
			return NULL;

		while (enqueue(e, pa->conf) == 1) {
			e = make_event(buf);
			if (!e)
				return NULL;
		}
	}

	return NULL;
}

static void *resize_handshake_consumer(void *a)
{
	struct resize_cons_arg *ca = a;
	unsigned int i;

	for (i = 0; i < ca->count; i++) {
		event_t *e;
		char buf[32];

		e = dequeue();
		if (!e) {
			ca->failed = 1;
			return NULL;
		}
		snprintf(buf, sizeof(buf), "resize-%06u", ca->start + i);
		if (strcmp(e->data, buf) != 0) {
			ca->failed = 1;
			free(e);
			return NULL;
		}
		free(e);
		if (i + 1 == ca->resize_after)
			increase_queue_depth(ca->resize_size);
	}

	return NULL;
}

static void *producer(void *a)
{
	struct prod_arg *pa = a;
	for (int i = 0; i < pa->count; i++) {
		event_t *e = make_event(pa->lines[i % pa->count]);
		if (e) {
			if (enqueue(e, pa->conf)) {
#ifdef HAVE_ATOMIC
				atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
#else
				dropped++;
#endif
			}
		}
	}
	return NULL;
}

static int concurrency_test(const char *logfile)
{
	FILE *f = fopen(logfile, "r");
	const char *lines[32];
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	int n = 0;
	struct disp_conf conf;
	pthread_t prod[2];
	int consumed = 0;
	int target;
	int rc = 1;

	if (!f) {
		fprintf(stderr, "concurrency_test: cannot open %s\n", logfile);
		return rc;
	}
	memset(&conf, 0, sizeof(conf));
	conf.overflow_action = O_IGNORE;

	while (n < 32 && fgets(buf, sizeof(buf), f)) {
		size_t len = strlen(buf);
		if (len && buf[len-1] == '\n')
			buf[len-1] = '\0';
		lines[n++] = strdup(buf);
	}
	fclose(f);
	if (init_queue(8)) {
		fprintf(stderr, "concurrency_test: init_queue failed\n");
		goto out_lines;
	}

	struct prod_arg pa = { .lines = lines, .count = n, .conf = &conf };
	target = n;
	pthread_create(&prod[0], NULL, producer, &pa);
	// pthread_create(&prod[1], NULL, producer, &pa);

	struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
	while (consumed < target - dropped) {
		event_t* e = dequeue_timed(&ts);
		if (e) {
			consumed++;
			free(e);
			continue;
		}
	}

	pthread_join(prod[0], NULL);
	// pthread_join(prod[1], NULL);

	int expected = target - dropped;
	if (consumed != expected || queue_current_depth() != 0) {
		fprintf(stderr,
				"concurrency_test: %d consumed, %d expected, %d dropped\n",
				consumed, expected, dropped);
		rc = 1;
	} else {
		rc = 0;
	}
	destroy_queue();
out_lines:
	for (int i = 0; i < n; i++)
		free((void *)lines[i]);
	return rc;
}

static int persist_test(const char *logfile)
{
	char tmp[] = "/tmp/audisp_qXXXXXX";
	struct disp_conf conf;
	FILE *f = fopen(logfile, "r");
	char buf[MAX_AUDIT_MESSAGE_LENGTH];
	struct stat st;
	int fd, rc = 1;

	if (!f) {
		fprintf(stderr, "persist_test: cannot open %s\n", logfile);
		return rc;
	}
	memset(&conf, 0, sizeof(conf));
	conf.overflow_action = O_IGNORE;

	fd = mkstemp(tmp);
	if (fd < 0) {
		fprintf(stderr, "persist_test: mkstemp failed\n");
		goto out_f;
	}
	close(fd);

	if (init_queue_extended(8, Q_IN_FILE | Q_CREAT | Q_SYNC, tmp)) {
		fprintf(stderr, "persist_test: init_queue_extended failed\n");
		goto out_unlink;
	}

	if (!fgets(buf, sizeof(buf), f)) {
		fprintf(stderr, "persist_test: empty logfile\n");
		goto out_q;
	}
	size_t len = strlen(buf);
	if (len && buf[len-1] == '\n')
		buf[len-1] = '\0';
	event_t *e = make_event(buf);
	if (!e || enqueue(e, &conf)) {
		fprintf(stderr, "persist_test: enqueue failed\n");
		goto out_q;
	}
	destroy_queue();

	if (stat(tmp, &st) || st.st_size != (off_t)strlen(buf)) {
		fprintf(stderr, "persist_test: file not persisted\n");
		goto out_unlink;
	}
	rc = 0;
out_q:
	;
out_unlink:
	unlink(tmp);
out_f:
	fclose(f);
	return rc;
}

static int resize_wrap_test(void)
{
	struct disp_conf conf;
	event_t *e = NULL;
	char buf[32];
	int i, rc = 1;

	memset(&conf, 0, sizeof(conf));
	conf.overflow_action = O_IGNORE;

	if (init_queue(100)) {
		fprintf(stderr, "resize_wrap_test: init_queue failed\n");
		return rc;
	}

	/* Fill the ring so the next enqueue sequence can wrap it. */
	for (i = 0; i < 100; i++) {
		snprintf(buf, sizeof(buf), "event-%03d", i);
		e = make_event(buf);
		if (!e || enqueue(e, &conf)) {
			fprintf(stderr, "resize_wrap_test: enqueue failed\n");
			goto out_q;
		}
		e = NULL;
	}

	for (i = 0; i < 80; i++) {
		snprintf(buf, sizeof(buf), "event-%03d", i);
		e = dequeue();
		if (!e) {
			fprintf(stderr, "resize_wrap_test: queue underflow\n");
			goto out_q;
		}
		if (strcmp(e->data, buf) != 0) {
			fprintf(stderr, "resize_wrap_test: initial data mismatch\n");
			goto out_free;
		}
		free(e);
		e = NULL;
	}

	/* Add more entries so the live data spans the end and start. */
	for (i = 100; i < 120; i++) {
		snprintf(buf, sizeof(buf), "event-%03d", i);
		e = make_event(buf);
		if (!e || enqueue(e, &conf)) {
			fprintf(stderr,
				"resize_wrap_test: wrapped enqueue failed\n");
			goto out_q;
		}
		e = NULL;
	}

	/* Growing a wrapped ring must not strand the entries at slot 0. */
	increase_queue_depth(200);

	/* The consumer should still see the wrapped entries in FIFO order. */
	for (i = 80; i < 120; i++) {
		snprintf(buf, sizeof(buf), "event-%03d", i);
		e = dequeue();
		if (!e) {
			fprintf(stderr,
				"resize_wrap_test: queue underflow after resize\n");
			goto out_q;
		}
		if (strcmp(e->data, buf) != 0) {
			fprintf(stderr,
				"resize_wrap_test: data mismatch after resize\n");
			goto out_free;
		}
		free(e);
		e = NULL;
	}

	if (queue_current_depth() != 0) {
		fprintf(stderr, "resize_wrap_test: depth not zero\n");
		goto out_q;
	}

	rc = 0;
out_free:
	free(e);
out_q:
	destroy_queue();
	return rc;
}

static int resize_handshake_test(void)
{
	/*
	 * Verify the real auditd threading model: one producer thread races with
	 * one dispatcher thread that both dequeues and performs the grow. The
	 * producer retries any event dropped while processing_suspended is set,
	 * so every logical event still has to be dequeued exactly once. The old
	 * resize path could lose copied entries or let enqueue() write into the
	 * freed ring array.
	 */
	struct disp_conf conf;
	struct resize_prod_arg pa = { .conf = &conf, .start = 0, .count = 2000 };
	struct resize_cons_arg ca = {
		.start = 0,
		.count = 2000,
		.resize_after = 128,
		.resize_size = 512,
		.failed = 0,
	};
	pthread_t prod;
	pthread_t disp;
	int rc = 1;

	memset(&conf, 0, sizeof(conf));
	conf.overflow_action = O_IGNORE;

	if (init_queue(64)) {
		fprintf(stderr, "resize_handshake_test: init_queue failed\n");
		return rc;
	}

	if (pthread_create(&disp, NULL, resize_handshake_consumer, &ca)) {
		fprintf(stderr,
			"resize_handshake_test: dispatcher thread create failed\n");
		goto out_q;
	}
	if (pthread_create(&prod, NULL, resize_handshake_producer, &pa)) {
		fprintf(stderr,
			"resize_handshake_test: producer thread create failed\n");
		pthread_cancel(disp);
		pthread_join(disp, NULL);
		goto out_q;
	}

	pthread_join(prod, NULL);
	pthread_join(disp, NULL);

	if (ca.failed) {
		fprintf(stderr,
			"resize_handshake_test: consumer observed bad data\n");
		goto out_q;
	}
	if (queue_current_depth() != 0) {
		fprintf(stderr,
			"resize_handshake_test: depth not zero after drain\n");
		goto out_q;
	}

	rc = 0;
out_q:
	destroy_queue();
	return rc;
}

int main(void)
{
	const char *srcdir = getenv("srcdir") ? getenv("srcdir") : ".";
	char path[512];
	snprintf(path, sizeof(path), "%s/../../auparse/test/test3.log", srcdir);

	if (basic_test(path))
		return 1;
	if (invalid_depth_test())
		return 1;
	if (resize_wrap_test())
		return 1;
	if (persist_test(path))
		return 1;
	if (resize_handshake_test())
		return 1;
	if (concurrency_test(path))
		return 1;
	return 0;
}
