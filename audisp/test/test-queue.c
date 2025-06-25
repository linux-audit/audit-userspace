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
#else
volatile ATOMIC_INT disp_hup = 0;
#endif

static event_t *make_event(const char *str)
{
	event_t *e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;
	e->hdr.ver = AUDISP_PROTOCOL_VER;
	e->hdr.hlen = sizeof(struct audit_dispatcher_header);
	e->hdr.type = 0;
	e->hdr.size = strlen(str);
	if (e->hdr.size >= MAX_AUDIT_MESSAGE_LENGTH)
		e->hdr.size = MAX_AUDIT_MESSAGE_LENGTH - 1;
	strncpy(e->data, str, e->hdr.size);
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

struct prod_arg {
	const char **lines;
	int count;
	struct disp_conf *conf;
};

static void *producer(void *a)
{
	struct prod_arg *pa = a;
	for (int i = 0; i < pa->count; i++) {
		event_t *e = make_event(pa->lines[i % pa->count]);
		if (e)
			enqueue(e, pa->conf);
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
	target = n * 2;
	pthread_create(&prod[0], NULL, producer, &pa);
	pthread_create(&prod[1], NULL, producer, &pa);

	while (consumed < target) {
		event_t *e = dequeue();
		if (e) {
			consumed++;
			free(e);
		}
	}

	pthread_join(prod[0], NULL);
	pthread_join(prod[1], NULL);

	if (queue_current_depth() != 0) {
		fprintf(stderr, "concurrency_test: depth not zero\n");
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

int main(void)
{
	const char *srcdir = getenv("srcdir") ? getenv("srcdir") : ".";
	char path[512];
	snprintf(path, sizeof(path), "%s/../../auparse/test/test3.log", srcdir);

	if (basic_test(path))
		return 1;
	if (persist_test(path))
		return 1;
	if (concurrency_test(path))
		return 1;
	return 0;
}

