#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <auplugin.h>

static void test_basic_state(void)
{
	int fds[2];
	char buf[16];
	char custom[32];
	auplugin_fgets_state_t *st;

	assert(pipe(fds) == 0);

	st = auplugin_fgets_init();
	assert(st);
	assert(auplugin_setvbuf_r(st, custom, sizeof(custom), MEM_SELF_MANAGED) == 0);

	/* no data yet */
	assert(auplugin_fgets_more_r(st, sizeof(buf)) == 0);
	assert(auplugin_fgets_eof_r(st) == 0);

	const char *input = "hi\n";
	assert(write(fds[1], input, strlen(input)));
	close(fds[1]);

	/* read the line */
	int len = auplugin_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 3);
	assert(strcmp(buf, "hi\n") == 0);

	/* EOF on next call */
	len = auplugin_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(auplugin_fgets_eof_r(st) == 1);

	auplugin_fgets_clear_r(st);
	close(fds[0]);
	auplugin_fgets_destroy(st);
}

static void test_deferred_compaction(void)
{
	int fds[2];
	char buf[64];
	char custom[33];
	const char *line =
		"0123456789abcdef0123456789abcdefQRSTUVWX\n";
	auplugin_fgets_state_t *st;
	size_t line_len = strlen(line);
	size_t capacity = sizeof(custom) - 1;

	assert(pipe(fds) == 0);
	st = auplugin_fgets_init();
	assert(st);
	assert(auplugin_setvbuf_r(st, custom, capacity, MEM_SELF_MANAGED) == 0);

	assert(write(fds[1], line, line_len) == (ssize_t)line_len);
	close(fds[1]);

	int len = auplugin_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == (int)capacity);
	assert(strncmp(buf, line, (size_t)len) == 0);
	assert(auplugin_fgets_eof_r(st) == 0);

	len = auplugin_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == (int)(line_len - capacity));
	assert(strcmp(buf, line + capacity) == 0);

	len = auplugin_fgets_r(st, buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(auplugin_fgets_eof_r(st) == 1);

	close(fds[0]);
	auplugin_fgets_destroy(st);
}

static void test_mmap_file(void)
{
	const char *srcdir = getenv("srcdir") ? getenv("srcdir") : ".";
	char path[512];
	int fd;
	auplugin_fgets_state_t *st;
	char buff[256];
	int lines = 0;

	snprintf(path, sizeof(path), "%s/../../auparse/test/test.log", srcdir);
	fd = open(path, O_RDONLY);
	assert(fd >= 0);

	st = auplugin_fgets_init();
	assert(st);

	struct stat sb;
	assert(fstat(fd, &sb) == 0);
	void *base = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (base == MAP_FAILED)
		exit(1);
	assert(auplugin_setvbuf_r(st, base, sb.st_size, MEM_MMAP_FILE) == 0);

	do {
		int res = auplugin_fgets_r(st, buff, sizeof(buff), fd);
		if (res > 0) {
			if (lines == 0)
				assert(strncmp(buff, "type=AVC", 8) == 0);
			lines++;
		}
	} while (!auplugin_fgets_eof_r(st));

	assert(lines == 14);

	auplugin_fgets_destroy(st);
	close(fd);
}

int main(void)
{
	test_basic_state();
	test_deferred_compaction();
	test_mmap_file();
	printf("audit-fgets_r tests: all passed\n");
	return 0;
}

