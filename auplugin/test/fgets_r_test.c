#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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

int main(void)
{
	test_basic_state();
	printf("audit-fgets_r tests: all passed\n");
	return 0;
}

