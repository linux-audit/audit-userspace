// test-audit-fgets.c
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <auplugin.h>

static void test_simple_line(void)
{
	int fds[2];
	char buf[16];
	assert(pipe(fds) == 0);

	auplugin_fgets_clear();
	// nothing in buffer yet
	assert(auplugin_fgets_more(sizeof(buf)) == 0);
	assert(auplugin_fgets_eof() == 0);

	// feed exactly one line and close
	const char *input = "hello\n";
	assert(write(fds[1], input, strlen(input)));
	close(fds[1]);

	// now we should see a complete line
	assert(auplugin_fgets_more(sizeof(buf)) == 0);
	int len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 6);
	assert(strcmp(buf, "hello\n") == 0);
	assert(auplugin_fgets_more(sizeof(buf)) == 0);
	assert(auplugin_fgets_eof() == 0);

	// next call: see EOF, no data
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(auplugin_fgets_eof() == 1);

	close(fds[0]);
}

static void test_multiple_lines(void)
{
	int fds[2];
	char buf[16];
	assert(pipe(fds) == 0);

	auplugin_fgets_clear();
	const char *input = "one\n two\n";
	assert(write(fds[1], input, strlen(input)));
	close(fds[1]);

	// first line
	int len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 4);
	assert(strcmp(buf, "one\n") == 0);

	// leftover " two\n" → there's a newline pending
	assert(auplugin_fgets_more(sizeof(buf)) == 1);

	// second line
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 5);
	assert(strcmp(buf, " two\n") == 0);

	// now buffer empties, EOF
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(auplugin_fgets_eof() == 1);
	assert(auplugin_fgets_more(sizeof(buf)) == 0);

	close(fds[0]);
}

static void test_partial_line(void)
{
	int fds[2];
	char buf[16];
	assert(pipe(fds) == 0);

	auplugin_fgets_clear();
	const char *input = "partial";  // no '\n'
	assert(write(fds[1], input, strlen(input)));
	close(fds[1]);

	// should hand back "partial" once EOF arrives
	int len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	/* first call buffers the data but doesn't yet see EOF */
	assert(len == 0);
	assert(auplugin_fgets_eof() == 0);

	/* second call returns the partial line and sets EOF */
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == (int)strlen(input));
	assert(memcmp(buf, input, len) == 0);
	assert(auplugin_fgets_eof() == 1);

	/* further calls return 0 once drained */
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 0);
	close(fds[0]);
}

static void test_long_line(void)
{
	int fds[2];
	char buf[10];
	assert(pipe(fds) == 0);

	auplugin_fgets_clear();
	// make a 20-byte 'a' line plus '\n'
	char input[22];
	memset(input, 'a', 20);
	input[20] = '\n';
	input[21] = '\0';
	assert(write(fds[1], input, 21));
	close(fds[1]);

	// 1) first chunk (blen=10 → blen-1=9)
	int len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 9);
	for (int i = 0; i < len; i++) assert(buf[i] == 'a');
	assert(buf[len] == '\0');
	// still have >9 bytes left (and no '\n' within the first 9)
	assert(auplugin_fgets_more(sizeof(buf)) == 1);

	// 2) second chunk: still sees newline in the remainder,
	//    but clamps again to 9
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 9);
	for (int i = 0; i < len; i++) assert(buf[i] == 'a');
	assert(buf[len] == '\0');
	assert(auplugin_fgets_more(sizeof(buf)) == 1);

	// 3) finally the last "aa\n"
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 3);
	assert(buf[0] == 'a' && buf[1] == 'a' && buf[2] == '\n');
	assert(buf[3] == '\0');
	/* we’ve drained the data but haven’t hit EOF yet */
	assert(auplugin_fgets_more(sizeof(buf)) == 0);
	assert(auplugin_fgets_eof() == 0);

	/* one more call to drive the EOF read() == 0 */
	len = auplugin_fgets(buf, sizeof(buf), fds[0]);
	assert(len == 0);
	assert(auplugin_fgets_eof() == 1);

	close(fds[0]);
}

int main(void)
{
	test_simple_line();
	test_multiple_lines();
	test_partial_line();
	test_long_line();
	printf("audit-fgets tests: all passed\n");
	return 0;
}

