#include "config.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "ausearch-checkpt.h"

/* test_checkpoint_event_type - round-trip a checkpoint event type
 * @void: no input
 *
 * Return: none. Failures abort through assert().
 */
static void test_checkpoint_event_type(void)
{
	const event original = {
		.sec = 1700000000,
		.milli = 123,
		.serial = 456,
		.node = "checkpoint-node",
		.type = INT_MAX,
	};
	char path[] = "/tmp/ausearch-checkpt-test.XXXXXX";
	char line[128];
	struct stat sbuf;
	FILE *file;
	int fd;
	int saw_output = 0;

	fd = mkstemp(path);
	assert(fd >= 0);
	assert(close(fd) == 0);
	assert(stat(path, &sbuf) == 0);
	assert(set_ChkPtFileDetails(path) == 0);
	assert(set_ChkPtLastEvent(&original) == 0);
	save_ChkPt(path);
	assert(checkpt_failure == 0);

	file = fopen(path, "r");
	assert(file != NULL);
	while (fgets(line, sizeof(line), file)) {
		if (strncmp(line, "output=", 7) == 0) {
			assert(strcmp(line,
				"output=checkpoint-node 1700000000.123:456 "
				"0x7FFFFFFF\n") == 0);
			saw_output = 1;
		}
	}
	assert(fclose(file) == 0);
	assert(saw_output);

	free_ChkPtMemory();
	assert(load_ChkPt(path) == 0);
	assert(chkpt_input_dev == sbuf.st_dev);
	assert(chkpt_input_ino == sbuf.st_ino);
	assert(chkpt_input_levent.sec == original.sec);
	assert(chkpt_input_levent.milli == original.milli);
	assert(chkpt_input_levent.serial == original.serial);
	assert(chkpt_input_levent.type == original.type);
	assert(chkpt_input_levent.node != NULL);
	assert(strcmp(chkpt_input_levent.node, original.node) == 0);
	free_ChkPtMemory();
	assert(unlink(path) == 0);
}

/* main - run checkpoint serialization regression tests
 * @void: no input
 *
 * Return: 0 when all tests pass.
 */
int main(void)
{
	test_checkpoint_event_type();
	return 0;
}
