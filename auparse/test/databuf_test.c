#include "config.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "data_buf.h"

static void test_basic(void)
{
	DataBuf db;
	char data1[] = "abcd";
	char data2[] = "ef";
	char data3[] = "ghij";

	assert(databuf_init(&db, 0, 0) == 1);
	assert(databuf_append(&db, data1, sizeof(data1) - 1) == 1);
	assert(db.len == 4 && db.offset == 0);
	assert(memcmp(databuf_beg(&db), "abcd", 4) == 0);

	assert(databuf_append(&db, data2, sizeof(data2) - 1) == 1);
	assert(db.len == 6 && db.offset == 0);
	assert(memcmp(databuf_beg(&db), "abcdef", 6) == 0);

	assert(databuf_advance(&db, 3) == 1);
	assert(db.offset == 3 && db.len == 3);
	assert(memcmp(databuf_beg(&db), "def", 3) == 0);

	assert(databuf_append(&db, data3, sizeof(data3) - 1) == 1);
	assert(db.offset == 0 && db.len == 7);
	assert(memcmp(databuf_beg(&db), "defghij", 7) == 0);

	databuf_free(&db);
}

static void test_preserve(void)
{
	DataBuf db;
	char data1[] = "abcd";
	char data2[] = "efgh";
	char big[] = "01234567";

	assert(databuf_init(&db, 8, DATABUF_FLAG_PRESERVE_HEAD) == 1);
	assert(databuf_append(&db, data1, 4) == 1);
	assert(databuf_advance(&db, 2) == 1);
	assert(databuf_append(&db, data2, 4) == 1);
	assert(db.offset == 2 && db.len == 6);

	assert(databuf_reset(&db) == 1);
	assert(db.offset == 0 && db.len == 6);
	assert(memcmp(databuf_beg(&db), "abcdef", 6) == 0);

	assert(databuf_replace(&db, "xy", 2) == 1);
	assert(databuf_advance(&db, 2) == 1);
	assert(databuf_append(&db, big, 8) == 1);
	assert(db.offset == 2 && db.len == 8);

	assert(databuf_reset(&db) == 1);
	assert(db.offset == 0 && db.len == 8);
	assert(memcmp(databuf_beg(&db), "xy012345", 8) == 0);

	databuf_free(&db);
}

int main(void)
{
	test_basic();
	test_preserve();
	printf("databuf tests: all passed\n");
	return 0;
}

