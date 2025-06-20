#ifndef AUPARSE_STUB_H
#define AUPARSE_STUB_H

/*
 * Stub definitions for using interpretation helpers without auparse
 * initialization. Each translation unit that needs them gets its own
 * static copy.
 */

typedef struct interp_nvnode {
	char *name;
	char *val;
	char *interp_val;
	unsigned int item;
} interp_nvnode;

typedef struct interp_nvlist {
	interp_nvnode *array;
	unsigned int cur;
	unsigned int cnt;
	unsigned int size;
	char *record;
	char *end;
} interp_nvlist;

typedef struct {
	interp_nvlist interpretations;
} interp_state_t;

#define NEVER_LOADED 0xFFFF

static interp_state_t interp_au;

#endif /* AUPARSE_STUB_H */
