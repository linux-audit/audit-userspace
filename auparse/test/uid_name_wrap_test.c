#include "config.h"
#include "internal.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>

/* Verify name->uid->name round trip through the cache */

/*
 * main - ensure cache lookups are symmetric
 *
 * Returns 0 on success or aborts on failure.
 */
int main(void)
{
	auparse_state_t au;
	memset(&au, 0, sizeof(au));

	uid_t uid = lookup_uid_from_name(&au, "root");
	assert(uid == 0);

	QNode *n = check_lru_uid(au.uid_cache, uid);
	assert(n && n->name && strcmp(n->name, "root") == 0);

	destroy_lru(au.uid_cache);
	return 0;
}
