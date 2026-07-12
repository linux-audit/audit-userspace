#include "config.h"
#include "internal.h"
#include <assert.h>
#include <stddef.h>

void *__real_malloc(size_t size);

static unsigned int rnode_allocations;

/* __wrap_malloc - fail the second event-record node allocation
 * @size: requested allocation size
 *
 * Return: allocated memory or NULL for the selected allocation.
 */
void *__wrap_malloc(size_t size)
{
	if (size == sizeof(rnode) && ++rnode_allocations == 2)
		return NULL;
	return __real_malloc(size);
}

/* test_append_oom - release a record if its list node cannot be allocated
 *
 * Return: none. Failures abort through assert().
 */
static void test_append_oom(void)
{
	static const char input[] =
		"type=SYSCALL msg=audit(1.001:1): arch=c000003e syscall=0\n"
		"type=PATH msg=audit(1.001:1): item=0 name=\"x\"\n";
	auparse_state_t *au;

	au = auparse_init(AUSOURCE_BUFFER, input);
	assert(au != NULL);
	(void)auparse_next_event(au);
	assert(rnode_allocations == 2);
	auparse_destroy(au);
}

/* main - execute append allocation failure regression coverage
 *
 * Return: 0 on success or aborts through assert().
 */
int main(void)
{
	test_append_oom();
	return 0;
}
