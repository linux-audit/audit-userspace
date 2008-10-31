#include <stdio.h>
#include "ausearch-int.h"

int main(void)
{
	int i = 0;
	ilist e;
	int_node *node;

	ilist_create(&e);

	ilist_add_if_uniq(&e, 6, 0);
	ilist_add_if_uniq(&e, 5, 0);
	ilist_add_if_uniq(&e, 7, 0);
	ilist_add_if_uniq(&e, 1, 0);
	ilist_add_if_uniq(&e, 8, 0);
	ilist_add_if_uniq(&e, 2, 0);
	ilist_add_if_uniq(&e, 9, 0);
	ilist_add_if_uniq(&e, 0, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 3, 0);

	ilist_first(&e);
	do {
		node = ilist_get_cur(&e);
		if (i != node->num) {
			printf("Test failed - i:%d != num:%d\n", i, node->num);
			return 1;
		}
		i++;
	} while ((node = ilist_next(&e)));
	
	ilist_clear(&e);
	printf("ilist test passed\n");
	return 0;
}

