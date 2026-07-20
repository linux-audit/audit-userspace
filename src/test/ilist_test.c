/* ilist_test.c -- ausearch integer list tests
 * Copyright 2008,2015,2019 Red Hat Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 */

#include <stdio.h>
#include "ausearch-int.h"

int main(void)
{
	int i = 0;
	ilist e;
	int_node *node;

	ilist_create(&e);

	// This first test checks to see if list is 
	// created in a numeric order
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
	puts("starting sort test");

	// Now test to see if the sort function works
	// Fill the list exactly backwards
	ilist_add_if_uniq(&e, 3, 0);
	ilist_add_if_uniq(&e, 3, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 3, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 2, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 2, 0);
	ilist_add_if_uniq(&e, 4, 0); 
	ilist_add_if_uniq(&e, 1, 0);

	ilist_sort_by_hits(&e);

	i = 0;
	ilist_first(&e);
	do {
		node = ilist_get_cur(&e);
		if (node->hits != (4-i)) {
			printf("Sort test failed - i:%d != ihits:%u\n",
				i, node->hits);
			return 1;
		}
		i++;
	} while ((node = ilist_next(&e)));
	
	ilist_clear(&e);

	printf("ilist tests passed\n");
	return 0;
}
