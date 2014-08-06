#include <stdio.h>
#include <string.h>
#include "ausearch-string.h"

slist s;

int print_list(void)
{
	int cnt = 0;
	slist_first(&s);
	do {
		snode *cur = slist_get_cur(&s);
		if (cur) {
			cnt++;
			printf("%s\n", cur->str);
		}
	} while (slist_next(&s));
	return cnt;
}

int main(void)
{
	snode n;
	int rc;

	slist_create(&s);
	slist_add_if_uniq(&s, "test1");
	slist_add_if_uniq(&s, "test2");
	slist_first(&s);
	slist_add_if_uniq(&s, "test3");
	puts("should be 3");
	rc = print_list();
	if (s.cnt != 3 || rc !=3) {
		puts("test count is wrong");
		return 1;
	}

	n.str = strdup("test4");
	n.key = NULL;
	n.hits = 1;
	slist_append(&s, &n);
	puts("should add a #4");
	rc = print_list();
	if (s.cnt != 4 || rc != 4) {
		puts("test count is wrong");
		return 1;
	}

	slist_add_if_uniq(&s, "test2");
	puts("should be same");
	rc = print_list();
	if (s.cnt != 4 || rc != 4) {
		puts("test count is wrong");
		return 1;
	}

	slist_clear(&s);
	puts("should be empty");
	rc = print_list();	
	if (s.cnt != 0 || rc != 0) {
		puts("test count is wrong");
		return 1;
	}
	return 0;
}

