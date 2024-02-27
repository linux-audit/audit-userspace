/*
 * ausearch-string.c - Minimal linked list library for strings
 * Copyright (c) 2005,2008,2014,2023 Red Hat Inc.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
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
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */

#pragma GCC optimize("O3,inline")
#include "ausearch-string.h"
#include <stdlib.h>
#include <string.h>


void slist_create(slist *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->last = NULL;
	l->cnt = 0;
}

snode *slist_next(slist *l)
{
	if (l->cur == NULL)
		return NULL;
	l->cur = l->cur->next;
	return l->cur;
}

void slist_append(slist *l, const snode *node)
{
	snode* newnode;

	newnode = malloc(sizeof(snode));

	if (node->str)
		newnode->str = node->str;
	else
		newnode->str = NULL;

	if (node->key)
		newnode->key = node->key;
	else
		newnode->key = NULL;

	newnode->hits = node->hits;
	newnode->next = NULL;

	// if the top is empty, add it there
	if (l->head == NULL) {
		l->head = newnode;
		l->last = newnode;
	} else { // Otherwise put at the end
		l->last->next = newnode;
		l->last = newnode;
	}

	// make newnode current
	l->cur = newnode;
	l->cnt++;
}

void slist_clear(slist* l)
{
	snode* nextnode;
	register snode* current;

	current = l->head;
	while (current) {
		nextnode=current->next;
		free(current->str);
		free(current->key);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->last = NULL;
	l->cnt = 0;
}

int slist_add_if_uniq(slist *l, const char *str)
{
	snode sn;
	register snode *cur;

	if (str == NULL)
		return -1;

	cur = l->head;
	while (cur) {
		if (strcmp(str, cur->str) == 0) {
			cur->hits++;
			l->cur = cur;
			return 0;
		} else
			cur = cur->next;
	}

	/* No matches, append to the end */
	sn.str = strdup(str);
	sn.key = NULL;
	sn.hits = 1;
	slist_append(l, &sn);
	return 1;
}

/*static void dump_list(slist *l)
{
	if (l == NULL)
		return;

	register snode* cur = l->head;
	puts("start dump");
	while (cur) {
		printf("%u\n", cur->hits);
		cur = cur->next;
	}
}*/

// This will sort the list from most hits to least
static void old_sort_by_hits(slist *l)
{
	register snode* cur, *prev;
	int swapped;

	do {
		swapped = 0;
		prev = NULL;
		cur = l->head;
//		dump_list(l);

		while (cur && cur->next) {
			// If the next node is bigger
			if (cur->hits < cur->next->hits) {
				// swap the nodes
				if (prev)
					prev->next = cur->next;
				else
					l->head = cur->next;

				snode *temp = cur->next->next;
				cur->next->next = cur;
				cur->next = temp;
				swapped = 1;
			}
			prev = cur;
			cur = cur->next;
		}
	} while (swapped);

	// End with cur pointing at first record
	l->cur = l->head;
}

// Merge two sorted lists
static snode* slist_merge_sorted_lists(snode *a, snode *b)
{
	snode dummy;
	snode *tail = &dummy;
	dummy.next = NULL;

	while (a && b) {
		if (a->hits >= b->hits) {
			tail->next = a;
			a = a->next;
		} else {
			tail->next = b;
			b = b->next;
		}
		tail = tail->next;
	}
	tail->next = a ? a : b;
	return dummy.next;
}

// Split the list into two halves
static void slist_split_list(snode *head, snode **front, snode **back)
{
	snode *fast, *slow;
	slow = head;
	fast = head->next;

	while (fast) {
		fast = fast->next;
		if (fast) {
			slow = slow->next;
			fast = fast->next;
		}
	}

	*front = head;
	*back = slow->next;
	slow->next = NULL;
}

// Merge sort for linked list
static void slist_merge_sort(snode **head_ref)
{
	snode *head = *head_ref;
	snode *a, *b;

	if (!head || !head->next)
		return;

	slist_split_list(head, &a, &b);

	slist_merge_sort(&a);
	slist_merge_sort(&b);

	*head_ref = slist_merge_sorted_lists(a, b);
}

// This function dominates aureport --summary --kind output
void slist_sort_by_hits(slist *l)
{
	if (l->cnt <= 1)
		return;

	// If the list is small, use old algorithm because
	// the new one has some overhead that makes it slower
	// until the list is big enough that the inefficiencies
	// of the old algorithm cause slowness. The value chosen
	// below is just a guess. At 100, the old algorithm is
	// faster. At 1000, the new one is 5x faster.
	if (l->cnt < 200)
		return old_sort_by_hits(l);

	slist_merge_sort(&l->head);

	// End with cur pointing at first record
	l->cur = l->head;
}

