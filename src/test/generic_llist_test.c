#include "generic-llist.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STRING_LEN 1024
#define TEST_ASSERT(condition, msg)    \
	do {                               \
		if (!(condition)) {            \
			printf("FAIL: %s\n", msg); \
			total_errors++;            \
		} else {                       \
			printf("PASS: %s\n", msg); \
		}                              \
	} while (0)

#define TEST_CASE(name)                              \
	do {                                             \
		test_count++;                                \
		printf("\nTest %d: %s\n", test_count, name); \
	} while (0)

int test_count = 0;
int total_errors = 0;

// Test data structure
typedef struct test_data
{
	char* value;
	int id;
} test_data;

// Free function for test data
void
free_test_data(void* data)
{
	if (data) {
		test_data* td = (test_data*)data;
		free(td->value);
		free(td);
	}
}

// Create test data
test_data*
create_test_data(const char* value, int id)
{
	test_data* td = malloc(sizeof(test_data));
	if (!td)
		return NULL;

	td->value = strdup(value);
	td->id = id;
	return td;
}

// Comparison function for test data
int
compare_test_data(const void* a, const void* b)
{
	const test_data* ta = (const test_data*)a;
	const test_data* tb = (const test_data*)b;
	return strcmp(ta->value, tb->value);
}

// Update function for test data
void
update_test_data(void* data)
{
	test_data* td = (test_data*)data;
	if (td && td->value) {
		// Convert to uppercase
		for (char* p = td->value; *p; p++)
			if (*p >= 'a' && *p <= 'z')
				*p = *p - 'a' + 'A';
	}
}

/**
 * Core verification function that checks if the linked list matches expected
 * output Verifies forward traversal, count, backward traversal, and current
 * pointer
 */
int
verify_list_structure(llist* l, const char* expected_forward, const char* test_name, const char* expected_current)
{
	char forward_result[MAX_STRING_LEN] = "";
	char backward_result[MAX_STRING_LEN] = "";
	int forward_count = 0;
	int backward_count = 0;

	// Save the original current pointer
	lnode* original_current = l->cur;

	// Forward traversal
	list_first(l);
	lnode* node = list_get_cur(l);
	while (node) {
		test_data* data = (test_data*)node->data;
		if (strlen(forward_result) > 0)
			strcat(forward_result, "->");
		strcat(forward_result, data->value);
		forward_count++;
		node = list_next(l);
	}

	// Backward traversal
	list_last(l);
	node = list_get_cur(l);
	while (node) {
		test_data* data = (test_data*)node->data;
		if (strlen(backward_result) > 0)
			strcat(backward_result, "->");
		strcat(backward_result, data->value);
		backward_count++;
		node = node->prev;
	}

	// Restore the original current pointer
	l->cur = original_current;

	// Generate expected backward string by reversing the forward string
	char expected_backward[MAX_STRING_LEN] = "";
	if (strlen(expected_forward) > 0) {
		// Simple approach: collect all elements in array and reverse
		char elements[100][100]; // Max 100 elements, each up to 100 chars
		int element_count = 0;

		// Parse the forward string manually
		const char* start = expected_forward;
		const char* arrow_pos;

		while ((arrow_pos = strstr(start, "->")) != NULL) {
			// Copy element before arrow
			int len = arrow_pos - start;
			strncpy(elements[element_count], start, len);
			elements[element_count][len] = '\0';
			element_count++;
			start = arrow_pos + 2; // Skip "->"
		}

		// Copy last element (after last arrow or the only element)
		strcpy(elements[element_count], start);
		element_count++;

		// Build backward string in reverse order
		for (int i = element_count - 1; i >= 0; i--) {
			if (strlen(expected_backward) > 0)
				strcat(expected_backward, "->");
			strcat(expected_backward, elements[i]);
		}
	}

	// Verification tests
	int success = 1;

	TEST_ASSERT(strcmp(forward_result, expected_forward) == 0,
				"Forward traversal matches expected");
	if (strcmp(forward_result, expected_forward) != 0) {
		printf("   Expected: %s, Got: %s\n", expected_forward, forward_result);
		success = 0;
	}

	TEST_ASSERT(strcmp(backward_result, expected_backward) == 0,
				"Backward traversal matches expected");
	if (strcmp(backward_result, expected_backward) != 0) {
		printf("   Expected: %s, Got: %s\n", expected_backward, backward_result);
		success = 0;
	}

	TEST_ASSERT(forward_count == l->cnt, "Forward count matches list count");
	if (forward_count != l->cnt) {
		printf("   Forward count: %d, List count: %d\n", forward_count, l->cnt);
		success = 0;
	}

	TEST_ASSERT(backward_count == l->cnt, "Backward count matches list count");
	if (backward_count != l->cnt) {
		printf("   Backward count: %d, List count: %d\n", backward_count, l->cnt);
		success = 0;
	}

	TEST_ASSERT(forward_count == backward_count,
				"Forward and backward counts match");

	// Verify current pointer if expected_current is provided
	if (expected_current != NULL) {
		if (strlen(expected_current) == 0) {
			// Empty string means current should be NULL
			TEST_ASSERT(l->cur == NULL, "Current pointer is NULL as expected");
		} else {
			TEST_ASSERT(l->cur != NULL, "Current pointer is not NULL");
			if (l->cur != NULL) {
				test_data* current_data = (test_data*)l->cur->data;
				TEST_ASSERT(strcmp(current_data->value, expected_current) == 0,
							"Current pointer points to expected data");
				if (strcmp(current_data->value, expected_current) != 0) {
					printf("   Expected current: %s, Got: %s\n", expected_current, current_data->value);
					success = 0;
				}
			} else {
				success = 0;
			}
		}
	}

	printf("   Test: %s - Forward: %s, Backward: %s, Current: %s\n", test_name, forward_result, backward_result, (l->cur && l->cur->data) ? ((test_data*)l->cur->data)->value : "NULL");

	return success;
}

// Basic functionality tests
void
test_basic_operations()
{
	printf("\n=== Basic Operations Tests ===\n");
	llist list;

	// Test 1: Create empty list
	TEST_CASE("Create empty list");
	list_create(&list, free_test_data);
	TEST_ASSERT(list.head == NULL, "Empty list initialization");
	TEST_ASSERT(list.cur == NULL, "Empty list current pointer");
	TEST_ASSERT(list.cnt == 0, "Empty list count");
	verify_list_structure(&list, "", "Empty list", "");

	// Test 2: Single element
	TEST_CASE("Single element");
	test_data* data1 = create_test_data("A", 1);
	list_append(&list, data1, sizeof(*data1));
	verify_list_structure(&list, "A", "Single element", "A");

	// Test 3: Multiple elements
	TEST_CASE("Multiple elements");
	test_data* data2 = create_test_data("B", 2);
	test_data* data3 = create_test_data("C", 3);
	list_append(&list, data2, sizeof(*data2));
	list_append(&list, data3, sizeof(*data3));
	verify_list_structure(&list, "A->B->C", "Three elements", "C");

	list_clear(&list);
}

// Advanced traversal tests
void
test_advanced_traversal()
{
	printf("\n=== Advanced Traversal Tests ===\n");
	llist list;
	list_create(&list, free_test_data);

	TEST_CASE("Six element list creation and traversal");
	// Create a longer list
	const char* values[] = { "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta" };
	int num_values = sizeof(values) / sizeof(values[0]);

	for (int i = 0; i < num_values; i++) {
		test_data* data = create_test_data(values[i], i);
		list_append(&list, data, sizeof(*data));
	}

	verify_list_structure(&list, "Alpha->Beta->Gamma->Delta->Epsilon->Zeta", "Six element list", "Zeta");

	// Test navigation functions
	TEST_CASE("Navigation functions test");
	list_first(&list);
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "Alpha") ==
				  0,
				"list_first() navigation");

	list_last(&list);
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "Zeta") ==
				  0,
				"list_last() navigation");

	// Test next navigation
	list_first(&list);
	list_next(&list);
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "Beta") ==
				  0,
				"list_next() navigation");

	list_clear(&list);
}

// Test find functionality
void
test_find_operations()
{
	printf("\n=== Find Operations Tests ===\n");
	llist list;
	list_create(&list, free_test_data);

	TEST_CASE("Find operations test");
	// Create test data
	test_data* data1 = create_test_data("Apple", 1);
	test_data* data2 = create_test_data("Banana", 2);
	test_data* data3 = create_test_data("Cherry", 3);
	test_data* data4 = create_test_data("Date", 4);

	list_append(&list, data1, sizeof(*data1));
	list_append(&list, data2, sizeof(*data2));
	list_append(&list, data3, sizeof(*data3));
	list_append(&list, data4, sizeof(*data4));

	verify_list_structure(&list, "Apple->Banana->Cherry->Date", "Find test setup", "Date");

	// Test finding existing element
	test_data search_data = { "Cherry", 0 };
	lnode* found = list_find(&list, &search_data, compare_test_data);
	TEST_ASSERT(found != NULL, "Find existing element");
	TEST_ASSERT(strcmp(((test_data*)found->data)->value, "Cherry") == 0,
				"Found correct element");

	// Test finding non-existing element
	test_data search_data2 = { "Orange", 0 };
	found = list_find(&list, &search_data2, compare_test_data);
	TEST_ASSERT(found == NULL, "Find non-existing element returns NULL");

	list_clear(&list);
}

// Test update functionality
void
test_update_operations()
{
	printf("\n=== Update Operations Tests ===\n");
	llist list;
	list_create(&list, free_test_data);

	TEST_CASE("Update operations test");
	test_data* data1 = create_test_data("hello", 1);
	test_data* data2 = create_test_data("world", 2);
	test_data* data3 = create_test_data("test", 3);

	list_append(&list, data1, sizeof(*data1));
	list_append(&list, data2, sizeof(*data2));
	list_append(&list, data3, sizeof(*data3));

	verify_list_structure(&list, "hello->world->test", "Before update", "test");

	// Update middle element
	list_first(&list);
	list_next(&list); // Move to "world"
	list_update_cur(&list, update_test_data);

	verify_list_structure(&list, "hello->WORLD->test", "After updating middle element", "WORLD");

	list_clear(&list);
}

// Test removal operations
void
test_removal_operations()
{
	printf("\n=== Removal Operations Tests ===\n");
	llist list;
	list_create(&list, free_test_data);

	TEST_CASE("Removal operations test");
	// Create initial list
	const char* values[] = { "First", "Second", "Third", "Fourth", "Fifth" };
	for (int i = 0; i < 5; i++) {
		test_data* data = create_test_data(values[i], i);
		list_append(&list, data, sizeof(*data));
	}

	verify_list_structure(&list, "First->Second->Third->Fourth->Fifth", "Before removals", "Fifth");

	// Remove middle element
	list_first(&list);
	list_next(&list);
	list_next(&list); // Move to "Third"
	list_delete_cur(&list);

	verify_list_structure(&list, "First->Second->Fourth->Fifth", "After removing middle", "Fourth");

	// Remove first element
	list_first(&list);
	list_delete_cur(&list);

	verify_list_structure(&list, "Second->Fourth->Fifth", "After removing first", "Second");

	// Remove last element
	list_last(&list);
	list_delete_cur(&list);

	verify_list_structure(&list, "Second->Fourth", "After removing last", "Fourth");

	list_clear(&list);
}

// Edge case tests
void
test_edge_cases()
{
	printf("\n=== Edge Case Tests ===\n");
	llist list;

	TEST_CASE("Edge case operations");
	// Test operations on uninitialized list
	list_create(&list, free_test_data);

	// Test operations on empty list
	list_first(&list);
	TEST_ASSERT(list_get_cur(&list) == NULL, "list_first on empty list");

	list_last(&list);
	TEST_ASSERT(list_get_cur(&list) == NULL, "list_last on empty list");

	lnode* next = list_next(&list);
	TEST_ASSERT(next == NULL, "list_next on empty list");

	// Test single element operations
	test_data* data = create_test_data("Single", 1);
	list_append(&list, data, sizeof(*data));

	verify_list_structure(&list, "Single", "Single element edge case", "Single");

	// Test removing single element
	list_delete_cur(&list);
	verify_list_structure(&list, "", "After removing single element", "");

	// Test multiple clear operations
	list_clear(&list);
	list_clear(&list); // Should not crash
	TEST_ASSERT(list.cnt == 0, "Multiple clear operations");

	// Test with duplicate values
	test_data* dup1 = create_test_data("Duplicate", 1);
	test_data* dup2 = create_test_data("Duplicate", 2);
	test_data* dup3 = create_test_data("Duplicate", 3);

	list_append(&list, dup1, sizeof(*dup1));
	list_append(&list, dup2, sizeof(*dup2));
	list_append(&list, dup3, sizeof(*dup3));

	verify_list_structure(&list, "Duplicate->Duplicate->Duplicate", "Duplicate values", "Duplicate");

	list_clear(&list);
}

// Stress test with large dataset
void
test_large_dataset()
{
	printf("\n=== Large Dataset Test ===\n");
	llist list;
	list_create(&list, free_test_data);

	TEST_CASE("Large dataset test");
	const int large_size = 1000;
	char expected[MAX_STRING_LEN] = "";

	// Create large list
	for (int i = 0; i < large_size; i++) {
		char value[20];
		snprintf(value, sizeof(value), "Item%d", i);
		test_data* data = create_test_data(value, i);
		list_append(&list, data, sizeof(*data));

		if (i == 0) {
			strcpy(expected, value);
		} else if (i < 10) { // Only show first 10 items in verification
			strcat(expected, "->");
			strcat(expected, value);
		}
	}

	TEST_ASSERT(list.cnt == large_size, "Large dataset count");

	// Test navigation on large dataset
	list_first(&list);
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "Item0") ==
				  0,
				"Large dataset first element");

	list_last(&list);
	TEST_ASSERT(
	  strcmp(((test_data*)list_get_cur_data(&list))->value, "Item999") == 0,
	  "Large dataset last element");

	printf("   Large dataset test completed with %d elements\n", large_size);

	list_clear(&list);
}

// Advanced test case: Dynamic List Manipulation with Current Pointer Management
void
test_dynamic_manipulation()
{
	printf("\n=== Dynamic List Manipulation Tests ===\n");
	llist list;
	list_create(&list, free_test_data);

	TEST_CASE("Dynamic list manipulation with current pointer management");

	// Step 1: Initial Setup - Create empty list
	verify_list_structure(&list, "", "Initial empty list", "");

	// Step 2: Append Elements A, B, C, D, E
	test_data* dataA = create_test_data("A", 1);
	test_data* dataB = create_test_data("B", 2);
	test_data* dataC = create_test_data("C", 3);
	test_data* dataD = create_test_data("D", 4);
	test_data* dataE = create_test_data("E", 5);

	list_append(&list, dataA, sizeof(*dataA));
	list_append(&list, dataB, sizeof(*dataB));
	list_append(&list, dataC, sizeof(*dataC));
	list_append(&list, dataD, sizeof(*dataD));
	list_append(&list, dataE, sizeof(*dataE));

	verify_list_structure(&list, "A->B->C->D->E", "After appending A,B,C,D,E", "E");
	TEST_ASSERT(strcmp(((test_data*)list.head->data)->value, "A") == 0,
				"Head is A");

	// Step 3: Remove First (A)
	list_first(&list);
	list_delete_cur(&list);

	verify_list_structure(&list, "B->C->D->E", "After removing first element A", "B");
	TEST_ASSERT(strcmp(((test_data*)list.head->data)->value, "B") == 0,
				"Head is now B");

	// Step 4: Set Current to C and Remove C
	test_data search_C = { "C", 0 };
	lnode* found_C = list_find(&list, &search_C, compare_test_data);
	TEST_ASSERT(found_C != NULL, "Found element C");
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "C") == 0,
				"Current is now C");

	list_delete_cur(&list);
	verify_list_structure(&list, "B->D->E", "After removing middle element C", "D");

	// Step 5: Remove Last (E)
	list_last(&list);
	list_delete_cur(&list);

	verify_list_structure(&list, "B->D", "After removing last element E", "D");

	// Step 6: Repeated Additions/Deletions

	// Append F, G
	test_data* dataF = create_test_data("F", 6);
	test_data* dataG = create_test_data("G", 7);
	list_append(&list, dataF, sizeof(*dataF));
	list_append(&list, dataG, sizeof(*dataG));

	verify_list_structure(&list, "B->D->F->G", "After appending F,G", "G");

	// Set Current to B and Remove B
	test_data search_B = { "B", 0 };
	lnode* found_B = list_find(&list, &search_B, compare_test_data);
	TEST_ASSERT(found_B != NULL, "Found element B");
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "B") == 0,
				"Current is now B");

	list_delete_cur(&list);
	verify_list_structure(&list, "D->F->G", "After removing B", "D");
	TEST_ASSERT(strcmp(((test_data*)list.head->data)->value, "D") == 0,
				"Head is now D");

	// Remove D (current)
	test_data search_D = { "D", 0 };
	lnode* found_D = list_find(&list, &search_D, compare_test_data);
	TEST_ASSERT(found_D != NULL, "Found element D");
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "D") == 0,
				"Current is D");

	list_delete_cur(&list);
	verify_list_structure(&list, "F->G", "After removing D", "F");
	TEST_ASSERT(strcmp(((test_data*)list.head->data)->value, "F") == 0,
				"Head is now F");

	// Append H
	test_data* dataH = create_test_data("H", 8);
	list_append(&list, dataH, sizeof(*dataH));

	verify_list_structure(&list, "F->G->H", "After appending H", "H");

	// Set Current to G and Remove G
	test_data search_G = { "G", 0 };
	lnode* found_G = list_find(&list, &search_G, compare_test_data);
	TEST_ASSERT(found_G != NULL, "Found element G");
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "G") == 0,
				"Current is now G");

	list_delete_cur(&list);
	verify_list_structure(&list, "F->H", "After removing G", "H");

	// Step 7: Final State Verification
	TEST_ASSERT(strcmp(((test_data*)list.head->data)->value, "F") == 0,
				"Final head is F");

	// Find tail by traversing to last element
	list_last(&list);
	TEST_ASSERT(strcmp(((test_data*)list_get_cur_data(&list))->value, "H") == 0,
				"Final tail is H");

	// Verify list integrity
	TEST_ASSERT(list.cnt == 2, "Final count is 2");

	// Test edge case: Remove all remaining elements
	list_first(&list);
	list_delete_cur(&list); // Remove F
	verify_list_structure(&list, "H", "After removing F", "H");

	list_delete_cur(&list); // Remove H (last element)
	verify_list_structure(&list, "", "After removing all elements", "");
	TEST_ASSERT(list.head == NULL, "Head is NULL after clearing");
	TEST_ASSERT(list.cur == NULL, "Current is NULL after clearing");
	TEST_ASSERT(list.cnt == 0, "Count is 0 after clearing");

	list_clear(&list);
}

int
main(void)
{
	printf("Starting comprehensive generic-llist tests...\n\n");

	test_basic_operations();
	test_advanced_traversal();
	test_find_operations();
	test_update_operations();
	test_removal_operations();
	test_edge_cases();
	test_large_dataset();
	test_dynamic_manipulation();

	printf("\n=== Test Summary ===\n");
	printf("Total tests run: %d\n", test_count);
	printf("Failed tests: %d\n", total_errors);

	if (total_errors == 0) {
		printf("All tests passed successfully!\n");
		return 0;
	} else {
		printf("Test suite failed with %d error(s)!\n", total_errors);
		return 1;
	}
}
