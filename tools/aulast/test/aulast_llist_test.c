#include "aulast-llist.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int test_count = 0;
static int test_passed = 0;

#define TEST_START(name)                      \
	do {                                      \
		printf("Running test: %s... ", name); \
		fflush(stdout);                       \
		test_count++;                         \
	} while (0)

#define TEST_PASS()       \
	do {                  \
		printf("PASS\n"); \
		test_passed++;    \
	} while (0)

#define TEST_FAIL(msg)             \
	do {                           \
		printf("FAIL: %s\n", msg); \
		return 0;                  \
	} while (0)

/* Utility function to count sessions in list */
static int count_sessions(llist *l)
{
	int count = 0;
	lnode *current, *saved_cur;

	// Save the current position
	saved_cur = l->cur;

	// Count sessions without affecting current position
	list_first(l);
	current = list_get_cur(l);
	while (current) {
		count++;
		current = list_next(l);
	}

	// Restore the original current position
	l->cur = saved_cur;

	return count;
}

/*
 * Test: update_operations_verification
 *
 * Steps:
 * 1. Create a new session with list_create_session()
 * 2. Verify initial state (status=LOG_IN, host=NULL, term=NULL, result=-1)
 * 3. Call list_update_start() with host, term, result, and serial number
 * 4. Verify all fields were updated correctly (status=SESSION_START, host/term set)
 * 5. Call list_update_logout() with end time and serial number
 * 6. Verify logout fields updated (status=LOG_OUT, end time set, proof set)
 * 7. Create second session and test list_update_start() with NULL parameters
 * 8. Verify NULL parameters don't crash and status still updates
 * 9. Clean up list
 */
/* Test that verifies update_start and update_logout actually update the values */
static int
test_update_operations_verification(void)
{
	TEST_START("update_operations_verification");

	llist l;
	lnode *found;
	time_t base_time = time(NULL);

	list_create(&l);

	// Create a session
	list_create_session(&l, 1000, 12345, 1001, 200001);

	// Verify initial state
	found = list_find_auid(&l, 1000, 12345, 1001);
	if (!found)
		TEST_FAIL("should find created session");
	if (found->status != LOG_IN)
		TEST_FAIL("initial status should be LOG_IN");
	if (found->term != NULL)
		TEST_FAIL("initial term should be NULL");
	if (found->host != NULL)
		TEST_FAIL("initial host should be NULL");
	if (found->result != -1)
		TEST_FAIL("initial result should be -1");
	if (found->user_login_proof != 0)
		TEST_FAIL("initial user_login_proof should be 0");

	// Update start - verify all fields get updated
	list_update_start(&l, "192.168.1.100", "pts/0", 0, 200002);

	// Verify update_start changes
	if (found->status != SESSION_START)
		TEST_FAIL("status should be SESSION_START after update_start");
	if (!found->term || strcmp(found->term, "pts/0") != 0)
		TEST_FAIL("term should be 'pts/0' after update_start");
	if (!found->host || strcmp(found->host, "192.168.1.100") != 0)
		TEST_FAIL("host should be '192.168.1.100' after update_start");
	if (found->result != 0)
		TEST_FAIL("result should be 0 after successful update_start");
	if (found->user_login_proof != 200002)
		TEST_FAIL("user_login_proof should be 200002 after update_start");

	// Update logout - verify fields get updated
	if (found->end != 0)
		TEST_FAIL("end time should be 0 before logout");
	if (found->user_end_proof != 0)
		TEST_FAIL("user_end_proof should be 0 before logout");

	list_update_logout(&l, base_time + 1800, 200003);

	// Verify update_logout changes
	if (found->status != LOG_OUT)
		TEST_FAIL("status should be LOG_OUT after update_logout");
	if (found->end != base_time + 1800)
		TEST_FAIL("end time should be set after update_logout");
	if (found->user_end_proof != 200003)
		TEST_FAIL("user_end_proof should be 200003 after update_logout");

	// Test update_start with NULL values
	list_create_session(&l, 1001, 12346, 1002, 200004);
	found = list_find_auid(&l, 1001, 12346, 1002);
	if (!found)
		TEST_FAIL("should find second session");

	list_update_start(&l, NULL, NULL, 1, 200005);
	if (found->status != SESSION_START)
		TEST_FAIL("status should be SESSION_START even with NULL values");
	if (found->term != NULL)
		TEST_FAIL("term should remain NULL when passed NULL");
	if (found->host != NULL)
		TEST_FAIL("host should remain NULL when passed NULL");
	if (found->result != 1)
		TEST_FAIL("result should be 1 (failed login)");

	list_clear(&l);
	TEST_PASS();
	return 1;
}

/*
 * Test: repeated_add_remove_with_find
 *
 * Steps:
 * 1. Create 5 sessions in a loop with incremental IDs (1000-1004, sessions 2000-2004)
 * 2. Update each session with list_update_start()
 * 3. Verify count_sessions() returns 5
 * 4. Find and delete session 2002 (middle of list)
 * 5. Verify session 2002 cannot be found anymore
 * 6. Find and delete session 2003 (another middle session)
 * 7. Verify session 2003 cannot be found anymore
 * 8. Verify count is now 3 sessions remaining
 * 9. Create new session with ID 2002 but different user (2002 instead of 1002)
 * 10. Create another new session with ID 2003 but different user (2003 instead of 1003)
 * 11. Verify old sessions are still gone but new ones exist
 * 12. Remove all remaining sessions one by one (2000, 2001, 2004, new 2002, new 2003)
 * 13. After each removal, verify count decreases and deleted session cannot be found
 * 14. Verify list is completely empty at the end
 */
/* Test repeated add/remove operations with find verification */
static int
test_repeated_add_remove_with_find(void)
{
	TEST_START("repeated_add_remove_with_find");

	llist l;
	lnode *found;
	int i;

	list_create(&l);

	// Phase 1: Add multiple sessions
	for (i = 0; i < 5; i++) {
		list_create_session(&l, 1000 + i, 12345 + i, 2000 + i, 300000 + i);
		list_update_start(&l, "localhost", "pts/0", 0, 300100 + i);
	}

	// Verify all 5 sessions exist
	if (count_sessions(&l) != 5)
		TEST_FAIL("should have 5 sessions after creation");

	// Phase 2: Remove middle sessions (2002, 2003), verify they're gone
	found = list_find_auid(&l, 1002, 12347, 2002);
	if (!found)
		TEST_FAIL("should find session 2002 before removal");
	list_delete_cur(&l);

	// Verify session 2002 is gone
	found = list_find_auid(&l, 1002, 12347, 2002);
	if (found)
		TEST_FAIL("session 2002 should be gone after delete_cur");

	found = list_find_auid(&l, 1003, 12348, 2003);
	if (!found)
		TEST_FAIL("should find session 2003 before removal");
	list_delete_cur(&l);

	// Verify session 2003 is gone
	found = list_find_auid(&l, 1003, 12348, 2003);
	if (found)
		TEST_FAIL("session 2003 should be gone after delete_cur");

	// Should have 3 sessions left
	if (count_sessions(&l) != 3)
		TEST_FAIL("should have 3 sessions after removing 2");


	// Phase 3: Add sessions back with same IDs but different users
	list_create_session(&l, 2002, 22347, 2002, 300010);  // Reuse session ID 2002
	list_update_start(&l, "remotehost", "ssh", 0, 300011);

	list_create_session(&l, 2003, 22348, 2003, 300012);  // Reuse session ID 2003
	list_update_start(&l, "remotehost2", "ssh", 0, 300013);

	// Verify old sessions are still gone, new ones exist
	found = list_find_auid(&l, 1002, 12347, 2002);  // Old session
	if (found)
		TEST_FAIL("old session 1002,12347,2002 should still be gone");

	found = list_find_auid(&l, 2002, 22347, 2002);  // New session
	if (!found)
		TEST_FAIL("new session 2002,22347,2002 should exist");
	if (found->auid != 2002)
		TEST_FAIL("new session should have auid 2002");

	// Phase 4: Remove all sessions one by one and verify with find
	int expected_count = 5;

	// Remove session 2000
	found = list_find_auid(&l, 1000, 12345, 2000);
	if (!found)
		TEST_FAIL("should find session 2000");
	list_delete_cur(&l);
	expected_count--;
	if (count_sessions(&l) != expected_count)
		TEST_FAIL("count mismatch after removing session 2000");
	found = list_find_auid(&l, 1000, 12345, 2000);
	if (found)
		TEST_FAIL("session 2000 should be gone");

	// Remove session 2001
	found = list_find_auid(&l, 1001, 12346, 2001);
	if (!found)
		TEST_FAIL("should find session 2001");
	list_delete_cur(&l);
	expected_count--;
	if (count_sessions(&l) != expected_count)
		TEST_FAIL("count mismatch after removing session 2001");
	found = list_find_auid(&l, 1001, 12346, 2001);
	if (found)
		TEST_FAIL("session 2001 should be gone");

	// Remove session 2004
	found = list_find_auid(&l, 1004, 12349, 2004);
	if (!found)
		TEST_FAIL("should find session 2004");
	list_delete_cur(&l);
	expected_count--;
	if (count_sessions(&l) != expected_count)
		TEST_FAIL("count mismatch after removing session 2004");
	found = list_find_auid(&l, 1004, 12349, 2004);
	if (found)
		TEST_FAIL("session 2004 should be gone");

	// Remove new session 2002 (user 2002)
	found = list_find_auid(&l, 2002, 22347, 2002);
	if (!found)
		TEST_FAIL("should find new session 2002");
	list_delete_cur(&l);
	expected_count--;
	if (count_sessions(&l) != expected_count)
		TEST_FAIL("count mismatch after removing new session 2002");
	found = list_find_auid(&l, 2002, 22347, 2002);
	if (found)
		TEST_FAIL("new session 2002 should be gone");

	// Remove new session 2003 (user 2003) - should be last one
	found = list_find_auid(&l, 2003, 22348, 2003);
	if (!found)
		TEST_FAIL("should find new session 2003");
	list_delete_cur(&l);
	expected_count--;
	if (count_sessions(&l) != expected_count)
		TEST_FAIL("count mismatch after removing new session 2003");
	if (expected_count != 0)
		TEST_FAIL("should have 0 sessions at end");
	found = list_find_auid(&l, 2003, 22348, 2003);
	if (found)
		TEST_FAIL("new session 2003 should be gone");

	// Verify list is empty
	if (count_sessions(&l) != 0)
		TEST_FAIL("list should be empty after removing all sessions");

	list_first(&l);
	if (list_get_cur(&l) != NULL)
		TEST_FAIL("list_get_cur should return NULL for empty list");

	list_clear(&l);
	TEST_PASS();
}

/*
 * Test: complex_session_management
 *
 * Steps:
 * Phase 1 - Initial Setup:
 * 1. Create 3 sessions: user 1000 with sessions 1001,1002 and user 1001 with session 1003
 * 2. Update each session with list_update_start() (different hosts/terminals)
 * 3. Verify all 3 sessions exist and first session has correct host
 *
 * Phase 2 - Session Conflict Resolution:
 * 4. Find user 1000's first session (1001)
 * 5. Update it to LOG_OUT state with list_update_logout()
 * 6. Verify logout fields are set correctly
 * 7. Delete the session with list_delete_cur()
 * 8. Verify session cannot be found anymore and count is now 2
 *
 * Phase 3 - Session ID Reuse:
 * 9. Create new session with same ID (1001) but different user (1003)
 * 10. Update new session with list_update_start()
 * 11. Verify new session exists and belongs to user 1003
 *
 * Phase 4 - Batch Operations:
 * 12. Find user 1001's session (1003) and logout with specific time
 * 13. Verify end time was set correctly
 * 14. Find user 1000's second session (1002) and logout
 * 15. Verify final count is 3 sessions
 * 16. Iterate through all sessions and verify they're all logged out or active
 * 17. Clean up list
 */
/* Advanced test: Complex multi-user session management scenario */
static int
test_complex_session_management(void)
{
	TEST_START("complex_session_management");

	llist l;
	lnode *found;
	time_t base_time = time(NULL);

	list_create(&l);

	// Phase 1: Create sessions and verify update operations
	list_create_session(&l, 1000, 12345, 1001, 200001);
	list_update_start(&l, "192.168.1.100", "pts/0", 0, 200002);

	list_create_session(&l, 1000, 12346, 1002, 200003);
	list_update_start(&l, "192.168.1.101", "pts/1", 0, 200004);

	list_create_session(&l, 1001, 12347, 1003, 200005);
	list_update_start(&l, "console", "tty1", 0, 200006);

	// Verify initial creation and updates
	if (count_sessions(&l) != 3)
		TEST_FAIL("should have 3 sessions created");

	// Verify first session update worked
	found = list_find_auid(&l, 1000, 12345, 1001);
	if (!found || found->status != SESSION_START)
		TEST_FAIL("first session should be in SESSION_START state");
	if (!found->host || strcmp(found->host, "192.168.1.100") != 0)
		TEST_FAIL("first session host should be updated");

	// Phase 2: Session conflict resolution
	found = list_find_auid(&l, 1000, 12345, 1001);
	if (!found)
		TEST_FAIL("should find user 1000's first session");

	// Update logout and remove
	list_update_logout(&l, base_time + 1800, 200011);
	if (found->status != LOG_OUT || found->end != base_time + 1800)
		TEST_FAIL("logout update should set status and end time");
	list_delete_cur(&l);

	// Verify removal
	found = list_find_auid(&l, 1000, 12345, 1001);
	if (found)
		TEST_FAIL("deleted session should not be found");

	if (count_sessions(&l) != 2)
		TEST_FAIL("should have 2 sessions after deletion");

	// Phase 3: Session ID reuse
	list_create_session(&l, 1003, 12350, 1001, 200012); // Reuse session ID 1001
	list_update_start(&l, "192.168.1.150", "pts/4", 0, 200013);

	found = list_find_auid(&l, 1003, 12350, 1001);
	if (!found)
		TEST_FAIL("new session with reused ID should exist");
	if (found->auid != 1003)
		TEST_FAIL("new session should belong to user 1003");

	// Phase 4: Batch operations
	found = list_find_auid(&l, 1001, 12347, 1003);
	if (!found)
		TEST_FAIL("should find user 1001's session");
	list_update_logout(&l, base_time + 2400, 200014);
	if (found->end != base_time + 2400)
		TEST_FAIL("logout should update end time");

	found = list_find_auid(&l, 1000, 12346, 1002);
	if (!found)
		TEST_FAIL("should find user 1000's second session");
	list_update_logout(&l, base_time + 3000, 200015);

	// Final verification: should have 3 sessions, all logged out
	if (count_sessions(&l) != 3)
		TEST_FAIL("should have 3 sessions at end");

	list_first(&l);
	found = list_get_cur(&l);
	while (found) {
		if (found->status != LOG_OUT && found->status != SESSION_START)
			TEST_FAIL("all remaining sessions should be logged out or active");
		found = list_next(&l);
	}

	list_clear(&l);
	TEST_PASS();
}

int
main(void)
{
	printf("Running aulast linked list advanced tests...\n\n");

	test_update_operations_verification();
	test_repeated_add_remove_with_find();
	test_complex_session_management();

	printf("\nTest Results: %d/%d tests passed\n", test_passed, test_count);

	if (test_passed == test_count) {
		printf("All tests PASSED!\n");
		return 0;
	} else {
		printf("Some tests FAILED!\n");
		return 1;
	}
}
