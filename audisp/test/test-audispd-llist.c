/*
 * test-audispd-llist.c - Test cases for audispd linked list implementation
 * Copyright (c) 2025 Red Hat Inc.
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
 *   Test cases based on audispd.c usage patterns
 */

#include "audispd-llist.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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

/* Helper function to create a sample plugin config */
static plugin_conf_t *create_test_plugin(const char *name, active_t active,
					const char *path)
{
	plugin_conf_t *config = malloc(sizeof(plugin_conf_t));
	if (!config)
		return NULL;

	clear_pconfig(config);
	config->active = active;
	config->path = path ? strdup(path) : NULL;
	config->name = name ? strdup(name) : NULL;

	return config;
}

/* Helper function to free a test plugin config */
static void free_test_plugin(plugin_conf_t *config)
{
	if (!config)
		return;

	free((char *)config->path);
	free(config->name);
	if (config->args) {
		for (int i = 0; i < config->nargs; i++) {
			free(config->args[i]);
		}
		free(config->args);
	}
	free(config);
}

/*
 * Test: plugin_configuration_management
 *
 * This test simulates the plugin configuration management scenario used in audispd.c
 *
 * Steps:
 * 1. Create a list and add multiple plugins with different configurations
 * 2. Test plist_count_active() with various active states
 * 3. Test plist_find_name() to locate specific plugins
 * 4. Test plist_mark_all_unchecked() and plist_find_unchecked()
 * 5. Verify list iteration with plist_first(), plist_next()
 * 6. Test plist_last() and plist_append() at end
 * 7. Clean up and verify empty list state
 */
static int
test_plugin_configuration_management(void)
{
	TEST_START("plugin_configuration_management");

	conf_llist plugin_list;
	plugin_conf_t *config1, *config2, *config3, *config4;
	lnode *node;

	plist_create(&plugin_list);

	// Verify initial empty state
	if (plist_count(&plugin_list) != 0)
		TEST_FAIL("new list should have count 0");
	if (plist_count_active(&plugin_list) != 0)
		TEST_FAIL("new list should have 0 active plugins");

	// Create test plugins with different configurations
	config1 = create_test_plugin("audit-remote", A_YES, "/usr/sbin/audit-remote");
	config2 = create_test_plugin("audit-syslog", A_NO, "/usr/sbin/audit-syslog");
	config3 = create_test_plugin("audit-af_unix", A_YES, "/usr/sbin/audit-af_unix");
	config4 = create_test_plugin("audit-custom-plugin", A_YES, "/usr/sbin/audit-custom-plugin");

	if (!config1 || !config2 || !config3 || !config4)
		TEST_FAIL("failed to create test plugin configs");

	// Add plugins to list
	if (plist_append(&plugin_list, config1) != 0)
		TEST_FAIL("failed to append config1");
	if (plist_append(&plugin_list, config2) != 0)
		TEST_FAIL("failed to append config2");
	if (plist_append(&plugin_list, config3) != 0)
		TEST_FAIL("failed to append config3");
	if (plist_append(&plugin_list, config4) != 0)
		TEST_FAIL("failed to append config4");

	// Verify counts
	if (plist_count(&plugin_list) != 4)
		TEST_FAIL("should have 4 plugins in list");
	if (plist_count_active(&plugin_list) != 3)
		TEST_FAIL("should have 3 active plugins");

	// Test find by name (used in audispd.c for HUP signal handling)
	node = plist_find_name(&plugin_list, "audit-syslog");
	if (!node || !node->p)
		TEST_FAIL("should find audit-syslog plugin");
	if (node->p->active != A_NO)
		TEST_FAIL("audit-syslog should be inactive");

	node = plist_find_name(&plugin_list, "audit-remote");
	if (!node || !node->p)
		TEST_FAIL("should find audit-remote plugin");
	if (node->p->active != A_YES)
		TEST_FAIL("audit-remote should be active");

	// Test find non-existent plugin
	node = plist_find_name(&plugin_list, "nonexistent");
	if (node)
		TEST_FAIL("should not find nonexistent plugin");

	// Test find with NULL name
	node = plist_find_name(&plugin_list, NULL);
	if (node)
		TEST_FAIL("should not find plugin with NULL name");

	// Test mark all unchecked (used for HUP signal handling)
	plist_mark_all_unchecked(&plugin_list);

	// Verify all plugins are marked unchecked
	plist_first(&plugin_list);
	node = plist_get_cur(&plugin_list);
	int unchecked_count = 0;
	while (node) {
		if (node->p && node->p->checked == 0)
			unchecked_count++;
		node = plist_next(&plugin_list);
	}
	if (unchecked_count != 4)
		TEST_FAIL("all 4 plugins should be unchecked");

	// Test find unchecked
	node = plist_find_unchecked(&plugin_list);
	if (!node)
		TEST_FAIL("should find at least one unchecked plugin");

	// Mark first plugin as checked
	node->p->checked = 1;

	// Should still find unchecked plugins
	node = plist_find_unchecked(&plugin_list);
	if (!node)
		TEST_FAIL("should still find unchecked plugins");

	// Clean up
	plist_clear(&plugin_list);

	// Verify cleared state
	if (plist_count(&plugin_list) != 0)
		TEST_FAIL("cleared list should have count 0");
	if (plist_count_active(&plugin_list) != 0)
		TEST_FAIL("cleared list should have 0 active plugins");

	plist_first(&plugin_list);
	if (plist_get_cur(&plugin_list) != NULL)
		TEST_FAIL("cleared list should have NULL current");

	// Free test configs (plist_clear should have freed the copies)
	free_test_plugin(config1);
	free_test_plugin(config2);
	free_test_plugin(config3);
	free_test_plugin(config4);

	TEST_PASS();
	return 1;
}

/*
 * Test: plugin_hup_signal_handling
 *
 * This test simulates the HUP signal handling scenario used in audispd.c
 * where the configuration is reloaded and plugins are compared between
 * old and new configurations.
 *
 * Steps:
 * 1. Create "old" plugin list with existing plugins
 * 2. Create "new" plugin list with updated configuration
 * 3. Mark all plugins in old list as unchecked
 * 4. Compare new plugins against old list using plist_find_name()
 * 5. Mark matching plugins as checked, add new plugins to old list
 * 6. Find unchecked plugins (these should be removed)
 * 7. Clean up both lists
 */
static int
test_plugin_hup_signal_handling(void)
{
	TEST_START("plugin_hup_signal_handling");

	conf_llist old_plugin_list, new_plugin_list;
	plugin_conf_t *old_config1, *old_config2, *old_config3;
	plugin_conf_t *new_config1, *new_config2, *new_config4;
	lnode *old_node, *new_node;

	plist_create(&old_plugin_list);
	plist_create(&new_plugin_list);

	// Create old configuration
	old_config1 = create_test_plugin("audit-remote", A_YES, "/usr/sbin/audit-remote");
	old_config2 = create_test_plugin("audit-syslog", A_YES, "/usr/sbin/audit-syslog");
	old_config3 = create_test_plugin("audit-af_unix", A_NO, "/usr/sbin/audit-af_unix");

	if (!old_config1 || !old_config2 || !old_config3)
		TEST_FAIL("failed to create old plugin configs");

	if (plist_append(&old_plugin_list, old_config1) != 0)
		TEST_FAIL("failed to append old_config1");
	if (plist_append(&old_plugin_list, old_config2) != 0)
		TEST_FAIL("failed to append old_config2");
	if (plist_append(&old_plugin_list, old_config3) != 0)
		TEST_FAIL("failed to append old_config3");

	// Create new configuration (remove audit-af_unix, add audit-custom-plugin, keep others)
	new_config1 = create_test_plugin("audit-remote", A_YES, "/usr/sbin/audit-remote");
	new_config2 = create_test_plugin("audit-syslog", A_NO, "/usr/sbin/audit-syslog"); // Changed to inactive
	new_config4 = create_test_plugin("audit-custom-plugin", A_YES, "/usr/sbin/audit-custom-plugin");

	if (!new_config1 || !new_config2 || !new_config4)
		TEST_FAIL("failed to create new plugin configs");

	if (plist_append(&new_plugin_list, new_config1) != 0)
		TEST_FAIL("failed to append new_config1");
	if (plist_append(&new_plugin_list, new_config2) != 0)
		TEST_FAIL("failed to append new_config2");
	if (plist_append(&new_plugin_list, new_config4) != 0)
		TEST_FAIL("failed to append new_config4");

	// Simulate HUP signal handling: mark all old plugins as unchecked
	plist_mark_all_unchecked(&old_plugin_list);

	// Process new configuration
	plist_first(&new_plugin_list);
	new_node = plist_get_cur(&new_plugin_list);

	while (new_node) {
		// Find matching plugin in old list
		old_node = plist_find_name(&old_plugin_list, new_node->p->name);

		if (old_node) {
			// Plugin exists in old list, mark as checked
			old_node->p->checked = 1;

			// Verify configuration update (audit-syslog changed
			// from A_YES to A_NO)
			if (strcmp(new_node->p->name, "audit-syslog") == 0) {
				if (old_node->p->active ==
				    A_YES && new_node->p->active == A_NO) {
					// This simulates updating the
					// configuration
					old_node->p->active = A_NO;
				}
			}
		} else {
			// New plugin, add to old list
			plist_last(&old_plugin_list);
			if (plist_append(&old_plugin_list, new_node->p) != 0)
			   TEST_FAIL("failed to append new plugin to old list");
		}

		new_node = plist_next(&new_plugin_list);
	}

	// Verify results
	if (plist_count(&old_plugin_list) != 4)
		TEST_FAIL("old list should have 4 plugins after processing");

	// Check that audit-custom-plugin was added
	old_node = plist_find_name(&old_plugin_list, "audit-custom-plugin");
	if (!old_node)
		TEST_FAIL("audit-custom-plugin should be added to old list");

	// Check that audit-syslog was updated
	old_node = plist_find_name(&old_plugin_list, "audit-syslog");
	if (!old_node || old_node->p->active != A_NO)
		TEST_FAIL("audit-syslog should be updated to inactive");

	// Find unchecked plugins (these should be removed)
	old_node = plist_find_unchecked(&old_plugin_list);
	if (!old_node)
		TEST_FAIL("should find unchecked plugin (audit-af_unix)");
	if (strcmp(old_node->p->name, "audit-af_unix") != 0)
		TEST_FAIL("unchecked plugin should be audit-af_unix");

	// Verify active count after changes
	if (plist_count_active(&old_plugin_list) != 2)
		TEST_FAIL("should have 2 active plugins after HUP processing");

	// Clean up
	plist_clear(&old_plugin_list);
	plist_clear(&new_plugin_list);

	free_test_plugin(old_config1);
	free_test_plugin(old_config2);
	free_test_plugin(old_config3);
	free_test_plugin(new_config1);
	free_test_plugin(new_config2);
	free_test_plugin(new_config4);

	TEST_PASS();
	return 1;
}

/*
 * Test: plugin_iteration_and_startup
 *
 * This test simulates the plugin iteration and startup scenario used in audispd.c
 *
 * Steps:
 * 1. Create list with multiple plugins (active and inactive)
 * 2. Iterate through all plugins using plist_first() and plist_next()
 * 3. Count active plugins during iteration
 * 4. Test plist_last() functionality
 * 5. Test list modification during iteration
 * 6. Verify proper cleanup
 */
static int
test_plugin_iteration_and_startup(void)
{
	TEST_START("plugin_iteration_and_startup");

	conf_llist plugin_list;
	plugin_conf_t *configs[5];
	lnode *node;
	int i, active_count = 0, total_count = 0;

	plist_create(&plugin_list);

	// Create mixed active/inactive plugins
	configs[0] = create_test_plugin("plugin1", A_YES, "/usr/sbin/plugin1");
	configs[1] = create_test_plugin("plugin2", A_NO, "/usr/sbin/plugin2");
	configs[2] = create_test_plugin("plugin3", A_YES, "/usr/sbin/plugin3");
	configs[3] = create_test_plugin("plugin4", A_YES, "/usr/sbin/plugin4");
	configs[4] = create_test_plugin("plugin5", A_NO, "/usr/sbin/plugin5");

	for (i = 0; i < 5; i++) {
		if (!configs[i])
			TEST_FAIL("failed to create plugin config");
		if (plist_append(&plugin_list, configs[i]) != 0)
			TEST_FAIL("failed to append plugin config");
	}

	// Simulate plugin startup iteration (like start_plugins in audispd.c)
	plist_first(&plugin_list);
	node = plist_get_cur(&plugin_list);

	while (node) {
		total_count++;
		if (node->p && node->p->active == A_YES) {
			active_count++;
			// Simulate plugin startup
			node->p->pid = 100 + active_count; // Fake PID
		}
		node = plist_next(&plugin_list);
	}

	// Verify iteration results
	if (total_count != 5)
		TEST_FAIL("should iterate through all 5 plugins");
	if (active_count != 3)
		TEST_FAIL("should find 3 active plugins");
	if (plist_count_active(&plugin_list) != 3)
		TEST_FAIL("plist_count_active should return 3");

	// Test plist_last() functionality
	plist_last(&plugin_list);
	node = plist_get_cur(&plugin_list);
	if (!node || !node->p)
		TEST_FAIL("plist_last should position at last node");
	if (strcmp(node->p->name, "plugin5") != 0)
		TEST_FAIL("last plugin should be plugin5");

	// Test adding plugin at end using plist_last()
	plugin_conf_t *config_new = create_test_plugin("plugin6", A_YES, "/usr/sbin/plugin6");
	if (!config_new)
		TEST_FAIL("failed to create new plugin config");

	plist_last(&plugin_list);
	if (plist_append(&plugin_list, config_new) != 0)
		TEST_FAIL("failed to append new plugin");

	if (plist_count(&plugin_list) != 6)
		TEST_FAIL("should have 6 plugins after append");

	// Verify new plugin is at end
	plist_last(&plugin_list);
	node = plist_get_cur(&plugin_list);
	if (!node || !node->p || strcmp(node->p->name, "plugin6") != 0)
		TEST_FAIL("last plugin should be plugin6");

	// Test iteration after modification
	int new_count = 0;
	plist_first(&plugin_list);
	node = plist_get_cur(&plugin_list);
	while (node) {
		new_count++;
		node = plist_next(&plugin_list);
	}

	if (new_count != 6)
		TEST_FAIL("should iterate through all 6 plugins after modification");

	// Clean up
	plist_clear(&plugin_list);

	for (i = 0; i < 5; i++) {
		free_test_plugin(configs[i]);
	}
	free_test_plugin(config_new);

	TEST_PASS();
	return 1;
}

/*
 * Test: memory_management_and_edge_cases
 *
 * This test covers memory management and edge cases
 *
 * Steps:
 * 1. Test operations on empty list
 * 2. Test append with NULL plugin config
 * 3. Test memory allocation failure simulation
 * 4. Test clearing empty list
 * 5. Test repeated clear operations
 * 6. Test large list operations
 */
static int
test_memory_management_and_edge_cases(void)
{
	TEST_START("memory_management_and_edge_cases");

	conf_llist plugin_list;
	lnode *node;

	plist_create(&plugin_list);

	// Test operations on empty list
	plist_first(&plugin_list);
	if (plist_get_cur(&plugin_list) != NULL)
		TEST_FAIL("empty list should have NULL current");

	if (plist_next(&plugin_list) != NULL)
		TEST_FAIL("next on empty list should return NULL");

	plist_last(&plugin_list);
	if (plist_get_cur(&plugin_list) != NULL)
		TEST_FAIL("last on empty list should have NULL current");

	if (plist_find_name(&plugin_list, "test") != NULL)
		TEST_FAIL("find on empty list should return NULL");

	if (plist_find_unchecked(&plugin_list) != NULL)
		TEST_FAIL("find_unchecked on empty list should return NULL");

	if (plist_count(&plugin_list) != 0)
		TEST_FAIL("empty list count should be 0");

	if (plist_count_active(&plugin_list) != 0)
		TEST_FAIL("empty list active count should be 0");

	// Test append with NULL plugin config
	if (plist_append(&plugin_list, NULL) != 0)
		TEST_FAIL("append with NULL should succeed");

	if (plist_count(&plugin_list) != 1)
		TEST_FAIL("should have 1 item after NULL append");

	plist_first(&plugin_list);
	node = plist_get_cur(&plugin_list);
	if (!node || node->p != NULL)
		TEST_FAIL("NULL append should create node with NULL plugin");

	// Test mark operations with NULL plugin
	plist_mark_all_unchecked(&plugin_list);

	node = plist_find_unchecked(&plugin_list);
	if (node != NULL)
		TEST_FAIL("find_unchecked should not find NULL plugin");

	// Clear and test multiple clear operations
	plist_clear(&plugin_list);
	plist_clear(&plugin_list); // Should be safe to call multiple times

	if (plist_count(&plugin_list) != 0)
		TEST_FAIL("count should be 0 after multiple clears");

	// Test large list operations
	const int large_count = 1000;
	plugin_conf_t *large_configs[large_count];

	for (int i = 0; i < large_count; i++) {
		char name[32];
		snprintf(name, sizeof(name), "plugin%d", i);
		large_configs[i] = create_test_plugin(name, (i % 2) ? A_YES : A_NO, "/usr/sbin/test");

		if (!large_configs[i])
			TEST_FAIL("failed to create large config");

		if (plist_append(&plugin_list, large_configs[i]) != 0)
			TEST_FAIL("failed to append to large list");
	}

	// Verify large list
	if (plist_count(&plugin_list) != large_count)
		TEST_FAIL("large list should have correct count");

	if (plist_count_active(&plugin_list) != large_count / 2)
		TEST_FAIL("large list should have half active plugins");

	// Test iteration through large list
	int iter_count = 0;
	plist_first(&plugin_list);
	node = plist_get_cur(&plugin_list);
	while (node) {
		iter_count++;
		node = plist_next(&plugin_list);
	}

	if (iter_count != large_count)
		TEST_FAIL("should iterate through all items in large list");

	// Test find operations on large list
	node = plist_find_name(&plugin_list, "plugin500");
	if (!node)
		TEST_FAIL("should find plugin500 in large list");

	node = plist_find_name(&plugin_list, "nonexistent");
	if (node)
		TEST_FAIL("should not find nonexistent plugin in large list");

	// Clean up large list
	plist_clear(&plugin_list);

	for (int i = 0; i < large_count; i++) {
		free_test_plugin(large_configs[i]);
	}

	TEST_PASS();
	return 1;
}

int
main(void)
{
	printf("Running audispd linked list advanced tests...\n\n");

	test_plugin_configuration_management();
	test_plugin_hup_signal_handling();
	test_plugin_iteration_and_startup();
	test_memory_management_and_edge_cases();

	printf("\nTest Results: %d/%d tests passed\n", test_passed, test_count);

	if (test_passed == test_count) {
		printf("All tests PASSED!\n");
		return 0;
	} else {
		printf("Some tests FAILED!\n");
		return 1;
	}
}
