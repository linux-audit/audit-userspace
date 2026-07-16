#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "auditd-event.h"
#include "auditd-config.h"
#include "common.h"
#ifdef AUDITD_LISTEN_TEST
#include "auditd-listen.h"
#include "autls.h"

void auditd_tls_test_set_transport(int value);
int auditd_tls_test_listener_count(void);
void auditd_tls_test_set_acl_table(struct autls_acl_table *table);
int auditd_tls_test_acl_check(const char *identity);
int auditd_tls_test_set_psk_state(int active, const char *identity);
void auditd_tls_test_clear(void);
#endif

#ifdef HAVE_ATOMIC
ATOMIC_INT stop = 0;
#else
volatile ATOMIC_INT stop = 0;
#endif

void update_report_timer(unsigned int interval){}

#ifdef AUDITD_LISTEN_TEST
/*
 * make_test_acl - create a single-entry ACL table for listener tests
 * @identity: identity to mark enabled
 *
 * Returns: ACL table on success, NULL on allocation failure.
 */
static struct autls_acl_table *make_test_acl(const char *identity)
{
	struct autls_acl_table *table;
	struct autls_acl_entry *entry;

	table = calloc(1, sizeof(*table));
	entry = calloc(1, sizeof(*entry));
	if (table == NULL || entry == NULL) {
		free(table);
		free(entry);
		return NULL;
	}

	entry->identity = strdup(identity);
	if (entry->identity == NULL) {
		free(entry);
		free(table);
		return NULL;
	}
	entry->identity_len = strlen(identity);
	entry->enabled = 1;
	table->entries = entry;
	table->count = 1;
	table->enabled_count = 1;
	return table;
}

/*
 * test_tls_acl_reload_preserves_old_state - reject invalid ACL reloads
 *
 * Returns: None.
 */
static void test_tls_acl_reload_preserves_old_state(void)
{
	struct daemon_conf old_conf, new_conf;
	struct autls_acl_table *table;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("/test/psk");
	old_conf.tls_allowed_clients = strdup("old-acl");
	new_conf.tls_allowed_clients = strdup("/proc/self/fd/-1");
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_allowed_clients != NULL);
	assert(new_conf.tls_allowed_clients != NULL);

	auditd_tls_test_set_transport(T_TLS);
	assert(auditd_tls_test_set_psk_state(1, NULL) == 0);
	table = make_test_acl("old-host");
	assert(table != NULL);
	auditd_tls_test_set_acl_table(table);

	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.tls_allowed_clients != NULL);
	assert(strcmp(old_conf.tls_allowed_clients, "old-acl") == 0);
	assert(auditd_tls_test_acl_check("old-host") == 1);

	free((void *)old_conf.tls_allowed_clients);
	auditd_tls_test_clear();
}

/*
 * test_tls_acl_reload_rejects_acl_only_removal - keep sole PSK auth source
 *
 * Returns: None.
 */
static void test_tls_acl_reload_rejects_acl_only_removal(void)
{
	struct daemon_conf old_conf, new_conf;
	struct autls_acl_table *table;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("/test/psk");
	old_conf.tls_allowed_clients = strdup("old-acl");
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_allowed_clients != NULL);

	auditd_tls_test_set_transport(T_TLS);
	assert(auditd_tls_test_set_psk_state(1, NULL) == 0);
	table = make_test_acl("old-host");
	assert(table != NULL);
	auditd_tls_test_set_acl_table(table);

	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.tls_allowed_clients != NULL);
	assert(strcmp(old_conf.tls_allowed_clients, "old-acl") == 0);
	assert(auditd_tls_test_acl_check("old-host") == 1);

	free((void *)old_conf.tls_allowed_clients);
	auditd_tls_test_clear();
}

/*
 * test_tls_acl_reload_allows_removal_with_identity - clear redundant ACL
 *
 * Returns: None.
 */
static void test_tls_acl_reload_allows_removal_with_identity(void)
{
	struct daemon_conf old_conf, new_conf;
	struct autls_acl_table *table;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("/test/psk");
	old_conf.tls_allowed_clients = strdup("old-acl");
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_allowed_clients != NULL);

	auditd_tls_test_set_transport(T_TLS);
	assert(auditd_tls_test_set_psk_state(1, "fallback-host") == 0);
	table = make_test_acl("old-host");
	assert(table != NULL);
	auditd_tls_test_set_acl_table(table);

	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.tls_allowed_clients == NULL);
	assert(auditd_tls_test_acl_check("old-host") == -2);

	auditd_tls_test_clear();
}

/*
 * test_tls_reconfigure_keeps_context_snapshot - retain restart-only TLS data
 *
 * Returns: None.
 */
static void test_tls_reconfigure_keeps_context_snapshot(void)
{
	struct daemon_conf old_conf, new_conf;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.transport = T_TLS;
	new_conf.transport = T_TLS;
	old_conf.tls_psk_file = strdup("old-psk");
	old_conf.tls_psk_identity = strdup("old-identity");
	old_conf.tls_cipher_suites = strdup("old-ciphers");
	old_conf.tls_key_exchange = strdup("old-groups");
	old_conf.tls_require_pqc = 1;
	old_conf.tls_crypto_profile = TLS_PROFILE_PQC;
	new_conf.tls_psk_file = strdup("new-psk");
	new_conf.tls_psk_identity = strdup("new-identity");
	new_conf.tls_cipher_suites = strdup("new-ciphers");
	new_conf.tls_key_exchange = strdup("new-groups");
	new_conf.tls_require_pqc = 0;
	new_conf.tls_crypto_profile = TLS_PROFILE_COMPATIBLE;
	assert(old_conf.tls_psk_file != NULL);
	assert(old_conf.tls_psk_identity != NULL);
	assert(old_conf.tls_cipher_suites != NULL);
	assert(old_conf.tls_key_exchange != NULL);
	assert(new_conf.tls_psk_file != NULL);
	assert(new_conf.tls_psk_identity != NULL);
	assert(new_conf.tls_cipher_suites != NULL);
	assert(new_conf.tls_key_exchange != NULL);

	auditd_tls_test_set_transport(T_TLS);
	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(strcmp(old_conf.tls_psk_file, "old-psk") == 0);
	assert(strcmp(old_conf.tls_psk_identity, "old-identity") == 0);
	assert(strcmp(old_conf.tls_cipher_suites, "old-ciphers") == 0);
	assert(strcmp(old_conf.tls_key_exchange, "old-groups") == 0);
	assert(old_conf.tls_require_pqc == 1);
	assert(old_conf.tls_crypto_profile == TLS_PROFILE_PQC);
	free((void *)old_conf.tls_psk_file);
	free((void *)old_conf.tls_psk_identity);
	free((void *)old_conf.tls_cipher_suites);
	free((void *)old_conf.tls_key_exchange);
	auditd_tls_test_clear();
}

/*
 * test_tls_init_failure_does_not_start_listener - reject invalid TLS first
 *
 * Returns: None.
 */
static void test_tls_init_failure_does_not_start_listener(void)
{
	struct daemon_conf config;
	struct ev_loop *loop;

	memset(&config, 0, sizeof(config));
	config.tcp_listen_port = 65530;
	config.tcp_listen_queue = 1;
	config.transport = T_TLS;
	config.tls_cipher_suites = "not-a-TLS-cipher";
	loop = ev_default_loop(EVFLAG_AUTO);

	assert(auditd_tcp_listen_init(loop, &config) == -1);
	assert(auditd_tls_test_listener_count() == 0);
	auditd_tls_test_clear();
}

/*
 * test_krb5_key_file_reconfigure - transfer the reloaded Kerberos key path
 *
 * Returns: None.
 */
static void test_krb5_key_file_reconfigure(void)
{
	struct daemon_conf old_conf, new_conf;
	const char *new_key_file;

	memset(&old_conf, 0, sizeof(old_conf));
	memset(&new_conf, 0, sizeof(new_conf));
	old_conf.krb5_principal = strdup("old-principal");
	old_conf.krb5_key_file = strdup("old-key-file");
	new_conf.krb5_principal = strdup("new-principal");
	new_conf.krb5_key_file = strdup("new-key-file");
	assert(old_conf.krb5_principal != NULL);
	assert(old_conf.krb5_key_file != NULL);
	assert(new_conf.krb5_principal != NULL);
	assert(new_conf.krb5_key_file != NULL);

	new_key_file = new_conf.krb5_key_file;
	auditd_tcp_listen_reconfigure(&new_conf, &old_conf);

	assert(old_conf.krb5_key_file == new_key_file);
	assert(strcmp(old_conf.krb5_key_file, "new-key-file") == 0);
	new_conf.krb5_principal = NULL;
	new_conf.krb5_key_file = NULL;
	free((void *)old_conf.krb5_principal);
	free((void *)old_conf.krb5_key_file);
}
#endif

int main(void)
{
	unsigned len_raw, len_enriched;
	struct daemon_conf conf;
	memset(&conf, 0, sizeof(conf));
	conf.daemonize = D_FOREGROUND;
	conf.log_format = LF_RAW;
	conf.node_name_format = N_NONE;
	conf.node_name = "testnode";
	conf.end_of_event_timeout = 1;

	if (init_event(&conf)) {
		fprintf(stderr, "init_event failed\n");
		return 1;
	}

	// Don't change this without adjusting offset to AUDIT_INTERP_SEPARATOR
	const char *msg = "audit(1170021493.5:100): pid=2000 uid=2 auid=-1 gid=2 ses=-1 msg=\'op=test\'\n";
	struct auditd_event *e;

	e = create_event(NULL, NULL, NULL, 0);
	if (!e)
		return 1;
	e->reply.type = AUDIT_TRUSTED_APP;
	e->reply.message = strdup(msg);
	e->reply.len = strlen(msg);
	format_event(e);
	len_raw = strlen(e->reply.message);
	printf("RAW: %s\n", e->reply.message);
	cleanup_event(e);

	conf.log_format = LF_ENRICHED;
	e = create_event(NULL, NULL, NULL, 0);
	if (!e)
		return 1;
	e->reply.type = AUDIT_TRUSTED_APP;
	e->reply.message = strdup(msg);
	e->reply.len = strlen(msg);
	format_event(e);
	len_enriched = strlen(e->reply.message);
	printf("ENRICHED: %s\n", e->reply.message);

	//shutdown_events();
	if (len_enriched <= len_raw) {
		printf("enriched length should be larger that raw length\n"
		       "    raw length = %u, enriched length = %u\n", len_raw,
			len_enriched);
		return 1;
	}
	if (e->reply.message[95] != AUDIT_INTERP_SEPARATOR) {
		puts("missing AUDIT_INTERP_SEPARATOR");
		printf("char 95: 0x%X\n", e->reply.message[95]);
		return 1;
	}
	if (!strstr(&(e->reply.message[95]), "AUID")) {
		puts("missing AUID interpretation");
		return 1;
	}
	cleanup_event(e);
#ifdef AUDITD_LISTEN_TEST
	test_tls_acl_reload_preserves_old_state();
	test_tls_acl_reload_rejects_acl_only_removal();
	test_tls_acl_reload_allows_removal_with_identity();
	test_tls_reconfigure_keeps_context_snapshot();
	test_tls_init_failure_does_not_start_listener();
	test_krb5_key_file_reconfigure();
#endif
	return 0;
}

// Needed only for linking
int send_audit_event(int type, const char *str)
{
	return 0;
}

// Needed only for linking
void distribute_event(struct auditd_event *e)
{
}
