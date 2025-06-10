#include "config.h"
#include <stdio.h>
#include <string.h>
#include "auditd-event.h"
#include "auditd-config.h"
#include "common.h"

#ifdef HAVE_ATOMIC
ATOMIC_INT stop = 0;
#else
volatile ATOMIC_INT stop = 0;
#endif

void update_report_timer(unsigned int interval){}

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
	cleanup_event(e);

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

