#ifndef LIBDISP_HEADERS
#define LIBDISP_HEADERS

#include <stdio.h>
#include "libaudit.h"
#include "auditd-config.h"

typedef struct event
{
	struct audit_dispatcher_header hdr;
	char data[MAX_AUDIT_MESSAGE_LENGTH];
} event_t;


int libdisp_init(const struct daemon_conf *config);
void libdisp_shutdown(void);
void libdisp_reconfigure(const struct daemon_conf *config);
void plugin_child_handler(pid_t pid);
int libdisp_enqueue(event_t *e);
int libdisp_active(void);
void libdisp_nudge_queue(void);
void libdisp_write_queue_state(FILE *f);
void libdisp_resume(void);

#endif
