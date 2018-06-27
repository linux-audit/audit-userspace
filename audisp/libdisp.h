#ifndef LIBDISP_HEADERS
#define LIBDISP_HEADERS

#include "libaudit.h"

typedef struct event
{
	struct audit_dispatcher_header hdr;
	char data[MAX_AUDIT_MESSAGE_LENGTH];
} event_t;


int libdisp_init(const char *config_dir);
void libdisp_shutdown(void);
void libdisp_reconfigure(const char *config_dir);
void plugin_child_handler(pid_t pid);
int libdisp_enqueue(event_t *e);
int libdisp_active(void);
void libdisp_nudge_queue(void);

#endif
