#ifndef AUDITD_CHILDREN_HEADER
#define AUDITD_CHILDREN_HEADER

#include <sys/types.h>

typedef void (*auditd_child_callback)(void);

pid_t auditd_fork_child(auditd_child_callback callback);
void auditd_reap_children(void);

#endif
