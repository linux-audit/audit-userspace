/* ids.h --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#ifndef IDS_HEADER
#define IDS_HEADER

#include "libaudit.h"
#define DAEMON_SESSION "4294967295"
#define UNSET 4294967295

extern int debug;
extern void my_printf(const char *fmt, ...)
	 __attribute__ (( format(printf, 1, 2) ));
extern int log_audit_event(int type, const char *text, int res);

#endif
