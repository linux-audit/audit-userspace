/* libaudit.h --
 * Copyright 2004-2018,2021-23 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *	Steve Grubb <sgrubb@redhat.com>
 *	Rickard E. (Rik) Faith <faith@redhat.com>
 */
#ifndef _LIBAUDIT_H_
#define _LIBAUDIT_H_

#include <asm/types.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/audit.h>
#include <stdarg.h>
#include <syslog.h>
// The following macros originate in sys/cdefs.h
// gcc-analyzer notation
// Define buffer access modes
#ifndef __attr_access
#  define __attr_access(x)
#endif
// Warn unused result
#ifndef __wur
# define __wur
#endif

#include <audit_logging.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Audit message type classification of the 5.0 kernel:
 * 1000 - 1099 are for commanding the audit system
 * 1100 - 1199 user space trusted application messages
 * 1200 - 1299 messages internal to the audit daemon
 * 1300 - 1399 audit event messages
 * 1400 - 1499 kernel SE Linux use
 * 1500 - 1599 AppArmor events
 * 1600 - 1699 kernel crypto events
 * 1700 - 1799 kernel anomaly records
 * 1800 - 1899 kernel integrity labels and related events
 * 1800 - 1999 future kernel use
 * 2001 - 2099 unused (kernel)
 * 2100 - 2199 user space anomaly records
 * 2200 - 2299 user space actions taken in response to anomalies
 * 2300 - 2399 user space generated LSPP events
 * 2400 - 2499 user space crypto events
 * 2500 - 2599 user space virtualization management events
 * 2600 - 2999 future user space (maybe integrity labels and related events)
 *
 *
 * NOTE: as of the audit-4.0 release, all of the audit record type
 * definitions have moved to the audit-records.h header file
 *
 */

/* This is related to the filterkey patch */
#define AUDIT_KEY_SEPARATOR 0x01

/* These are used in filter control */
#ifndef AUDIT_FILTER_URING_EXIT
#define AUDIT_FILTER_URING_EXIT 0x07 /* Apply rule at io_uring op exit */
#endif

#ifndef AUDIT_FILTER_EXCLUDE
#define AUDIT_FILTER_EXCLUDE	AUDIT_FILTER_TYPE
#endif

#define AUDIT_FILTER_MASK	0x07	/* Mask to get actual filter */
#define AUDIT_FILTER_UNSET	0x80	/* This value means filter is unset */

/* This is the character that separates event data from enrichment fields */
#define AUDIT_INTERP_SEPARATOR 0x1D

//////////////////////////////////////////////////////
// This is an external ABI. Any changes in here will
// likely affect pam_loginuid. There might be other
// apps that use this low level interface, but I don't
// know of any.
//
/* data structure for who signaled the audit daemon */
struct audit_sig_info {
        uid_t           uid;
        pid_t           pid;
	char		ctx[0];
};

/* defines for audit subsystem */
#define MAX_AUDIT_MESSAGE_LENGTH    8970 // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1
struct audit_message {
	struct nlmsghdr nlh;
	char   data[MAX_AUDIT_MESSAGE_LENGTH];
};

// internal - forward declaration
struct daemon_conf;

struct audit_reply {
	int                      type;
	int                      len;
	struct nlmsghdr         *nlh;
	struct audit_message     msg;

	/* Using a union to compress this structure since only one of
	 * the following should be valid for any packet. */
	union {
	struct audit_status     *status;
	struct audit_rule_data  *ruledata;
	struct audit_login      *login;
	char                    *message;
	struct nlmsgerr         *error;
	struct audit_sig_info   *signal_info;
	struct daemon_conf      *conf;
#ifdef AUDIT_FEATURE_VERSION
	struct audit_features	*features;
#endif
	};
};

//
// End of ABI control
//////////////////////////////////////////////////////

//////////////////////////////////////////////////////
// audit dispatcher interface
//
/* audit_dispatcher_header: This header is versioned. If anything gets
 * added to it, it must go at the end and the version number bumped.
 * This MUST BE fixed size for compatibility. If you are going to add
 * new member then add them into _structure_ part.
 */
struct audit_dispatcher_header {
	uint32_t	ver;	/* The version of this protocol */
	uint32_t	hlen;	/* Header length */
	uint32_t	type;	/* Message type */
	uint32_t	size;	/* Size of data following the header */
};

// Original protocol starts with msg='
#define AUDISP_PROTOCOL_VER  0

// Starts with node and/or type already in the text before msg=
// IOW, its preformatted in the audit daemon.
#define AUDISP_PROTOCOL_VER2 1


///////////////////////////////////////////////////
// Libaudit API
//

/* This is the machine type list */
typedef enum {
	MACH_X86=0,
	MACH_86_64,
	MACH_IA64,	// Deprecated but has to stay
	MACH_PPC64,
	MACH_PPC,
	MACH_S390X,
	MACH_S390,
	MACH_ALPHA,	// Deprecated but has to stay
	MACH_ARM,
	MACH_AARCH64,
	MACH_PPC64LE,
	MACH_IO_URING
} machine_t;

/* These are the valid audit failure tunable enum values */
typedef enum {
	FAIL_IGNORE=0,
	FAIL_LOG,
	FAIL_TERMINATE
} auditfail_t;

/* Messages */
typedef enum { MSG_STDERR, MSG_SYSLOG, MSG_QUIET } message_t;
typedef enum { DBG_NO, DBG_YES } debug_message_t;
void set_aumessage_mode(message_t mode, debug_message_t debug);

/* General */
typedef enum { GET_REPLY_BLOCKING=0, GET_REPLY_NONBLOCKING } reply_t;
int  audit_get_reply(int fd, struct audit_reply *rep, reply_t block,
	int peek) __wur;
uid_t audit_getloginuid(void);
int  audit_setloginuid(uid_t uid) __wur;
uint32_t audit_get_session(void);
int  audit_detect_machine(void);
int audit_determine_machine(const char *arch);
char *audit_format_signal_info(char *buf, int len, const char *op,
			const struct audit_reply *rep, const char *res)
			__attr_access ((__write_only__, 1, 2));

/* Translation functions */
int        audit_name_to_field(const char *field);
const char *audit_field_to_name(int field);
int        audit_name_to_syscall(const char *sc, int machine);
const char *audit_syscall_to_name(int sc, int machine);
const char *audit_uringop_to_name(int uringop);
int        audit_name_to_uringop(const char *uringop);
int        audit_name_to_flag(const char *flag);
const char *audit_flag_to_name(int flag);
int        audit_name_to_action(const char *action);
const char *audit_action_to_name(int action);
int        audit_name_to_msg_type(const char *msg_type);
const char *audit_msg_type_to_name(int msg_type);
int        audit_name_to_machine(const char *machine);
const char *audit_machine_to_name(int machine);
unsigned int audit_machine_to_elf(int machine);
int          audit_elf_to_machine(unsigned int elf);
const char *audit_operator_to_symbol(int op);
int        audit_name_to_errno(const char *error);
const char *audit_errno_to_name(int error);
int        audit_name_to_ftype(const char *name);
const char *audit_ftype_to_name(int ftype);
int        audit_name_to_fstype(const char *name);
const char *audit_fstype_to_name(int fstype);
void audit_number_to_errmsg(int errnumber, const char *opt);

/* AUDIT_GET */
int audit_request_status(int fd);
int audit_is_enabled(int fd);
int get_auditfail_action(auditfail_t *failmode);
int audit_request_features(int fd);
uint32_t audit_get_features(void);

/* AUDIT_SET */
typedef enum { WAIT_NO, WAIT_YES } rep_wait_t;
int  audit_set_pid(int fd, uint32_t pid, rep_wait_t wmode) __wur;
int  audit_set_enabled(int fd, uint32_t enabled) __wur;
int  audit_set_failure(int fd, uint32_t failure) __wur;
int  audit_set_rate_limit(int fd, uint32_t limit);
int  audit_set_backlog_limit(int fd, uint32_t limit);
int  audit_set_backlog_wait_time(int fd, uint32_t bwt);
int  audit_reset_lost(int fd);
int  audit_reset_backlog_wait_time_actual(int fd);
int  audit_set_feature(int fd, unsigned feature, unsigned value,
		      unsigned lock) __wur;
int  audit_set_loginuid_immutable(int fd) __wur;

/* AUDIT_LIST_RULES */
int  audit_request_rules_list_data(int fd);

/* SIGNAL_INFO */
int audit_request_signal_info(int fd);

/* AUDIT_WATCH */
int audit_update_watch_perms(struct audit_rule_data *rule, int perms);
int audit_add_watch(struct audit_rule_data **rulep, const char *path);
int audit_add_watch_dir(int type, struct audit_rule_data **rulep,
				const char *path);
int audit_trim_subtrees(int fd);
int audit_make_equivalent(int fd, const char *mount_point,
				const char *subtree);

/* AUDIT_ADD_RULE */
int audit_add_rule_data(int fd, struct audit_rule_data *rule,
                               int flags, int action);

/* AUDIT_DEL_RULE */
int audit_delete_rule_data(int fd, struct audit_rule_data *rule,
                                  int flags, int action);

/* Rule-building helper functions */
/* Heap-allocates and initializes an audit_rule_data */
struct audit_rule_data *audit_rule_create_data(void);
/* Initializes an existing audit_rule_data struct */
void audit_rule_init_data(struct audit_rule_data *rule);
int audit_rule_syscallbyname_data(struct audit_rule_data *rule,
                                          const char *scall);
int audit_rule_io_uringbyname_data(struct audit_rule_data *rule,
                                          const char *scall);

/* Note that the following function takes a **, where audit_rule_fieldpair()
 * takes just a *.  That structure may need to be reallocated as a result of
 * adding new fields */
int audit_rule_fieldpair_data(struct audit_rule_data **rulep,
                                      const char *pair, int flags);
int audit_rule_interfield_comp_data(struct audit_rule_data **rulep,
					 const char *pair, int flags);
/* Deallocates the audit_rule_rule object, and any associated resources */
void audit_rule_free_data(struct audit_rule_data *rule);

/* Capability testing functions */
int audit_can_control(void);
int audit_can_write(void);
int audit_can_read(void);

#ifdef __cplusplus
}
#endif

#endif
