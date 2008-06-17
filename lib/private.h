/* private.h -- 
 * Copyright 2005,2006 Red Hat Inc., Durham, North Carolina.
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
 */
#ifndef _PRIVATE_H_
#define _PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PIC
# define hidden __attribute__ ((visibility ("hidden")))
# define hidden_proto(fct) __hidden_proto (fct, fct##_internal)
# define __hidden_proto(fct, internal)  \
     extern __typeof (fct) internal;    \
     extern __typeof (fct) fct __asm (#internal) hidden;
# if defined(__alpha__) || defined(__mips__)
#  define hidden_def(fct) \
     asm (".globl " #fct "\n" #fct " = " #fct "_internal");
# else
#  define hidden_def(fct) \
     asm (".globl " #fct "\n.set " #fct ", " #fct "_internal");
#endif
#else
# define hidden
# define hidden_proto(fct)
# define hidden_def(fct)
#endif

typedef enum { REAL_ERR, HIDE_IT } hide_t;

/* Internal syslog messaging */
void audit_msg(int priority, const char *fmt, ...) hidden
#ifdef __GNUC__
	__attribute__ ((format (printf, 2, 3)));
#else
	;
#endif

/* General */
extern int audit_send(int fd, int type, const void *data, unsigned int size)
	hidden;

// This is the main messaging function used internally
// Don't hide it, it used to be a part of the public API!
extern int audit_send_user_message(int fd, int type, hide_t hide_err, 
	const char *message);

// Newly deprecated
// Don't hide them, they used to be a part of the public API!
extern int  audit_request_rules_list(int fd);
extern int  audit_add_rule(int fd, struct audit_rule *rule,
				int flags, int action);
extern int  audit_delete_rule(int fd, struct audit_rule *rule,
				int flags, int action);
extern int  audit_rule_syscall(struct audit_rule *rule, int scall);
extern int  audit_rule_syscallbyname(struct audit_rule *rule,
				const char *scall);
extern int  audit_rule_fieldpair(struct audit_rule *rule, const char *pair,
				int flags);
extern void audit_rule_free(struct audit_rule *rule);

// libaudit.c
hidden_proto(audit_send_user_message);
hidden_proto(audit_request_rules_list);
hidden_proto(audit_add_rule);
hidden_proto(audit_delete_rule);
hidden_proto(audit_rule_syscall);
hidden_proto(audit_rule_syscallbyname);
hidden_proto(audit_rule_fieldpair);
hidden_proto(audit_rule_free);
hidden_proto(audit_add_watch_dir);
hidden_proto(audit_detect_machine);
hidden_proto(audit_request_status);
hidden_proto(audit_rule_syscall_data);
hidden_proto(audit_rule_syscallbyname_data);

// lookup_table.c
hidden_proto(audit_elf_to_machine);
hidden_proto(audit_machine_to_elf);
hidden_proto(audit_msg_type_to_name);
hidden_proto(audit_name_to_errno);
hidden_proto(audit_name_to_field);
hidden_proto(audit_name_to_machine);
hidden_proto(audit_name_to_msg_type);
hidden_proto(audit_name_to_syscall);
hidden_proto(audit_operator_to_symbol);
hidden_proto(audit_name_to_ftype);

// netlink.c
hidden_proto(audit_get_reply);

// FIXME delete after bumping soname number
extern int audit_log_avc(int fd, int type, const char *fmt, va_list ap); //dbus,nscd
hidden_proto(audit_log_avc)


#ifdef __cplusplus
}
#endif

#endif

