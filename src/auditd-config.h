/* auditd-config.h -- 
 * Copyright 2004-2009,2014,2016,2018 Red Hat Inc.
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
 *   Steve Grubb <sgrubb@redhat.com>
 */

#ifndef AUDITD_CONFIG_H
#define AUDITD_CONFIG_H

#include "libaudit.h"
#include <grp.h>
#define CONFIG_FILE "/etc/audit/auditd.conf"
#define MEGABYTE 1048576UL

// Define user space end of event timeout default (in seconds)
#define	EOE_TIMEOUT	2L

typedef enum { D_FOREGROUND, D_BACKGROUND } daemon_t;
typedef enum { LF_RAW, LF_NOLOG, LF_ENRICHED } logging_formats;
typedef enum { FT_NONE, FT_INCREMENTAL, FT_INCREMENTAL_ASYNC, FT_DATA, FT_SYNC } flush_technique;
typedef enum { FA_IGNORE, FA_SYSLOG, FA_ROTATE, FA_EMAIL, FA_EXEC, FA_SUSPEND,
		FA_SINGLE, FA_HALT } failure_action_t;
typedef enum { SZ_IGNORE, SZ_SYSLOG, SZ_SUSPEND, SZ_ROTATE, 
		SZ_KEEP_LOGS } size_action;
typedef enum { TEST_AUDITD, TEST_SEARCH } log_test_t;
typedef enum { N_NONE, N_HOSTNAME, N_FQD, N_NUMERIC, N_USER } node_t;
typedef enum { O_IGNORE, O_SYSLOG, O_SUSPEND, O_SINGLE,
		O_HALT } overflow_action_t;
typedef enum { T_TCP, T_TLS, T_KRB5, T_LABELED } transport_t;

struct daemon_conf
{
	daemon_t daemonize;
	unsigned int local_events;
	uid_t sender_uid;	/* the uid for sender of sighup */
	pid_t sender_pid;	/* the pid for sender of sighup */
	const char *sender_ctx;	/* the context for the sender of sighup */
	unsigned int write_logs;
	const char *log_file;
	logging_formats log_format;
	gid_t log_group;
	unsigned int priority_boost;
	flush_technique flush;
	unsigned int freq;
	unsigned int num_logs;
	node_t node_name_format;
	const char *node_name;
	unsigned long max_log_size;
	size_action max_log_size_action;
	unsigned long space_left;
	unsigned int space_left_percent;
	failure_action_t space_left_action;
	const char *space_left_exe;
	const char *action_mail_acct;
	unsigned int verify_email;
	unsigned long admin_space_left;
	unsigned int admin_space_left_percent;
	failure_action_t admin_space_left_action;
	const char *admin_space_left_exe;
	failure_action_t disk_full_action;
	const char *disk_full_exe;
	failure_action_t disk_error_action;
	const char *disk_error_exe;
	unsigned long tcp_listen_port;
	unsigned long tcp_listen_queue;
	unsigned long tcp_max_per_addr;
	int use_libwrap;
	unsigned long tcp_client_min_port;
	unsigned long tcp_client_max_port;
	unsigned long tcp_client_max_idle;
	int transport;
	const char *krb5_principal;
	const char *krb5_key_file;
	int distribute_network_events;
	// Dispatcher config
	unsigned int q_depth;
	overflow_action_t overflow_action;
	unsigned int max_restarts;
	char *plugin_dir;
	const char *config_dir;
        // Userspace configuration items
        unsigned long end_of_event_timeout;
};

void set_allow_links(int allow);
int set_config_dir(const char *val);

int load_config(struct daemon_conf *config, log_test_t lt);
void clear_config(struct daemon_conf *config);
const char *audit_lookup_format(int fmt);
int create_log_file(const char *val);
int resolve_node(struct daemon_conf *config);
void setup_percentages(struct daemon_conf *config, int fd);

void init_config_manager(void);
#ifdef AUDITD_EVENT_H
int start_config_manager(struct auditd_event *e);
#endif
void free_config(struct daemon_conf *config);

#endif
