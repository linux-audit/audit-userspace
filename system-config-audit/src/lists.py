# Lists of possible ID values.
#
# Copyright (C) 2007 Red Hat, Inc.  All rights reserved.
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program; if
# not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Red Hat Author: Miloslav Trmac <mitr@redhat.com>
import stat

import audit

__all__ = ('field_vars',
           'ids_to_names', 'ids_severities', 'ids_types',
           'machines', 'machine_names', 'event_types', 'event_type_names',
           'sorted_machine_names', 'sorted_event_type_names',
           'sorted_file_type_names', 'syscalls')

def N_(s): return s

# FIXME: these lists should be available from libaudit

# sed -n '/AUDIT_NEGATE/d; /Rule fields/,/These are the supported operators/s/^#define[ \t]*\([^ \t]*\)[ \t].*$/audit.\1,/p' < /usr/include/linux/audit.h
field_vars = (
audit.AUDIT_PID,
audit.AUDIT_UID,
audit.AUDIT_EUID,
audit.AUDIT_SUID,
audit.AUDIT_FSUID,
audit.AUDIT_GID,
audit.AUDIT_EGID,
audit.AUDIT_SGID,
audit.AUDIT_FSGID,
audit.AUDIT_LOGINUID,
audit.AUDIT_PERS,
audit.AUDIT_ARCH,
audit.AUDIT_MSGTYPE,
audit.AUDIT_SUBJ_USER,
audit.AUDIT_SUBJ_ROLE,
audit.AUDIT_SUBJ_TYPE,
audit.AUDIT_SUBJ_SEN,
audit.AUDIT_SUBJ_CLR,
audit.AUDIT_PPID,
audit.AUDIT_OBJ_USER,
audit.AUDIT_OBJ_ROLE,
audit.AUDIT_OBJ_TYPE,
audit.AUDIT_OBJ_LEV_LOW,
audit.AUDIT_OBJ_LEV_HIGH,
audit.AUDIT_DEVMAJOR,
audit.AUDIT_DEVMINOR,
audit.AUDIT_INODE,
audit.AUDIT_EXIT,
audit.AUDIT_SUCCESS,
audit.AUDIT_WATCH,
audit.AUDIT_PERM,
audit.AUDIT_DIR,
audit.AUDIT_FILETYPE,
audit.AUDIT_ARG0,
audit.AUDIT_ARG1,
audit.AUDIT_ARG2,
audit.AUDIT_ARG3,
audit.AUDIT_FILTERKEY,
)

# sed -n '/S_IFMT/d; s/^# *define[ \t]*\(S_IF[^ \t]*\)[ \t].*$/stat.\1,/p' /usr/include/sys/stat.h
file_types = (
stat.S_IFDIR,
stat.S_IFCHR,
stat.S_IFBLK,
stat.S_IFREG,
stat.S_IFIFO,
stat.S_IFLNK,
stat.S_IFSOCK,
)

# sed -n '/machine type list/,/machine_t/s/^[ \t]*\(MACH_[^,=]*\)\([,=].*\)\?$/audit.\1,/p' /usr/include/libaudit.h
machines = (
audit.MACH_X86,
audit.MACH_86_64,
audit.MACH_IA64,
audit.MACH_PPC64,
audit.MACH_PPC,
audit.MACH_S390X,
audit.MACH_S390,
audit.MACH_ALPHA,
)

# sed -n '/AUDIT_USER/,/AUDIT_KERNEL[^_]/s/^#define[ \t]*\([^ \t]*\)[ \t].*$/audit.\1,/p' /usr/include/linux/audit.h
event_types = (
audit.AUDIT_USER,
audit.AUDIT_LOGIN,
audit.AUDIT_WATCH_INS,
audit.AUDIT_WATCH_REM,
audit.AUDIT_WATCH_LIST,
audit.AUDIT_SIGNAL_INFO,
audit.AUDIT_ADD_RULE,
audit.AUDIT_DEL_RULE,
audit.AUDIT_LIST_RULES,
audit.AUDIT_TRIM,
audit.AUDIT_MAKE_EQUIV,
audit.AUDIT_TTY_GET,
audit.AUDIT_TTY_SET,
audit.AUDIT_FIRST_USER_MSG,
audit.AUDIT_USER_AVC,
audit.AUDIT_USER_TTY,
audit.AUDIT_LAST_USER_MSG,
audit.AUDIT_FIRST_USER_MSG2,
audit.AUDIT_LAST_USER_MSG2,
audit.AUDIT_DAEMON_START,
audit.AUDIT_DAEMON_END,
audit.AUDIT_DAEMON_ABORT,
audit.AUDIT_DAEMON_CONFIG,
audit.AUDIT_SYSCALL,
audit.AUDIT_PATH,
audit.AUDIT_IPC,
audit.AUDIT_SOCKETCALL,
audit.AUDIT_CONFIG_CHANGE,
audit.AUDIT_SOCKADDR,
audit.AUDIT_CWD,
audit.AUDIT_EXECVE,
audit.AUDIT_IPC_SET_PERM,
audit.AUDIT_MQ_OPEN,
audit.AUDIT_MQ_SENDRECV,
audit.AUDIT_MQ_NOTIFY,
audit.AUDIT_MQ_GETSETATTR,
audit.AUDIT_KERNEL_OTHER,
audit.AUDIT_FD_PAIR,
audit.AUDIT_OBJ_PID,
audit.AUDIT_TTY,
audit.AUDIT_EOE,
audit.AUDIT_AVC,
audit.AUDIT_SELINUX_ERR,
audit.AUDIT_AVC_PATH,
audit.AUDIT_MAC_POLICY_LOAD,
audit.AUDIT_MAC_STATUS,
audit.AUDIT_MAC_CONFIG_CHANGE,
audit.AUDIT_MAC_UNLBL_ALLOW,
audit.AUDIT_MAC_CIPSOV4_ADD,
audit.AUDIT_MAC_CIPSOV4_DEL,
audit.AUDIT_MAC_MAP_ADD,
audit.AUDIT_MAC_MAP_DEL,
audit.AUDIT_MAC_IPSEC_ADDSA,
audit.AUDIT_MAC_IPSEC_DELSA,
audit.AUDIT_MAC_IPSEC_ADDSPD,
audit.AUDIT_MAC_IPSEC_DELSPD,
audit.AUDIT_MAC_IPSEC_EVENT,
audit.AUDIT_MAC_UNLBL_STCADD,
audit.AUDIT_MAC_UNLBL_STCDEL,
audit.AUDIT_FIRST_KERN_ANOM_MSG,
audit.AUDIT_LAST_KERN_ANOM_MSG,
audit.AUDIT_ANOM_PROMISCUOUS,
audit.AUDIT_ANOM_ABEND,
audit.AUDIT_KERNEL,
)

# From code in src/auditctl.c
ids_severities = (('inf', N_('Information only')),
                  ('low', N_('Low')),
                  ('med', N_('Medium')),
                  ('hi', N_('High')))
# From code in src/auditctl.c
ids_types = (('file', N_('File watch')),
             ('exec', N_('Execution watch')),
             ('mkexe', N_('Executable created')))

# Just a wildest possible guess.  This is flexible enough to handle all machine
# types.
syscalls = range(audit.AUDIT_BITMASK_SIZE * 32)

def ids_to_names(ids, fn):
    '''Convert a list of IDs to their string representations using fn.

    fn may return None, ignore the ID in that case.

    '''
    possible_names = (fn(i) for i in ids)
    return [name for name in possible_names if name is not None]

file_type_names = ids_to_names(file_types, audit.audit_ftype_to_name)
event_type_names = ids_to_names(event_types, audit.audit_msg_type_to_name)
machine_names = ids_to_names(machines, audit.audit_machine_to_name)

sorted_event_type_names = sorted(event_type_names)
sorted_file_type_names = sorted(file_type_names)
sorted_machine_names = sorted(machine_names)
