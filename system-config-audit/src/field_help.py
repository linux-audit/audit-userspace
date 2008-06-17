# Rule field help texts.
# coding=utf-8
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
from gettext import gettext as _

import audit

__all__ = ('field_help')

def N_(s): return s

__field_help = {
    audit.AUDIT_ARCH: N_("The CPU architecture of the syscall.  The arch can be "
                         "found using `uname -m'."),
    audit.AUDIT_ARG0: N_('The first argument to a syscall.  Note that string '
                         'arguments are not supported.  This is most likely to be '
                         'used on platforms that multiplex socket or IPC '
                         'operations.'),
    audit.AUDIT_ARG1: N_('The second argument to a syscall.  Note that string '
                         'arguments are not supported.  This is most likely to be '
                         'used on platforms that multiplex socket or IPC '
                         'operations.'),
    audit.AUDIT_ARG2: N_('The third argument to a syscall.  Note that string '
                         'arguments are not supported.  This is most likely to be '
                         'used on platforms that multiplex socket or IPC '
                         'operations.'),
    audit.AUDIT_ARG3: N_('The fourth argument to a syscall.  Note that string '
                         'arguments are not supported.  This is most likely to be '
                         'used on platforms that multiplex socket or IPC '
                         'operations.'),
    audit.AUDIT_DEVMAJOR: N_('Device major number'),
    audit.AUDIT_DEVMINOR: N_('Device minor number'),
    # audit.AUDIT_DIR is handled specially in the GUI
    audit.AUDIT_EGID: N_('Effective group ID'),
    audit.AUDIT_EUID: N_('Effective user ID'),
    audit.AUDIT_EXIT: N_('Exit value from a syscall'),
    audit.AUDIT_FILETYPE: N_("The target file's type.  Can be either file, "
                             "dir, socket, symlink, char, block, or fifo."),
    # audit.AUDIT_FILTERKEY is handled specially in the GUI
    audit.AUDIT_FSGID: N_('File system group ID'),
    audit.AUDIT_FSUID: N_('File system user ID'),
    audit.AUDIT_GID: N_('Group ID'),
    audit.AUDIT_INODE: N_('Inode number'),
    audit.AUDIT_LOGINUID: N_('ID of the user in whose login session the process '
                             'is running'),
    # audit.AUDIT_MSGTYPE has a special version of the dialog
    audit.AUDIT_OBJ_LEV_HIGH: N_("Resource's SELinux high level"),
    audit.AUDIT_OBJ_LEV_LOW: N_("Resource's SELinux low level"),
    audit.AUDIT_OBJ_ROLE: N_("Resource's SELinux role"),
    audit.AUDIT_OBJ_TYPE: N_("Resource's SELinux type"),
    audit.AUDIT_OBJ_USER: N_("Resource's SELinux user"),
    audit.AUDIT_PERM: N_('Permission filter for file operations.  '
                         'r=read, w=write, x=execute, a=attribute change.  These '
                         'permissions are not the standard file permissions, they '
                         'specify a kind of syscall. The read and write syscalls '
                         'are omitted because they would overwhelm the logs. '
                         'Instead, the open flags are looked at to see what '
                         'permission was requested.'),
    audit.AUDIT_PERS: N_('OS personality number'),
    audit.AUDIT_PID: N_('Process ID'),
    audit.AUDIT_PPID: N_("Parent's process ID"),
    audit.AUDIT_SGID: N_('Set group ID'),
    audit.AUDIT_SUBJ_CLR: N_("Program's SELinux clearance"),
    audit.AUDIT_SUBJ_ROLE: N_("Program's SELinux role"),
    audit.AUDIT_SUBJ_SEN: N_("Program's SELinux sensitivity"),
    audit.AUDIT_SUBJ_TYPE: N_("Program's SELinux type"),
    audit.AUDIT_SUBJ_USER: N_("Program's SELinux user"),
    audit.AUDIT_SUCCESS: N_('If the exit value is >= 0, this is 1, otherwise it '
                            'is 0.'),
    audit.AUDIT_SUID: N_('Set user ID'),
    audit.AUDIT_UID: N_('User ID'),
    # audit.AUDIT_WATCH is handled specially in the GUI
}

def field_help(type):
    return _(__field_help.get(type, N_('No help available')))
