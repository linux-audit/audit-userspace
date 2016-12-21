/*
 * classify_syscall_map.h
 * Copyright (c) 2016 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This software may be freely redistributed and/or modified under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 */
#include "classify-internal.h"

_S(CLASS_FILE_STAT, "access")
_S(CLASS_FILE_STAT, "faccessat")
_S(CLASS_FILE_CHATTR, "chmod")
_S(CLASS_FILE_CHATTR, "fchmod")
_S(CLASS_FILE_CHATTR, "fchmodat")
_S(CLASS_FILE_CHATTR, "chown")
_S(CLASS_FILE_CHATTR, "fchown")
_S(CLASS_FILE_CHATTR, "fchownat")
_S(CLASS_FILE_CHATTR, "lchown")
_S(CLASS_FILE_LDMOD, "finit_module")
_S(CLASS_FILE_LDMOD, "init_module")
_S(CLASS_FILE_UNLDMOD, "delete_module")
_S(CLASS_FILE_CHATTR, "setxattr")
_S(CLASS_FILE_CHATTR, "fsetxattr")
_S(CLASS_FILE_CHATTR, "lsetxattr")
_S(CLASS_FILE_DIR, "mkdir")
_S(CLASS_FILE_DIR, "mkdirat")
_S(CLASS_FILE_MOUNT, "mount")
_S(CLASS_FILE_STAT, "newfstatat")
_S(CLASS_FILE_STAT, "stat")
_S(CLASS_FILE_STAT, "fstat")
_S(CLASS_FILE_STAT, "lstat")
_S(CLASS_FILE_STAT, "stat64")
_S(CLASS_FILE_STAT, "statfs")
_S(CLASS_FILE_STAT, "fstatfs")
_S(CLASS_FILE, "creat")
_S(CLASS_FILE, "open")
_S(CLASS_FILE, "openat")
_S(CLASS_FILE, "readlink")
_S(CLASS_FILE, "readlinkat")
_S(CLASS_FILE_CHATTR, "removexattr")
_S(CLASS_FILE_CHATTR, "fremovexattr")
_S(CLASS_FILE_CHATTR, "lremovexattr")
_S(CLASS_FILE_RENAME, "rename")
_S(CLASS_FILE_RENAME, "renameat")
_S(CLASS_FILE_RENAME, "renameat2")
_S(CLASS_FILE_DEL, "rmdir")
_S(CLASS_FILE_LNK, "symlink")
_S(CLASS_FILE_LNK, "symlinkat")
_S(CLASS_FILE_UMNT, "umount2")
_S(CLASS_FILE_DEL, "unlink")
_S(CLASS_FILE_DEL, "unlinkat")
_S(CLASS_FILE_TIME, "utime")
_S(CLASS_FILE_TIME, "utimes")
_S(CLASS_FILE_TIME, "futimesat")
_S(CLASS_FILE_TIME, "futimens")
_S(CLASS_FILE_TIME, "utimensat")
_S(CLASS_EXEC, "execve")
_S(CLASS_EXEC, "execveat")
_S(CLASS_SOCKET_ACCEPT, "accept")
_S(CLASS_SOCKET_ACCEPT, "accept4")
_S(CLASS_SOCKET_BIND, "bind")
_S(CLASS_SOCKET_CONN, "connect")
_S(CLASS_SOCKET_RECV, "recvfrom")
_S(CLASS_SOCKET_RECV, "recvmsg")
_S(CLASS_SOCKET_SEND, "sendmsg")
_S(CLASS_SOCKET_SEND, "sendto")
_S(CLASS_PID, "kill")
_S(CLASS_PID, "tkill")
_S(CLASS_PID, "tgkill")
_S(CLASS_UID, "setuid")
_S(CLASS_UID, "seteuid")
_S(CLASS_UID, "setfsuid")
_S(CLASS_UID, "setreuid")
_S(CLASS_UID, "setresuid")
_S(CLASS_GID, "setgid")
_S(CLASS_GID, "setegid")
_S(CLASS_GID, "setfsgid")
_S(CLASS_GID, "setregid")
_S(CLASS_GID, "setresgid")
_S(CLASS_SYSTEM_TIME, "settimeofday")
_S(CLASS_SYSTEM_TIME, "clock_settime")
_S(CLASS_SYSTEM_TIME, "stime")
_S(CLASS_SYSTEM_TIME, "adjtimex")
_S(CLASS_MAKE_DEV, "mknod")
_S(CLASS_MAKE_DEV, "mknodat")
_S(CLASS_SYSTEM_NAME, "sethostname")
_S(CLASS_SYSTEM_NAME, "setdomainname")

