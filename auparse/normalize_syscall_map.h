/*
 * normalize_syscall_map.h
 * Copyright (c) 2016-17 Red Hat Inc., Durham, North Carolina.
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
#include "normalize-internal.h"

_S(NORM_FILE_STAT, "access")
_S(NORM_FILE_STAT, "faccessat")
_S(NORM_FILE_CHATTR, "chmod")
_S(NORM_FILE_CHATTR, "fchmod")
_S(NORM_FILE_CHATTR, "fchmodat")
_S(NORM_FILE_CHATTR, "chown")
_S(NORM_FILE_CHATTR, "fchown")
_S(NORM_FILE_CHATTR, "fchownat")
_S(NORM_FILE_CHATTR, "lchown")
_S(NORM_FILE_LDMOD, "finit_module")
_S(NORM_FILE_LDMOD, "init_module")
_S(NORM_FILE_UNLDMOD, "delete_module")
_S(NORM_FILE_CHATTR, "setxattr")
_S(NORM_FILE_CHATTR, "fsetxattr")
_S(NORM_FILE_CHATTR, "lsetxattr")
_S(NORM_FILE_DIR, "mkdir")
_S(NORM_FILE_DIR, "mkdirat")
_S(NORM_FILE_MOUNT, "mount")
_S(NORM_FILE_STAT, "newfstatat")
_S(NORM_FILE_STAT, "stat")
_S(NORM_FILE_STAT, "fstat")
_S(NORM_FILE_STAT, "lstat")
_S(NORM_FILE_STAT, "stat64")
_S(NORM_FILE_SYS_STAT, "statfs")
_S(NORM_FILE_SYS_STAT, "fstatfs")
_S(NORM_FILE, "creat")
_S(NORM_FILE, "open")
_S(NORM_FILE, "openat")
_S(NORM_FILE, "readlink")
_S(NORM_FILE, "readlinkat")
_S(NORM_FILE_CHATTR, "removexattr")
_S(NORM_FILE_CHATTR, "fremovexattr")
_S(NORM_FILE_CHATTR, "lremovexattr")
_S(NORM_FILE_RENAME, "rename")
_S(NORM_FILE_RENAME, "renameat")
_S(NORM_FILE_RENAME, "renameat2")
_S(NORM_FILE_DEL, "rmdir")
_S(NORM_FILE_LNK, "symlink")
_S(NORM_FILE_LNK, "symlinkat")
_S(NORM_FILE_UMNT, "umount2")
_S(NORM_FILE_DEL, "unlink")
_S(NORM_FILE_DEL, "unlinkat")
_S(NORM_FILE_TIME, "utime")
_S(NORM_FILE_TIME, "utimes")
_S(NORM_FILE_TIME, "futimesat")
_S(NORM_FILE_TIME, "futimens")
_S(NORM_FILE_TIME, "utimensat")
_S(NORM_EXEC, "execve")
_S(NORM_EXEC, "execveat")
_S(NORM_SOCKET_ACCEPT, "accept")
_S(NORM_SOCKET_ACCEPT, "accept4")
_S(NORM_SOCKET_BIND, "bind")
_S(NORM_SOCKET_CONN, "connect")
_S(NORM_SOCKET_RECV, "recvfrom")
_S(NORM_SOCKET_RECV, "recvmsg")
_S(NORM_SOCKET_SEND, "sendmsg")
_S(NORM_SOCKET_SEND, "sendto")
_S(NORM_PID, "kill")
_S(NORM_PID, "tkill")
_S(NORM_PID, "tgkill")
_S(NORM_UID, "setuid")
_S(NORM_UID, "seteuid")
_S(NORM_UID, "setfsuid")
_S(NORM_UID, "setreuid")
_S(NORM_UID, "setresuid")
_S(NORM_GID, "setgid")
_S(NORM_GID, "setegid")
_S(NORM_GID, "setfsgid")
_S(NORM_GID, "setregid")
_S(NORM_GID, "setresgid")
_S(NORM_SYSTEM_TIME, "settimeofday")
_S(NORM_SYSTEM_TIME, "clock_settime")
_S(NORM_SYSTEM_TIME, "stime")
_S(NORM_SYSTEM_TIME, "adjtimex")
_S(NORM_MAKE_DEV, "mknod")
_S(NORM_MAKE_DEV, "mknodat")
_S(NORM_SYSTEM_NAME, "sethostname")
_S(NORM_SYSTEM_NAME, "setdomainname")

