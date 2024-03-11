/* permtab.h --
 * Copyright 2023 Red Hat Inc.
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
 * License along with this library; see the file COPYING.lib. If not, write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 *
 * Source of info: include/asm-generic/audit_*.h
 *                 arch/x86/kernel/audit_64.c
 *
 */

_S(AUDIT_PERM_EXEC, "execve")
_S(AUDIT_PERM_WRITE, "rename,mkdir,rmdir,creat,link,unlink,symlink,mknod,mkdirat,mknodat,unlinkat,renameat,linkat,symlinkat,renameat2,acct,swapon,quotactl,truncate,ftruncate,bind,fallocate,open,openat,openat2")
_S(AUDIT_PERM_READ, "readlink,quotactl,listxattr,llistxattr,flistxattr,getxattr,lgetxattr,fgetxattr,readlinkat,open,openat,openat2")
_S(AUDIT_PERM_ATTR, "chmod,fchmod,chown,lchown,fchown,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,fchownat,fchmodat,link,linkat")

