/* clone-flagtab.h --
 * Copyright 2007,2012-23 Red Hat Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330ULL, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 * Location: include/uapi/linux/sched.h
 */

_S(0x000000100ULL,	"CLONE_VM" )
_S(0x000000200ULL,	"CLONE_FS" )
_S(0x000000400ULL,	"CLONE_FILES" )
_S(0x000000800ULL,	"CLONE_SIGHAND" )
_S(0x000002000ULL,	"CLONE_PTRACE" )
_S(0x000004000ULL,	"CLONE_VFORK" )
_S(0x000008000ULL,	"CLONE_PARENT" )
_S(0x000010000ULL,	"CLONE_THREAD" )
_S(0x000020000ULL,	"CLONE_NEWNS" )
_S(0x000040000ULL,	"CLONE_SYSVSEM" )
_S(0x000080000ULL,	"CLONE_SETTLS" )
_S(0x000100000ULL,	"CLONE_PARENT_SETTID" )
_S(0x000200000ULL,	"CLONE_CHILD_CLEARTID" )
_S(0x000400000ULL,	"CLONE_DETACHED" )
_S(0x000800000ULL,	"CLONE_UNTRACED" )
_S(0x001000000ULL,	"CLONE_CHILD_SETTID" )
_S(0x002000000ULL,	"CLONE_STOPPED" )
_S(0x004000000ULL,	"CLONE_NEWUTS" )
_S(0x008000000ULL,	"CLONE_NEWIPC" )
_S(0x010000000ULL,	"CLONE_NEWUSER" )
_S(0x020000000ULL,	"CLONE_NEWPID" )
_S(0x040000000ULL,	"CLONE_NEWNET" )
_S(0x080000000ULL,	"CLONE_IO" )
_S(0x100000000ULL,	"CLONE_CLEAR_SIGHAND")
_S(0x200000000ULL,	"CLONE_INTO_CGROUP")

