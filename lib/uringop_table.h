/* uringop_table.h --
 * Copyright 2005-21 Red Hat Inc.
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
 *      Richard Guy Briggs <rgb@redhat.com>
 */

/* from /usr/include/linux/io_uring.h */

_S(0,	"nop")
_S(1,	"readv")
_S(2,	"writev")
_S(3,	"fsync")
_S(4,	"read_fixed")
_S(5,	"write_fixed")
_S(6,	"poll_add")
_S(7,	"poll_remove")
_S(8,	"sync_file_range")
_S(9,	"sendmsg")
_S(10,	"recvmsg")
_S(11,	"timeout")
_S(12,	"timeout_remove")
_S(13,	"accept")
_S(14,	"async_cancel")
_S(15,	"link_timeout")
_S(16,	"connect")
_S(17,	"fallocate")
_S(18,	"openat")
_S(19,	"close")
_S(20,	"files_update")
_S(21,	"statx")
_S(22,	"read")
_S(23,	"write")
_S(24,	"fadvise")
_S(25,	"madvise")
_S(26,	"send")
_S(27,	"recv")
_S(28,	"openat2")
_S(29,	"epoll_ctl")
_S(30,	"splice")
_S(31,	"provide_bufers")
_S(32,	"remove_bufers")
_S(33,	"tee")
_S(34,	"shutdown")
_S(35,	"renameat")
_S(36,	"unlinkat")

