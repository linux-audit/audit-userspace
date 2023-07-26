/* uringop_table.h --
 * Copyright 2005-23 Red Hat Inc.
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

/*
 *  From /usr/include/linux/io_uring.h
 *  kernel location here: io_uring/opdef.c
 *
 *  Note: not all ops are auditable for performance reasons. This was
 *  discussed on the linux-audit mail list:
 *  https://listman.redhat.com/archives/linux-audit/2021-June/018042.html
 */

_S(9,	"sendmsg")
_S(10,	"recvmsg")
_S(13,	"accept")
_S(16,	"connect")
_S(17,	"fallocate")
_S(18,	"openat")
_S(19,	"close")
_S(28,	"openat2")
_S(34,	"shutdown")
_S(35,	"renameat")
_S(36,	"unlinkat")
_S(37,  "mkdirat")
_S(38,  "symlinkat")
_S(39,  "linkat")
_S(40,  "msg_ring")
_S(41,  "fsetxattr")
_S(42,  "setxattr")
_S(43,  "fgetxattr")
_S(44,  "getxattr")
_S(46,  "uring_cmd")
_S(47,  "send_zc")
_S(48,	"sendmsg_zc")

