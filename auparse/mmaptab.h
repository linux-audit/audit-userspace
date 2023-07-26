/* mmaptab.h --
 * Copyright 2012-13,2018,2020 Red Hat Inc.
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
 *      Steve Grubb <sgrubb@redhat.com>
 * Location: include/uapi/asm-generic/mman-common.h
 * 0x0100 - 0x4000 flags are defined in include/uapi/asm-generic/mman.h
 */

_S(0x0000001, "MAP_SHARED"	)
_S(0x0000002, "MAP_PRIVATE"	)
_S(0x0000010, "MAP_FIXED"	)
_S(0x0000020, "MAP_ANONYMOUS"	)
_S(0x0000040, "MAP_32BIT"	)
_S(0x0000100, "MAP_GROWSDOWN"	)
_S(0x0000800, "MAP_DENYWRITE"	)
_S(0x0001000, "MAP_EXECUTABLE"	)
_S(0x0002000, "MAP_LOCKED"	)
_S(0x0004000, "MAP_NORESERVE"	)
_S(0x0008000, "MAP_POPULATE"	)
_S(0x0010000, "MAP_NONBLOCK"	)
_S(0x0020000, "MAP_STACK"	)
_S(0x0040000, "MAP_HUGETLB"	)
_S(0x0080000, "MAP_SYNC"	)
_S(0x0100000, "MAP_FIXED_NOREPLACE")
_S(0x4000000, "MAP_UNINITIALIZED")
