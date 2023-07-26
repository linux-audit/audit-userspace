/* openat2-resolvetab.h --
 * Copyright 2021 Red Hat Inc.
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
 * Location: include/uapi/linux/openat2.h
 */

_S(0x01, "RESOLVE_NO_XDEV" )
_S(0x02, "RESOLVE_NO_MAGICLINKS" )
_S(0x04, "RESOLVE_NO_SYMLINKS" )
_S(0x08, "RESOLVE_BENEATH" )
_S(0x10, "RESOLVE_IN_ROOT" )
_S(0x20, "RESOLVE_CACHED" )
