/* prottab.h --
 * Copyright 2012-13 Red Hat Inc.
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
 * Foundation Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 * Location: include/uapi/asm-generic/mman-common.h
 */

_S(1,	"PROT_READ"	)
_S(2,	"PROT_WRITE"	)
_S(4,	"PROT_EXEC"	)
_S(8,	"PROT_SEM"	)
_S(0x01000000, "PROT_GROWSDOWN")
_S(0x02000000, "PROT_GROWSUP")

