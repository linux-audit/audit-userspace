/* bpftab.h --
 * Copyright 2018-23 Red Hat Inc.
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
 * Location: include/uapi/linux/bpf.h
 */

_S(0, "BPF_MAP_CREATE")
_S(1, "BPF_MAP_LOOKUP_ELEM")
_S(2, "BPF_MAP_UPDATE_ELEM")
_S(3, "BPF_MAP_DELETE_ELEM")
_S(4, "BPF_MAP_GET_NEXT_KEY")
_S(5, "BPF_PROG_LOAD")
_S(6, "BPF_OBJ_PIN")
_S(7, "BPF_OBJ_GET")
_S(8, "BPF_PROG_ATTACH")
_S(9, "BPF_PROG_DETACH")
_S(10, "BPF_PROG_TEST_RUN")
_S(11, "BPF_PROG_GET_NEXT_ID")
_S(12, "BPF_MAP_GET_NEXT_ID")
_S(13, "BPF_PROG_GET_FD_BY_ID")
_S(14, "BPF_MAP_GET_FD_BY_ID")
_S(15, "BPF_OBJ_GET_INFO_BY_FD")
_S(16, "BPF_PROG_QUERY")
_S(17, "BPF_RAW_TRACEPOINT_OPEN")
_S(18, "BPF_BTF_LOAD")
_S(19, "BPF_BTF_GET_FD_BY_ID")
_S(20, "BPF_TASK_FD_QUERY")
_S(21, "BPF_MAP_LOOKUP_AND_DELETE_ELEM")
_S(22, "BPF_MAP_FREEZE")
_S(23, "BPF_BTF_GET_NEXT_ID")
_S(24, "BPF_MAP_LOOKUP_BATCH")
_S(25, "BPF_MAP_LOOKUP_AND_DELETE_BATCH")
_S(26, "BPF_MAP_UPDATE_BATCH")
_S(27, "BPF_MAP_DELETE_BATCH")
_S(28, "BPF_LINK_CREATE")
_S(29, "BPF_LINK_UPDATE")
_S(30, "BPF_LINK_GET_FD_BY_ID")
_S(31, "BPF_LINK_GET_NEXT_ID")
_S(32, "BPF_ENABLE_STATS")
_S(33, "BPF_ITER_CREATE")
_S(34, "BPF_LINK_DETACH")
_S(35, "BPF_PROG_BIND_MAP")
