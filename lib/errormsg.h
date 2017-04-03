/* errormsg.h --
 * Copyright 2008 FUJITSU Inc.
 * Copyright 2012-16 Red Hat
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
 *      Zhang Xiliang <zhangxiliang@cn.fujitsu.com>
 *      Steve Grubb <sgrubb@redhat.com>
 */

struct msg_tab {
    int key; /* error number */
    /*
     * the field string position in the error message
     * 0: don't output field string
     * 1: output field string before error message
     * 2: output field string after error message
     */
    int position;
    const char	*cvalue;
};

#ifndef NO_TABLES
static const struct msg_tab err_msgtab[] = {
    { -1,    2,    "-F missing operation for" },
    { -2,    2,    "-F unknown field:" },
    { -3,    1,    "must be before -S" },
    { -4,    1,    "machine type not found" },
    { -5,    1,    "elf mapping not found" },
    { -6,    1,    "requested bit level not supported by machine" },
    { -7,    1,    "can only be used with exit filter list" },
    { -8,    2,    "-F unknown message type -" },
    { -9,    0,    "msgtype field can only be used with exclude or user filter list" },
    { -10,    0,    "Failed upgrading rule" },
    { -11,    0,    "String value too long" },
    { -12,    0,    "Only msgtype, *uid, *gid, pid, and subj* fields can be used with exclude filter" },
    { -13,    1,    "only takes = or != operators" },
    { -14,    0,    "Permission can only contain  \'rwxa\'" },
    { -15,    2,    "-F unknown errno -"},
    { -16,    2,    "-F unknown file type - " },
    { -17,    1,    "can only be used with exit and entry filter list" },
    { -18,    1,    "" }, // Deprecated don't reuse
    { -19,    0,    "Key field needs a watch, syscall or exe path given prior to it" },
    { -20,    2,    "-F missing value after operation for" },
    { -21,    2,    "-F value should be number for" },
    { -22,    2,    "-F missing field name before operator for" },
    { -23,    2,    "" }, // Deprecated don't reuse
    { -24,    2,    "-C missing field name before operator for" },
    { -25,    2,    "-C missing value after operation for "},
    { -26,    2,    "-C unknown field:" },
    { -27,    2,    "-C unknown right hand value for comparison with:" },
    { -28,    2,    "Too many fields in rule:" },
    { -29,    1,    "only takes = operator" },
    { -30,    2,    "Field option not supported by kernel:" },
    { -31,    1,    "must be used with exclude, user, or exit filter" },
    { -32,    0,    "filter is missing from rule" },
    { -33,    2,    "-C incompatible comparison" },
};
#define EAU_OPMISSING		1
#define EAU_FIELDUNKNOWN	2
#define EAU_ARCHMISPLACED	3
#define EAU_ARCHUNKNOWN		4
#define EAU_ELFUNKNOWN		5
#define EAU_ARCHNOBIT		6
#define EAU_EXITONLY		7
#define EAU_MSGTYPEUNKNOWN	8
#define EAU_MSGTYPEEXCLUDEUSER	9
#define EAU_UPGRADEFAIL		10
#define EAU_STRTOOLONG		11
#define EAU_MSGTYPECREDEXCLUDE	12
#define EAU_OPEQNOTEQ		13
#define EAU_PERMRWXA		14
#define EAU_ERRUNKNOWN		15
#define EAU_FILETYPEUNKNOWN	16
#define EAU_EXITENTRYONLY	17
#define EAU_KEYDEP		19
#define EAU_FIELDVALMISSING	20
#define EAU_FIELDVALNUM		21
#define EAU_FIELDNAME		22
#define EAU_COMPFIELDNAME	24
#define EAU_COMPVAL		25
#define EAU_COMPFIELDUNKNOWN	26
#define EAU_COMPVALUNKNOWN	27
#define EAU_FIELDTOOMANY	28
#define EAU_OPEQ		29
#define EAU_FIELDNOSUPPORT	30
#define EAU_FIELDNOFILTER	31
#define EAU_FILTERMISSING	32
#define EAU_COMPINCOMPAT	33
#endif
