# Makefile.am -- 
# Copyright 2005-06,2008,2012,2014-15 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
# 
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#
# This make file builds a static multi-threaded libary for the audit
# daemon's own use.

AUTOMAKE_OPTIONS = no-dependencies
AM_CPPFLAGS = -I${top_srcdir}/lib -I${top_builddir}/lib
CONFIG_CLEAN_FILES = *.rej *.orig
AM_CFLAGS = -fPIC -DPIC -D_REENTRANT -D_GNU_SOURCE -DNO_TABLES

noinst_LIBRARIES = libauditmt.a

libauditmt_a_SOURCES = ${top_srcdir}/lib/libaudit.c \
	${top_srcdir}/lib/message.c ${top_srcdir}/lib/netlink.c \
	${top_srcdir}/lib/lookup_table.c ${top_srcdir}/lib/audit_logging.c \
	${top_srcdir}/lib/deprecated.c ${top_srcdir}/lib/strsplit.c
libauditmt_a_HEADERS: ${top_builddir}/config.h ${top_srcdir}/lib/libaudit.h \
	${top_srcdir}/lib/private.h
libauditmt_a_DEPENDENCIES = $(libaudit_a_SOURCES) ${top_builddir}/config.h \
	${top_srcdir}/lib/gen_tables.h ${top_builddir}/lib/i386_tables.h \
	${top_builddir}/lib/ia64_tables.h ${top_builddir}/lib/ppc_tables.h \
	${top_builddir}/lib/s390_tables.h ${top_builddir}/lib/s390x_tables.h \
	${top_builddir}/lib/x86_64_tables.h ${top_srcdir}/lib/private.h \
	${top_builddir}/lib/actiontabs.h ${top_builddir}/lib/fieldtabs.h \
	${top_builddir}/lib/flagtabs.h ${top_builddir}/lib/ftypetabs.h \
	${top_builddir}/lib/machinetabs.h ${top_builddir}/lib/msg_typetabs.h \
	${top_builddir}/lib/optabs.h
AM_LDFLAGS = -Wl,-z,relro

lib_OBJECTS = $(libauditmt_a_OBJECTS)
