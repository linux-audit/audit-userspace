# Makefile.am -- 
# Copyright 2005-06,2008 Red Hat Inc., Durham, North Carolina.
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
CONFIG_CLEAN_FILES = Makefile.in *.rej *.orig 
AM_CFLAGS = -fPIC -DPIC -D_REENTRANT -D_GNU_SOURCE

noinst_LIBRARIES = libauditmt.a
noinst_HEADERS = libaudit.h private.h

libauditmt_a_SOURCES = libaudit.c message.c netlink.c \
lookup_table.c audit_logging.c deprecated.c
libauditmt_a_HEADERS: ${top_builddir}/config.h libaudit.h private.h
libauditmt_a_DEPENDENCIES = $(libaudit_a_SOURCES) ${top_builddir}/config.h \
	gen_tables.h i386_tables.h ia64_tables.h ppc_tables.h \
	s390_tables.h s390x_tables.h x86_64_tables.h private.h \
	actiontabs.h fieldtabs.h flagtabs.h ftypetabs.h \
	machinetabs.h msg_typetabs.h optabs.h
AM_LDFLAGS = -Wl,-z,relro

lib_OBJECTS = $(libauditmt_a_OBJECTS)

libaudit.h:
	cp ${top_srcdir}/lib/libaudit.h .
libaudit.c: libaudit.h private.h errormsg.h
	cp ${top_srcdir}/lib/libaudit.c .
message.c: libaudit.h
	cp ${top_srcdir}/lib/message.c .
netlink.c: libaudit.h
	cp ${top_srcdir}/lib/netlink.c .
lookup_table.c: libaudit.h
	cp ${top_srcdir}/lib/lookup_table.c .
audit_logging.c: libaudit.h
	cp ${top_srcdir}/lib/audit_logging.c .
deprecated.c: libaudit.h private.h
	cp ${top_srcdir}/lib/deprecated.c .
gen_tables.h:
	cp ${top_srcdir}/lib/gen_tables.h .
i386_tables.h:
	cp ${top_builddir}/lib/i386_tables.h .
ia64_tables.h:
	cp ${top_builddir}/lib/ia64_tables.h .
ppc_tables.h:
	cp ${top_builddir}/lib/ppc_tables.h .
s390_tables.h:
	cp ${top_builddir}/lib/s390_tables.h .
s390x_tables.h:
	cp ${top_builddir}/lib/s390x_tables.h .
x86_64_tables.h:
	cp ${top_builddir}/lib/x86_64_tables.h .
private.h:
	cp ${top_srcdir}/lib/private.h .
alpha_tables.h:
	cp ${top_builddir}/lib/alpha_tables.h .
actiontabs.h:
	cp ${top_builddir}/lib/actiontabs.h .
fieldtabs.h:
	cp ${top_builddir}/lib/fieldtabs.h .
flagtabs.h:
	cp ${top_builddir}/lib/flagtabs.h .
ftypetabs.h:
	cp ${top_builddir}/lib/ftypetabs.h .
machinetabs.h:
	cp ${top_builddir}/lib/machinetabs.h .
msg_typetabs.h:
	cp ${top_builddir}/lib/msg_typetabs.h .
optabs.h:
	cp ${top_builddir}/lib/optabs.h .
errtabs.h:
	cp ${top_builddir}/lib/errtabs.h .
errormsg.h:
	cp ${top_builddir}/lib/errormsg.h .

lookup_table.o: ${top_builddir}/config.h gen_tables.h i386_tables.h \
	ia64_tables.h ppc_tables.h s390_tables.h s390x_tables.h \
	x86_64_tables.h alpha_tables.h private.h actiontabs.h \
	fieldtabs.h flagtabs.h ftypetabs.h machinetabs.h \
	msg_typetabs.h optabs.h errtabs.h

libauditmt.o: $(libauditmt_a_SOURCES)

clean-generic:
	rm -f *.h *.c

