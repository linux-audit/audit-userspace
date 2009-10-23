# Makefile.am -- 
# Copyright 2004-2009 Red Hat Inc., Durham, North Carolina.
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

SUBDIRS = test
CLEANFILES = $(BUILT_SOURCES)
CONFIG_CLEAN_FILES = *.loT *.rej *.orig
EXTRA_DIST = syscall-update.txt
VERSION_INFO = 1:0
AM_CFLAGS = -fPIC -DPIC -D_GNU_SOURCE
INCLUDES = -I. -I${top_srcdir} -I${top_srcdir}/auparse
lib_LTLIBRARIES = libaudit.la
include_HEADERS = libaudit.h
libaudit_la_SOURCES = libaudit.c message.c netlink.c \
	lookup_table.c audit_logging.c deprecated.c \
	private.h errormsg.h
libaudit_la_LIBADD =
libaudit_la_DEPENDENCIES = $(libaudit_la_SOURCES) ../config.h
libaudit_la_LDFLAGS = -Wl,-z,relro -version-info $(VERSION_INFO)
nodist_libaudit_la_SOURCES = $(BUILT_SOURCES)

BUILT_SOURCES = actiontabs.h errtabs.h fieldtabs.h flagtabs.h \
	ftypetabs.h i386_tables.h ia64_tables.h machinetabs.h \
	msg_typetabs.h optabs.h ppc_tables.h s390_tables.h \
	s390x_tables.h x86_64_tables.h
if USE_ALPHA
BUILT_SOURCES += alpha_tables.h
endif
if USE_ARMEB
BUILT_SOURCES += armeb_tables.h
endif
noinst_PROGRAMS = gen_actiontabs_h gen_errtabs_h gen_fieldtabs_h \
	gen_flagtabs_h gen_ftypetabs_h gen_i386_tables_h \
	gen_ia64_tables_h gen_machinetabs_h gen_msg_typetabs_h \
	gen_optabs_h gen_ppc_tables_h gen_s390_tables_h \
	gen_s390x_tables_h gen_x86_64_tables_h
if USE_ALPHA
noinst_PROGRAMS += gen_alpha_tables_h
endif
if USE_ARMEB
noinst_PROGRAMS += gen_armeb_tables_h
endif
gen_actiontabs_h_SOURCES = gen_tables.c gen_tables.h actiontab.h
gen_actiontabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="actiontab.h"'
actiontabs.h: gen_actiontabs_h Makefile
	./gen_actiontabs_h --lowercase --i2s --s2i action > $@

if USE_ALPHA
gen_alpha_tables_h_SOURCES = gen_tables.c gen_tables.h alpha_table.h
gen_alpha_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="alpha_table.h"'
alpha_tables.h: gen_alpha_tables_h Makefile
	./gen_alpha_tables_h --lowercase --i2s --s2i alpha_syscall > $@
endif

if USE_ARMEB
gen_armeb_tables_h_SOURCES = gen_tables.c gen_tables.h armeb_table.h
gen_armeb_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="armeb_table.h"'
armeb_tables.h: gen_armeb_tables_h Makefile
	./gen_armeb_tables_h --lowercase --i2s --s2i armeb_syscall > $@
endif

gen_errtabs_h_SOURCES = gen_tables.c gen_tables.h errtab.h
gen_errtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="errtab.h"'
errtabs.h: gen_errtabs_h Makefile
	./gen_errtabs_h --duplicate-ints --uppercase --i2s --s2i err > $@

gen_fieldtabs_h_SOURCES = gen_tables.c gen_tables.h fieldtab.h
gen_fieldtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="fieldtab.h"'
fieldtabs.h: gen_fieldtabs_h Makefile
	./gen_fieldtabs_h --duplicate-ints --lowercase --i2s --s2i field > $@

gen_flagtabs_h_SOURCES = gen_tables.c gen_tables.h flagtab.h
gen_flagtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="flagtab.h"'
flagtabs.h: gen_flagtabs_h Makefile
	./gen_flagtabs_h --lowercase --i2s --s2i flag > $@

gen_ftypetabs_h_SOURCES = gen_tables.c gen_tables.h ftypetab.h
gen_ftypetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ftypetab.h"'
ftypetabs.h: gen_ftypetabs_h Makefile
	./gen_ftypetabs_h --lowercase --i2s --s2i ftype > $@

gen_i386_tables_h_SOURCES = gen_tables.c gen_tables.h i386_table.h
gen_i386_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="i386_table.h"'
i386_tables.h: gen_i386_tables_h Makefile
	./gen_i386_tables_h --duplicate-ints --lowercase --i2s --s2i \
		i386_syscall > $@

gen_ia64_tables_h_SOURCES = gen_tables.c gen_tables.h ia64_table.h
gen_ia64_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ia64_table.h"'
ia64_tables.h: gen_ia64_tables_h Makefile
	./gen_ia64_tables_h --lowercase --i2s --s2i ia64_syscall > $@

gen_machinetabs_h_SOURCES = gen_tables.c gen_tables.h machinetab.h
gen_machinetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="machinetab.h"'
machinetabs.h: gen_machinetabs_h Makefile
	./gen_machinetabs_h --duplicate-ints --lowercase --i2s --s2i machine \
		> $@

gen_msg_typetabs_h_SOURCES = gen_tables.c gen_tables.h msg_typetab.h
gen_msg_typetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="msg_typetab.h"'
msg_typetabs.h: gen_msg_typetabs_h Makefile
	./gen_msg_typetabs_h --uppercase --i2s --s2i msg_type > $@

gen_optabs_h_SOURCES = gen_tables.c gen_tables.h optab.h
gen_optabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="optab.h"'
optabs.h: gen_optabs_h Makefile
	./gen_optabs_h --i2s op > $@

gen_ppc_tables_h_SOURCES = gen_tables.c gen_tables.h ppc_table.h
gen_ppc_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ppc_table.h"'
ppc_tables.h: gen_ppc_tables_h Makefile
	./gen_ppc_tables_h --lowercase --i2s --s2i ppc_syscall > $@

gen_s390_tables_h_SOURCES = gen_tables.c gen_tables.h s390_table.h
gen_s390_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="s390_table.h"'
s390_tables.h: gen_s390_tables_h Makefile
	./gen_s390_tables_h --lowercase --i2s --s2i s390_syscall > $@

gen_s390x_tables_h_SOURCES = gen_tables.c gen_tables.h s390x_table.h
gen_s390x_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="s390x_table.h"'
s390x_tables.h: gen_s390x_tables_h Makefile
	./gen_s390x_tables_h --lowercase --i2s --s2i s390x_syscall > $@

gen_x86_64_tables_h_SOURCES = gen_tables.c gen_tables.h x86_64_table.h
gen_x86_64_tables_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="x86_64_table.h"'
x86_64_tables.h: gen_x86_64_tables_h Makefile
	./gen_x86_64_tables_h --lowercase --i2s --s2i x86_64_syscall > $@
