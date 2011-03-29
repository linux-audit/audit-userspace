# Makefile.am -- 
# Copyright 2006-08,2011 Red Hat Inc., Durham, North Carolina.
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
AM_CFLAGS = -fPIC -DPIC -D_GNU_SOURCE -g ${DEBUG}
INCLUDES = -I. -I${top_srcdir} -I${top_srcdir}/src -I${top_srcdir}/lib
LIBS =
lib_LTLIBRARIES = libauparse.la
include_HEADERS = auparse.h auparse-defs.h
libauparse_la_SOURCES = nvpair.c interpret.c nvlist.c ellist.c		\
	auparse.c auditd-config.c message.c data_buf.c auparse-defs.h	\
	data_buf.h nvlist.h auparse.h ellist.h				\
	internal.h nvpair.h rnode.h interpret.h				\
	private.h expression.c expression.h tty_named_keys.h
nodist_libauparse_la_SOURCES = $(BUILT_SOURCES)

libauparse_la_LIBADD = ${top_builddir}/lib/libaudit.la
libauparse_la_DEPENDENCIES = $(libauparse_la_SOURCES) ${top_builddir}/config.h
libauparse_la_LDFLAGS = -Wl,-z,relro

message.c:
	cp ${top_srcdir}/lib/message.c .

BUILT_SOURCES = captabs.h clone-flagtabs.h epoll_ctls.h famtabs.h \
	fcntl-cmdtabs.h flagtabs.h icmptypetabs.h ipctabs.h \
	nfprototabs.h open-flagtabs.h \
	seeks.h socktabs.h typetabs.h
noinst_PROGRAMS = gen_captabs_h gen_clone-flagtabs_h gen_epoll_ctls_h \
	gen_famtabs_h gen_fcntl-cmdtabs_h gen_flagtabs_h \
	gen_icmptypetabs_h gen_ipctabs_h gen_nfprototabs_h \
	gen_open-flagtabs_h gen_seeks_h \
	gen_socktabs_h gen_typetabs_h

gen_captabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h captab.h
gen_captabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="captab.h"'
captabs.h: gen_captabs_h Makefile
	./gen_captabs_h --i2s cap > $@

gen_clone_flagtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h \
	clone-flagtab.h
gen_clone_flagtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="clone-flagtab.h"'
clone-flagtabs.h: gen_clone-flagtabs_h Makefile
	./gen_clone-flagtabs_h --i2s-transtab clone_flag > $@

gen_epoll_ctls_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h epoll_ctl.h
gen_epoll_ctls_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="epoll_ctl.h"'
epoll_ctls.h: gen_epoll_ctls_h Makefile
	./gen_epoll_ctls_h --i2s epoll_ctl > $@

gen_famtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h famtab.h
gen_famtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="famtab.h"'
famtabs.h: gen_famtabs_h Makefile
	./gen_famtabs_h --i2s fam > $@

gen_flagtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h flagtab.h
# ../auparse/ is used to avoid using ../lib/flagtab.h
gen_flagtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="../auparse/flagtab.h"'
flagtabs.h: gen_flagtabs_h Makefile
	./gen_flagtabs_h --i2s-transtab flag > $@

gen_fcntl_cmdtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h \
	fcntl-cmdtab.h
gen_fcntl_cmdtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="fcntl-cmdtab.h"'
fcntl-cmdtabs.h: gen_fcntl-cmdtabs_h Makefile
	./gen_fcntl-cmdtabs_h --i2s fcntl > $@

gen_icmptypetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h icmptypetab.h
gen_icmptypetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="icmptypetab.h"'
icmptypetabs.h: gen_icmptypetabs_h Makefile
	./gen_icmptypetabs_h --i2s icmptype > $@

gen_ipctabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ipctab.h
gen_ipctabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ipctab.h"'
ipctabs.h: gen_ipctabs_h Makefile
	./gen_ipctabs_h --i2s ipc > $@

gen_nfprototabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h nfprototab.h
gen_nfprototabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="nfprototab.h"'
nfprototabs.h: gen_nfprototabs_h Makefile
	./gen_nfprototabs_h --i2s nfproto > $@

gen_open_flagtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h \
	open-flagtab.h
gen_open_flagtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="open-flagtab.h"'
open-flagtabs.h: gen_open-flagtabs_h Makefile
	./gen_open-flagtabs_h --i2s-transtab open_flag > $@

gen_seeks_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h seek.h
gen_seeks_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="seek.h"'
seeks.h: gen_seeks_h Makefile
	./gen_seeks_h --i2s seek > $@

gen_socktabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h socktab.h
gen_socktabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="socktab.h"'
socktabs.h: gen_socktabs_h Makefile
	./gen_socktabs_h --i2s sock > $@

gen_typetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h typetab.h
gen_typetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="typetab.h"'
typetabs.h: gen_typetabs_h Makefile
	./gen_typetabs_h --s2i type > $@
