# Makefile.am -- 
# Copyright 2006-08,2011-13 Red Hat Inc., Durham, North Carolina.
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
	auparse-idata.h data_buf.h nvlist.h auparse.h ellist.h		\
	internal.h nvpair.h rnode.h interpret.h				\
	private.h expression.c expression.h tty_named_keys.h
nodist_libauparse_la_SOURCES = $(BUILT_SOURCES)

libauparse_la_LIBADD = ${top_builddir}/lib/libaudit.la
libauparse_la_DEPENDENCIES = $(libauparse_la_SOURCES) ${top_builddir}/config.h
libauparse_la_LDFLAGS = -Wl,-z,relro

message.c:
	cp ${top_srcdir}/lib/message.c .

BUILT_SOURCES = accesstabs.h captabs.h clocktabs.h clone-flagtabs.h \
	epoll_ctls.h famtabs.h fcntl-cmdtabs.h \
	flagtabs.h icmptypetabs.h ipctabs.h ipccmdtabs.h\
	ipoptnametabs.h ip6optnametabs.h \
	mmaptabs.h mounttabs.h nfprototabs.h open-flagtabs.h \
	persontabs.h prctl_opttabs.h pktoptnametabs.h \
	prottabs.h ptracetabs.h \
	rlimittabs.h recvtabs.h schedtabs.h seccomptabs.h \
	seektabs.h shm_modetabs.h signaltabs.h sockoptnametabs.h \
	socktabs.h sockleveltabs.h socktypetabs.h \
	tcpoptnametabs.h typetabs.h umounttabs.h
noinst_PROGRAMS = gen_accesstabs_h gen_captabs_h gen_clock_h \
	gen_clone-flagtabs_h \
	gen_epoll_ctls_h gen_famtabs_h \
	gen_fcntl-cmdtabs_h gen_flagtabs_h \
	gen_icmptypetabs_h gen_ipctabs_h gen_ipccmdtabs_h\
	gen_ipoptnametabs_h gen_ip6optnametabs_h gen_nfprototabs_h \
	gen_mmaptabs_h gen_mounttabs_h \
	gen_open-flagtabs_h gen_persontabs_h \
	gen_prctl_opttabs_h gen_pktoptnametabs_h gen_prottabs_h \
	gen_recvtabs_h gen_rlimit_h gen_ptracetabs_h \
	gen_schedtabs_h gen_seccomptabs_h \
	gen_seektabs_h gen_shm_modetabs_h gen_signals_h \
	gen_sockoptnametabs_h gen_socktabs_h gen_sockleveltabs_h \
	gen_socktypetabs_h gen_tcpoptnametabs_h gen_typetabs_h \
	gen_umounttabs_h

gen_accesstabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h accesstab.h
gen_accesstabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="accesstab.h"'
accesstabs.h: gen_accesstabs_h Makefile
	./gen_accesstabs_h --i2s-transtab access > $@

gen_captabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h captab.h
gen_captabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="captab.h"'
captabs.h: gen_captabs_h Makefile
	./gen_captabs_h --i2s cap > $@

gen_clock_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h clocktab.h
gen_clock_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="clocktab.h"'
clocktabs.h: gen_clock_h Makefile
	./gen_clock_h --i2s clock > $@

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

gen_ipccmdtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ipccmdtab.h
gen_ipccmdtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ipccmdtab.h"'
ipccmdtabs.h: gen_ipccmdtabs_h Makefile
	./gen_ipccmdtabs_h --i2s-transtab ipccmd > $@

gen_ipoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ipoptnametab.h
gen_ipoptnametabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ipoptnametab.h"'
ipoptnametabs.h: gen_ipoptnametabs_h Makefile
	./gen_ipoptnametabs_h --i2s ipoptname > $@

gen_ip6optnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ip6optnametab.h
gen_ip6optnametabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ip6optnametab.h"'
ip6optnametabs.h: gen_ip6optnametabs_h Makefile
	./gen_ip6optnametabs_h --i2s ip6optname > $@

gen_mmaptabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h mmaptab.h
gen_mmaptabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="mmaptab.h"'
mmaptabs.h: gen_mmaptabs_h Makefile
	./gen_mmaptabs_h --i2s-transtab mmap > $@

gen_mounttabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h mounttab.h
gen_mounttabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="mounttab.h"'
mounttabs.h: gen_mounttabs_h Makefile
	./gen_mounttabs_h --i2s-transtab mount > $@

gen_nfprototabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h nfprototab.h
gen_nfprototabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="nfprototab.h"'
nfprototabs.h: gen_nfprototabs_h Makefile
	./gen_nfprototabs_h --i2s nfproto > $@

gen_open_flagtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h \
	open-flagtab.h
gen_open_flagtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="open-flagtab.h"'
open-flagtabs.h: gen_open-flagtabs_h Makefile
	./gen_open-flagtabs_h --i2s-transtab open_flag > $@

gen_persontabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h persontab.h
gen_persontabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="persontab.h"'
persontabs.h: gen_persontabs_h Makefile
	./gen_persontabs_h --i2s person > $@

gen_ptracetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h ptracetab.h
gen_ptracetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="ptracetab.h"'
ptracetabs.h: gen_ptracetabs_h Makefile
	./gen_ptracetabs_h --i2s ptrace > $@

gen_prctl_opttabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h prctl-opt-tab.h
gen_prctl_opttabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="prctl-opt-tab.h"'
prctl_opttabs.h: gen_prctl_opttabs_h Makefile
	./gen_prctl_opttabs_h --i2s prctl_opt > $@

gen_pktoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h pktoptnametab.h
gen_pktoptnametabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="pktoptnametab.h"'
pktoptnametabs.h: gen_pktoptnametabs_h Makefile
	./gen_pktoptnametabs_h --i2s pktoptname > $@

gen_prottabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h prottab.h
gen_prottabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="prottab.h"'
prottabs.h: gen_prottabs_h Makefile
	./gen_prottabs_h --i2s-transtab prot > $@

gen_recvtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h recvtab.h
gen_recvtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="recvtab.h"'
recvtabs.h: gen_recvtabs_h Makefile
	./gen_recvtabs_h --i2s-transtab recv > $@

gen_rlimit_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h rlimittab.h
gen_rlimit_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="rlimittab.h"'
rlimittabs.h: gen_rlimit_h Makefile
	./gen_rlimit_h --i2s rlimit > $@

gen_schedtabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h schedtab.h
gen_schedtabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="schedtab.h"'
schedtabs.h: gen_schedtabs_h Makefile
	./gen_schedtabs_h --i2s sched > $@

gen_seccomptabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h seccomptab.h
gen_seccomptabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="seccomptab.h"'
seccomptabs.h: gen_seccomptabs_h Makefile
	./gen_seccomptabs_h --i2s seccomp > $@

gen_seektabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h seektab.h
gen_seektabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="seektab.h"'
seektabs.h: gen_seektabs_h Makefile
	./gen_seektabs_h --i2s seek > $@

gen_shm_modetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h shm_modetab.h
gen_shm_modetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="shm_modetab.h"'
shm_modetabs.h: gen_shm_modetabs_h Makefile
	./gen_shm_modetabs_h --i2s-transtab shm_mode > $@

gen_signals_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h signaltab.h
gen_signals_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="signaltab.h"'
signaltabs.h: gen_signals_h Makefile
	./gen_signals_h --i2s signal > $@

gen_sockleveltabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h sockleveltab.h
gen_sockleveltabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="sockleveltab.h"'
sockleveltabs.h: gen_sockleveltabs_h Makefile
	./gen_sockleveltabs_h --i2s socklevel > $@

gen_sockoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h sockoptnametab.h
gen_sockoptnametabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="sockoptnametab.h"'
sockoptnametabs.h: gen_sockoptnametabs_h Makefile
	./gen_sockoptnametabs_h --i2s sockoptname > $@

gen_socktabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h socktab.h
gen_socktabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="socktab.h"'
socktabs.h: gen_socktabs_h Makefile
	./gen_socktabs_h --i2s sock > $@

gen_socktypetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h socktypetab.h
gen_socktypetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="socktypetab.h"'
socktypetabs.h: gen_socktypetabs_h Makefile
	./gen_socktypetabs_h --i2s sock_type > $@

gen_tcpoptnametabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h tcpoptnametab.h
gen_tcpoptnametabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="tcpoptnametab.h"'
tcpoptnametabs.h: gen_tcpoptnametabs_h Makefile
	./gen_tcpoptnametabs_h --i2s tcpoptname > $@

gen_typetabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h typetab.h
gen_typetabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="typetab.h"'
typetabs.h: gen_typetabs_h Makefile
	./gen_typetabs_h --s2i type > $@

gen_umounttabs_h_SOURCES = ../lib/gen_tables.c ../lib/gen_tables.h umounttab.h
gen_umounttabs_h_CFLAGS = $(AM_CFLAGS) '-DTABLE_H="umounttab.h"'
umounttabs.h: gen_umounttabs_h Makefile
	./gen_umounttabs_h --i2s-transtab umount > $@

