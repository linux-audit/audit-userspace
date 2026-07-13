# Copyright 2008,2014,2015 Red Hat Inc.
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

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/src
AM_CFLAGS = -D_GNU_SOURCE -Wno-pointer-sign ${WFLAGS}
AM_LDFLAGS =
if HAVE_ASAN
AM_CFLAGS += ${ASAN_FLAGS}
AM_LDFLAGS += ${ASAN_FLAGS}
endif
check_PROGRAMS = ilist_test slist_test format_event_test \
	auditd_config_alloc_test ausearch_checkpt_test auditd_dispatch_test \
	ilist_alloc_test auditd_reconfigure_test lol_alloc_test auditctl_key_test \
	auditctl_list_alloc_test delete_all_alloc_test
TESTS = $(check_PROGRAMS)
ilist_test_LDADD = ${top_builddir}/src/ausearch-int.o
ilist_test_DEPENDENCIES = ${top_builddir}/src/ausearch-int.o
ilist_alloc_test_SOURCES = ilist_alloc_test.c
lol_alloc_test_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/common \
	-I${top_srcdir}/auparse
lol_alloc_test_SOURCES = lol_alloc_test.c
slist_test_LDADD = ${top_builddir}/src/ausearch-string.o
slist_test_DEPENDENCIES = ${top_builddir}/src/ausearch-string.o
format_event_test_CFLAGS = -D_REENTRANT -D_GNU_SOURCE -Wno-pointer-sign ${WFLAGS} -fno-strict-aliasing -I${top_srcdir}/common -I${top_srcdir}/auparse -I${top_srcdir}/audisp -I${top_srcdir}/src/libev
format_event_test_SOURCES = format_event_test.c \
	${top_srcdir}/src/auditd-event.c \
	${top_srcdir}/src/auditd-reconfigure.c \
	${top_srcdir}/src/auditd-config.c \
	${top_srcdir}/src/auditd-sendmail.c \
	${top_srcdir}/src/auditd-dispatch.c
format_event_test_LDADD = ${top_builddir}/lib/libaudit.la \
	${top_builddir}/auparse/libauparse.la \
	${top_builddir}/audisp/libdisp.la \
	${top_builddir}/src/libev/libev.la \
	${top_builddir}/common/libaucommon.la -lpthread -lm $(gss_libs) $(LIBWRAP_LIBS)
auditd_config_alloc_test_SOURCES = auditd_config_alloc_test.c
auditd_config_alloc_test_CFLAGS = -D_GNU_SOURCE -Wno-pointer-sign ${WFLAGS} \
	-fno-strict-aliasing -I${top_srcdir}/common -I${top_srcdir}/src
ausearch_checkpt_test_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/auparse
ausearch_checkpt_test_SOURCES = ausearch_checkpt_test.c \
	${top_srcdir}/src/ausearch-checkpt.c
auditd_dispatch_test_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/audisp \
	-I${top_srcdir}/src/libev
auditd_dispatch_test_SOURCES = auditd_dispatch_test.c \
	${top_srcdir}/src/auditd-dispatch.c
auditd_reconfigure_test_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/src/libev
auditd_reconfigure_test_SOURCES = auditd_reconfigure_test.c
auditctl_key_test_SOURCES = auditctl_key_test.c \
	${top_srcdir}/src/auditctl-llist.c
auditctl_key_test_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/auparse
auditctl_key_test_LDADD = ${top_builddir}/lib/libaudit.la \
	${top_builddir}/auparse/libauparse.la \
	${top_builddir}/common/libaucommon.la
auditctl_list_alloc_test_SOURCES = auditctl_list_alloc_test.c \
	${top_srcdir}/src/auditctl-llist.c
auditctl_list_alloc_test_CFLAGS = ${AM_CFLAGS} -I${top_srcdir}/auparse
auditctl_list_alloc_test_LDADD = ${top_builddir}/lib/libaudit.la \
	${top_builddir}/auparse/libauparse.la \
	${top_builddir}/common/libaucommon.la
delete_all_alloc_test_SOURCES = delete_all_alloc_test.c
if ENABLE_LISTENER
format_event_test_SOURCES += \
        ${top_srcdir}/src/auditd-listen.c
if ENABLE_TLS
format_event_test_CFLAGS += -I${top_srcdir}/autls $(OPENSSL_CFLAGS)
format_event_test_CFLAGS += -DAUDITD_EXE=\"$(sbindir)/auditd\"
format_event_test_CFLAGS += -DAUDITD_LISTEN_TEST
format_event_test_LDADD += ${top_builddir}/autls/libautls.la

# Direct src/test builds bypass the top-level SUBDIRS ordering.
${top_builddir}/autls/libautls.la:
	$(MAKE) $(AM_MAKEFLAGS) -C ${top_builddir}/autls libautls.la
endif
endif
