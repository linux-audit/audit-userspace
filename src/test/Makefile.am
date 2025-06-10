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

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/src -I${top_srcdir}/common -I${top_srcdir}/auparse
check_PROGRAMS = ilist_test slist_test # format_event_test
TESTS = $(check_PROGRAMS)
ilist_test_LDADD = ${top_builddir}/src/ausearch-int.o
ilist_test_DEPENDENCIES = ${top_builddir}/src/ausearch-int.o
slist_test_LDADD = ${top_builddir}/src/ausearch-string.o
slist_test_DEPENDENCIES = ${top_builddir}/src/ausearch-string.o
format_event_test_LDADD = ${top_builddir}/src/auditd-event.o \
	${top_builddir}/src/auditd-config.o \
	${top_builddir}/src/auditd-auditd-sendmail.o \
	${top_builddir}/src/auditd-auditd-dispatch.o \
	${top_builddir}/src/auditd-auditd-listen.o \
	${top_builddir}/lib/libaudit.la ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/audisp/libdisp.la \
	${top_builddir}/src/libev/libev.la \
	${top_builddir}/common/libaucommon.la -lpthread -lm $(gss_libs)
format_event_test_DEPENDENCIES = ${top_builddir}/src/auditd-event.o \
	${top_builddir}/src/auditd-config.o \
	${top_builddir}/src/auditd-auditd-sendmail.o \
	${top_builddir}/src/auditd-auditd-dispatch.o \
	${top_builddir}/src/auditd-auditd-listen.o \
	${top_builddir}/lib/libaudit.la ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/common/libaucommon.la ${top_builddir}/audisp/libdisp.la\
	${top_builddir}/src/libev/libev.la

