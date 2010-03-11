# Makefile.am-- 
# Copyright 2004-2006, 2008 Red Hat Inc., Durham, North Carolina.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#

CONFIG_CLEAN_FILES = *.rej *.orig
AUTOMAKE_OPTIONS = no-dependencies
SUBDIRS = test
INCLUDES = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/src/libev
sbin_PROGRAMS = auditd auditctl aureport ausearch autrace
LIBS = -Lmt -lauditmt
LDADD = -lpthread
AM_CFLAGS = -D_REENTRANT -D_GNU_SOURCE
noinst_HEADERS = auditd-config.h auditd-event.h auditd-listen.h ausearch-llist.h ausearch-options.h auditctl-llist.h aureport-options.h ausearch-parse.h aureport-scan.h ausearch-lookup.h ausearch-int.h auditd-dispatch.h ausearch-string.h ausearch-nvpair.h ausearch-common.h ausearch-avc.h ausearch-time.h ausearch-lol.h

auditd_SOURCES = auditd.c auditd-event.c auditd-config.c auditd-reconfig.c auditd-sendmail.c auditd-dispatch.c auditd-listen.c
auditd_CFLAGS = -fPIE -DPIE -g -D_REENTRANT -D_GNU_SOURCE -fno-strict-aliasing 
auditd_LDFLAGS = -pie -Wl,-z,relro
auditd_DEPENDENCIES = mt/libauditmt.a libev/libev.a
auditd_LDADD = @LIBWRAP_LIBS@ @libev_LIBS@ -Llibev -lev -lrt -lpthread -lm $(gss_libs)

auditctl_SOURCES = auditctl.c auditctl-llist.c delete_all.c
auditctl_DEPENDENCIES = mt/libauditmt.a 

aureport_SOURCES = aureport.c auditd-config.c ausearch-llist.c aureport-options.c ausearch-string.c ausearch-parse.c aureport-scan.c aureport-output.c ausearch-lookup.c ausearch-int.c ausearch-time.c ausearch-nvpair.c ausearch-avc.c ausearch-lol.c
aureport_DEPENDENCIES = mt/libauditmt.a

ausearch_SOURCES = ausearch.c auditd-config.c ausearch-llist.c ausearch-options.c ausearch-report.c ausearch-match.c ausearch-string.c ausearch-parse.c ausearch-int.c ausearch-time.c ausearch-nvpair.c ausearch-lookup.c ausearch-avc.c ausearch-lol.c
ausearch_DEPENDENCIES = mt/libauditmt.a

autrace_SOURCES = autrace.c delete_all.c auditctl-llist.c
autrace_DEPENDENCIES = mt/libauditmt.a

mt/libauditmt.a:
	make -C mt
libev/libev.a:
	make -C libev
