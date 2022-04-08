# Makefile.am --
# Copyright 2018,19 Red Hat Inc., Durham, North Carolina.
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
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
# Boston, MA 02110-1335, USA.
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
# 

CONFIG_CLEAN_FILES = *.loT *.rej *.orig
EXTRA_DIST = syslog.conf $(man_MANS)
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/common -I${top_srcdir}/auparse
prog_confdir = $(sysconfdir)/audit
plugin_confdir=$(prog_confdir)/plugins.d
plugin_conf = syslog.conf
sbin_PROGRAMS = audisp-syslog
man_MANS = audisp-syslog.8

audisp_syslog_DEPENDENCIES = ${top_builddir}/common/libaucommon.la
audisp_syslog_SOURCES = audisp-syslog.c
audisp_syslog_CFLAGS = -fPIE -DPIE -g -D_GNU_SOURCE -Wundef ${WFLAGS}
audisp_syslog_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now
audisp_syslog_LDADD = $(CAPNG_LDADD) ${top_builddir}/common/libaucommon.la ${top_builddir}/auparse/libauparse.la

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(plugin_conf) ${DESTDIR}${plugin_confdir}

uninstall-hook:
	rm ${DESTDIR}${plugin_confdir}/$(plugin_conf)

