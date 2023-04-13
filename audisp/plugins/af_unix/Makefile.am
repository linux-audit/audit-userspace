# Makefile.am--
# Copyright 2023 Red Hat Inc.
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
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
# Boston, MA 02110-1335, USA.
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#

CONFIG_CLEAN_FILES = *.rej *.orig
CONF_FILES = af_unix.conf
EXTRA_DIST = $(CONF_FILES) $(man_MANS)

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/common
prog_confdir = $(sysconfdir)/audit
plugin_confdir=$(prog_confdir)/plugins.d
plugin_conf = af_unix.conf
sbin_PROGRAMS = audisp-af_unix
man_MANS = audisp-af_unix.8

audisp_af_unix_DEPENDENCIES = ${top_builddir}/common/libaucommon.la
audisp_af_unix_SOURCES = audisp-af_unix.c
audisp_af_unix_CFLAGS = -fPIE -DPIE -g -D_GNU_SOURCE -Wundef ${WFLAGS}
audisp_af_unix_LDFLAGS = -pie -Wl,-z,relro -Wl,-z,now
audisp_af_unix_LDADD = $(CAPNG_LDADD) ${top_builddir}/common/libaucommon.la

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	for i in $(CONF_FILES); do \
		$(INSTALL_DATA) -D -m 640 ${srcdir}/"$$i" \
			${DESTDIR}${plugin_confdir}; \
	done

uninstall-hook:
	for i in $(CONF_FILES); do \
		rm ${DESTDIR}${plugin_confdir}/"$$i"; \
	done

