# Makefile.am --
# Copyright 2021 Steve Grubb.
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
EXTRA_DIST = au-statsd.conf audisp-statsd.conf  $(man_MANS)
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/auparse
prog_confdir = $(sysconfdir)/audit
prog_conf = audisp-statsd.conf
plugin_confdir=$(prog_confdir)/plugins.d
plugin_conf = au-statsd.conf
sbin_PROGRAMS = audisp-statsd
man_MANS = audisp-statsd.8
audisp_statsd_SOURCES = audisp-statsd.c
audisp_statsd_CFLAGS = -g -D_GNU_SOURCE ${WFLAGS}
audisp_statsd_LDADD = ${top_builddir}/auparse/libauparse.la ${top_builddir}/lib/libaudit.la

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(plugin_conf) ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(prog_conf) ${DESTDIR}${prog_confdir}

uninstall-hook:
	rm ${DESTDIR}${plugin_confdir}/$(plugin_conf)
	rm ${DESTDIR}${prog_confdir}/$(prog_conf)

