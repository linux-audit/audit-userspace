# Makefile.am --
# Copyright 2021 Steve Grubb
# All Rights Reserved.
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
EXTRA_DIST = audisp-ids.conf ids.conf TODO README.md
SUBDIRS = rules
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/common -I${top_srcdir}/auparse
prog_confdir = $(sysconfdir)/audit
prog_conf = ids.conf
plugin_confdir=$(prog_confdir)/plugins.d
plugin_conf = audisp-ids.conf
sbin_PROGRAMS = audisp-ids
noinst_HEADERS = account.h avl.h ids_config.h gcc-attributes.h ids.h \
	model_bad_event.h model_behavior.h nvpair.h origin.h \
	reactions.h session.h timer-services.h

audisp_ids_DEPENDENCIES = ${top_builddir}/common/libaucommon.la
audisp_ids_SOURCES = account.c avl.c ids.c ids_config.c model_bad_event.c \
	model_behavior.c nvpair.c origin.c reactions.c session.c \
	timer-services.c
audisp_ids_CFLAGS = -D_GNU_SOURCE ${WFLAGS}
audisp_ids_LDADD = ${top_builddir}/lib/libaudit.la ${top_builddir}/auparse/libauparse.la ${top_builddir}/common/libaucommon.la

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(plugin_conf) ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(prog_conf) ${DESTDIR}${prog_confdir}

uninstall-hook:
	rm ${DESTDIR}${plugin_confdir}/$(plugin_conf)
