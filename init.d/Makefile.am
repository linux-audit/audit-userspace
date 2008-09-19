# Makefile.am--
# Copyright 2004-07 Red Hat Inc., Durham, North Carolina.
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
EXTRA_DIST = auditd.init auditd.sysconfig auditd.conf audit.rules \
	auditd.cron libaudit.conf audispd.conf
libconfig = libaudit.conf
dispconfig = audispd.conf
dispconfigdir = $(sysconfdir)/audisp
initdir=$(sysconfdir)/rc.d/init.d
sysconfigdir=$(sysconfdir)/sysconfig

auditdir = $(sysconfdir)/audit
dist_audit_DATA = auditd.conf audit.rules

install-data-hook:
	$(INSTALL_DATA) -D -m 640 ${srcdir}/auditd.sysconfig ${DESTDIR}${sysconfigdir}/auditd
	$(INSTALL_DATA) -D -m 640 ${srcdir}/${libconfig} ${DESTDIR}${sysconfdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/${dispconfig} ${DESTDIR}${dispconfigdir}

install-exec-hook:
	$(INSTALL_SCRIPT) -D ${srcdir}/auditd.init ${DESTDIR}${initdir}/auditd


uninstall-hook:
	rm ${DESTDIR}${sysconfigdir}/auditd
	rm ${DESTDIR}${dispconfigdir}/${dispconfig}
	rm ${DESTDIR}${sysconfdir}/${libconfig}
	rm ${DESTDIR}${initdir}/auditd

