# Makefile.am--
# Copyright 2004-07,2012-13,2018 Red Hat Inc., Durham, North Carolina.
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
EXTRA_DIST = auditd.init auditd.service auditd.sysconfig auditd.conf \
	auditd.cron libaudit.conf auditd.condrestart \
	auditd.reload auditd.restart auditd.resume \
	auditd.rotate auditd.state auditd.stop \
	audit-stop.rules augenrules audit-functions
libconfig = libaudit.conf
if ENABLE_SYSTEMD
initdir = /usr/lib/systemd/system
legacydir = $(libexecdir)/initscripts/legacy-actions/auditd
else
initdir = $(sysconfdir)/rc.d/init.d
sysconfigdir = $(sysconfdir)/sysconfig
endif

auditdir = $(sysconfdir)/audit
auditrdir = $(auditdir)/rules.d
dist_audit_DATA = auditd.conf audit-stop.rules
sbin_SCRIPTS = augenrules

install-data-hook:
	$(INSTALL_DATA) -D -m 640 ${srcdir}/${libconfig} ${DESTDIR}${sysconfdir}
if ENABLE_SYSTEMD
else
	$(INSTALL_DATA) -D -m 640 ${srcdir}/auditd.sysconfig ${DESTDIR}${sysconfigdir}/auditd
endif

install-exec-hook:
if ENABLE_SYSTEMD
	mkdir -p ${DESTDIR}${initdir}
	mkdir -p ${DESTDIR}${legacydir}
	mkdir -p ${DESTDIR}${libexecdir}
	$(INSTALL_SCRIPT) -D -m 644 ${srcdir}/auditd.service ${DESTDIR}${initdir}
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/auditd.rotate ${DESTDIR}${legacydir}/rotate
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/auditd.resume ${DESTDIR}${legacydir}/resume
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/auditd.reload ${DESTDIR}${legacydir}/reload
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/auditd.state ${DESTDIR}${legacydir}/state
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/auditd.stop ${DESTDIR}${legacydir}/stop
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/auditd.restart ${DESTDIR}${legacydir}/restart
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/auditd.condrestart ${DESTDIR}${legacydir}/condrestart
	$(INSTALL_SCRIPT) -D -m 750 ${srcdir}/audit-functions ${DESTDIR}${libexecdir}
else
	$(INSTALL_SCRIPT) -D ${srcdir}/auditd.init ${DESTDIR}${initdir}/auditd
endif
	chmod 0750 $(DESTDIR)$(sbindir)/augenrules


uninstall-hook:
	rm ${DESTDIR}${sysconfdir}/${libconfig}
if ENABLE_SYSTEMD
	rm ${DESTDIR}${initdir}/auditd.service
	rm ${DESTDIR}${legacydir}/rotate
	rm ${DESTDIR}${legacydir}/resume
	rm ${DESTDIR}${legacydir}/reload
	rm ${DESTDIR}${legacydir}/state
	rm ${DESTDIR}${legacydir}/stop
	rm ${DESTDIR}${legacydir}/restart
	rm ${DESTDIR}${legacydir}/condrestart
else
	rm ${DESTDIR}${sysconfigdir}/auditd
	rm ${DESTDIR}${initdir}/auditd
endif

