# Copyright (C) 2007, 2008 Red Hat, Inc.  All rights reserved.
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program; if
# not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Red Hat Author: Miloslav Trmac <mitr@redhat.com>

## Process this file with automake to produce Makefile.in

## Settings
ACLOCAL_AMFLAGS = -I m4
applicationsdir = $(datarootdir)/applications
CONFIG_CLEAN_FILES = *.rej *.orig

## Targets
SUBDIRS = po

dist_applications_DATA = system-config-audit.desktop
bin_SCRIPTS = src/system-config-audit
libexec_PROGRAMS = src/system-config-audit-server
dist_pkgdata_DATA = src/system-config-audit.glade
pkgdata_PYTHON = src/auditd_config.py src/audit_rules.py \
	src/client.py src/config.py \
	src/dialog_base.py \
	src/event_type_dialog.py \
	src/field_help.py \
	src/global_dialog.py \
	src/key_dialog.py src/key_list_dialog.py \
	src/lists.py \
	src/main.py src/main_window.py \
	src/rule_dialog.py src/rule_list_dialog.py src/rule_table.py \
	src/save_dialog.py \
	src/type_list_dialog.py \
	src/util.py \
	src/watch_dialog.py src/watch_list_dialog.py
nodist_pkgdata_PYTHON = src/settings.py src/server.py

install-fedora: install admin/system-config-audit-server.console
	mv $(DESTDIR)$(libexecdir)/system-config-audit-server \
		$(DESTDIR)$(libexecdir)/system-config-audit-server-real
	ln -s /usr/bin/consolehelper \
		$(DESTDIR)$(libexecdir)/system-config-audit-server
	$(mkdir_p) $(DESTDIR)$(sysconfdir)/pam.d \
		$(DESTDIR)$(sysconfdir)/security/console.apps
	$(INSTALL_DATA) $(srcdir)/admin/system-config-audit-server.pam \
		$(DESTDIR)$(sysconfdir)/pam.d/system-config-audit-server
	$(INSTALL_DATA) admin/system-config-audit-server.console \
		$(DESTDIR)$(sysconfdir)/security/console.apps/system-config-audit-server

## Rules
CLEANFILES = $(applications_DATA) $(bin_SCRIPTS) $(nodist_pkgdata_PYTHON) \
	admin/system-config-audit-server.console
DISTCLEANFILES = $(CLEANFILES) \
	intltool-extract intltool-merge intltool-update
EXTRA_DIST = admin/intltool-extract.in admin/intltool-merge.in \
	admin/intltool-update.in admin/system-config-audit-server.console.in \
	admin/system-config-audit-server.pam \
	src/settings.py.in src/system-config-audit.in \
	system-config-audit.desktop.in

src_system_config_audit_server_SOURCES = src/server.c src/server.h
src_system_config_audit_server_CPPFLAGS = $(AM_CPPFLAGS) \
	-DLOCALEDIR='"$(localedir)"' -DSYSCONFDIR='"$(sysconfdir)"' \
	-I$(top_srcdir)/../lib
src_system_config_audit_server_LDADD = $(top_builddir)/../lib/libaudit.la

admin/system-config-audit-server.console: \
		admin/system-config-audit-server.console.in Makefile
	$(mkdir_p) admin
	sed 's|@''libexecdir''@|$(libexecdir)|g' \
		< $(srcdir)/admin/system-config-audit-server.console.in > $@

src/server.py: src/server.h Makefile
	$(mkdir_p) src
	 sed -n 's/#define[ \t]\+\([^ \t]\+\)[ \t]\+\([^ \t]\+\)\([ \t]\+.*\)\?$$/\1 = \2/p' \
		< $(srcdir)/src/server.h > $@

src/settings.py: src/settings.py.in Makefile
	$(mkdir_p) src
	sed -e 's|@''PACKAGE''@|$(PACKAGE)|g' \
		-e 's|@''PACKAGE_VERSION''@|$(PACKAGE_VERSION)|g' \
		-e 's|@''libexecdir''@|$(libexecdir)|g' \
		-e 's|@''localedir''@|$(localedir)|g' \
		-e 's|@''pkgdatadir''@|$(pkgdatadir)|g' \
		< $(srcdir)/src/settings.py.in > $@

src/system-config-audit: src/system-config-audit.in Makefile
	$(mkdir_p) src
	sed -e 's|@''PYTHON''@|$(PYTHON)|g' \
		-e 's|@''SHELL''@|$(SHELL)|g' \
		-e 's|@''pkgdatadir''@|$(pkgdatadir)|g' \
		< $(srcdir)/src/system-config-audit.in > $@

@INTLTOOL_DESKTOP_RULE@

clean-generic:
	rm -f system-config-audit.desktop
