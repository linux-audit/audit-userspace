# Makefile.am --
# Copyright 2007,2008,2011 Red Hat Inc., Durham, North Carolina.
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
#   Miloslav Trmac <mitr@redhat.com>
# 

CONFIG_CLEAN_FILES = *.loT *.rej *.orig

pyexec_LTLIBRARIES = auparse.la

auparse_la_SOURCES = auparse_python.c
auparse_la_CPPFLAGS = -I$(top_srcdir)/auparse $(AM_CPPFLAGS) -I/usr/include/python$(PYTHON_VERSION) -fno-strict-aliasing
auparse_la_LDFLAGS = -module -avoid-version -Wl,-z,relro
auparse_la_LIBADD = ../../auparse/libauparse.la ../../lib/libaudit.la
