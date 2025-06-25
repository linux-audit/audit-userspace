# Makefile.am --
# Copyright 2025 Red Hat Inc.
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
# License along with this program; see the file COPYING.lib. If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
# Boston, MA 02110-1335, USA.
# 
# Authors:
#   Steve Grubb <sgrubb@redhat.com>

AM_CPPFLAGS = -I${top_srcdir}/auplugin -I${top_srcdir}/lib -I${top_srcdir}/auparse
check_PROGRAMS = fgets_test metrics_test
TESTS = $(check_PROGRAMS)

fgets_test_LDADD = ${top_builddir}/auplugin/libauplugin.la
fgets_test_DEPENDENCIES = ${top_builddir}/auplugin/libauplugin.la

metrics_test_LDADD = ${top_builddir}/auplugin/libauplugin.la
metrics_test_DEPENDENCIES = ${top_builddir}/auplugin/libauplugin.la

