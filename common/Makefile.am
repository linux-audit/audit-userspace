# Makefile.am-- 
# Copyright 2018-2023 Red Hat Inc.
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
AM_CFLAGS = -fPIC -DPIC -D_GNU_SOURCE -g
AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/lib

noinst_HEADERS = common.h
libaucommon_la_DEPENDENCIES = ../config.h
libaucommon_la_SOURCES = audit-fgets.c strsplit.c common.c
noinst_LTLIBRARIES = libaucommon.la

