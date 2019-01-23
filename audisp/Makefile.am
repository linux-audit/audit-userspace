# Makefile.am-- 
# Copyright 2007,2011,2015-16,2018 Red Hat Inc., Durham, North Carolina.
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

SUBDIRS = plugins 
CONFIG_CLEAN_FILES = *.rej *.orig
AM_CPPFLAGS = -D_GNU_SOURCE -fPIC -DPIC -I${top_srcdir} -I${top_srcdir}/lib -I${top_srcdir}/src -I${top_srcdir}/src/libev
LIBS = -L${top_builddir}/lib -laudit 
LDADD = -lpthread

noinst_HEADERS = audispd-pconfig.h audispd-llist.h audispd-config.h \
	queue.h audispd-builtins.h libdisp.h
libdisp_a_SOURCES = audispd.c audispd-pconfig.c queue.c \
	audispd-llist.c audispd-builtins.c
libdisp_a_CFLAGS = -fno-strict-aliasing
noinst_LIBRARIES = libdisp.a

