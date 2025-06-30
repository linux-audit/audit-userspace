# Makefile.am -- 
# Copyright 2006-08,2014-17 Red Hat Inc.
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
#

CONFIG_CLEAN_FILES = *.loT *.rej *.orig *.cur
noinst_PROGRAMS = auparse_test auparselol_test lookup_test databuf_test \
	auparse_extra_test
TESTS = run_auparse_tests.sh run_auparselol_test.sh lookup_test \
	databuf_test auparse_extra_test
dist_check_SCRIPTS = run_auparse_tests.sh run_auparselol_test.sh
EXTRA_DIST = auparse_test.ref auparse_test.ref.py test.log test2.log test3.log test4.log auditd_raw.sed run_auparse_tests.sh auparse_test.py run_auparselol_test.sh
CLEANFILES = run_auparse_tests.sh run_auparselol_test.sh
DISTCLEANFILES = $(CLEANFILES)

AM_CPPFLAGS = -I${top_srcdir}/auparse -I${top_srcdir}/lib
AM_CFLAGS = -D_GNU_SOURCE -Wno-pointer-sign ${WFLAGS}

lookup_test_SOURCES = lookup_test.c
lookup_test_LDFLAGS = -static
lookup_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la
lookup_test_DEPENDENCIES = ${top_builddir}/auparse/libauparse.la ${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la

auparse_test_SOURCES = auparse_test.c
auparse_test_LDFLAGS = -static
auparse_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la
auparse_test_DEPENDENCIES = ${top_builddir}/auparse/libauparse.la ${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la

auparselol_test_SOURCES = auparselol_test.c
auparselol_test_LDFLAGS = -static
auparselol_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la
auparselol_test_DEPENDENCIES = ${top_builddir}/auparse/libauparse.la ${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la

databuf_test_SOURCES = databuf_test.c
databuf_test_LDFLAGS = -static
databuf_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la
databuf_test_DEPENDENCIES = ${top_builddir}/auparse/libauparse.la ${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la

auparse_extra_test_SOURCES = auparse_extra_test.c
auparse_extra_test_LDFLAGS = -static
auparse_extra_test_LDADD = ${top_builddir}/auparse/libauparse.la \
	${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la
auparse_extra_test_DEPENDENCIES = ${top_builddir}/auparse/libauparse.la ${top_builddir}/lib/libaudit.la ${top_builddir}/common/libaucommon.la

drop_srcdir = sed 's,$(srcdir)/test,test,'


diffcheck: auparse_test auparselol_test
	./auparse_test > auparse_test.cur
	diff -u $(srcdir)/auparse_test.ref auparse_test.cur
	./auparselol_test -f test3.log --check | sort > auparse_test.cur
	sed -f ./auditd_raw.sed test3.log | sort > auparse_test.raw
	diff -u auparse_test.raw auparse_test.cur

memcheck: auparse_test
	valgrind --leak-check=yes --show-reachable=yes ./auparse_test 

pycheck: auparse_test.py
if USE_PYTHON3
	PYTHONPATH=${top_builddir}/bindings/python/python3/.libs/ \
	PYTHONDONTWRITEBYTECODE=1 \
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py
endif

pydiffcheck: auparse_test.py 
if USE_PYTHON3
	PYTHONPATH=${top_builddir}/bindings/python/python3/.libs/ \
	PYTHONDONTWRITEBYTECODE=1 \
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py \
		| $(drop_srcdir) > auparse_test.cur
	diff -u $(srcdir)/auparse_test.ref.py auparse_test.cur
endif

pymemcheck: auparse_test.py
if USE_PYTHON3
	PYTHONPATH=${top_builddir}/bindings/python/python3/.libs/ \
	PYTHONDONTWRITEBYTECODE=1 \
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs srcdir=$(srcdir) valgrind --leak-check=yes --show-reachable=yes python $(srcdir)/auparse_test.py

${top_builddir}/bindings/python/build/*/auparse.so: ${top_srcdir}/bindings/python/auparse_python.c
	cd ${top_builddir}/bindings/python && make
endif

clean-generic:
	$(RM) *.cur
	$(RM) auparse_test.raw
if USE_PYTHON3
	$(RM) ${top_builddir}/bindings/swig/python3/_audit.so
endif
	test "$(top_srcdir)" = "$(top_builddir)" || $(RM) test*.log
