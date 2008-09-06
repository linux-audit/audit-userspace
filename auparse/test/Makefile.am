# Makefile.am -- 
# Copyright 2006-08 Red Hat Inc., Durham, North Carolina.
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

CONFIG_CLEAN_FILES = Makefile.in *.loT *.rej *.orig

check_PROGRAMS = auparse_test 
dist_check_SCRIPTS = auparse_test.py
EXTRA_DIST = auparse_test.ref test.log test2.log

INCLUDES = -I.. -I${top_srcdir}/lib

auparse_test_SOURCES = auparse_test.c
auparse_test_LDFLAGS = -static
auparse_test_LDADD = -L${top_builddir}/auparse/.libs \
	-L${top_builddir}/lib/.libs -lauparse -laudit
auparse_test_DEPENDENCIES = ${top_builddir}/auparse/.libs/libauparse.a \
	$(srcdir)/../*.c $(srcdir)/../*.h

drop_srcdir = sed 's,$(srcdir)/test,test,'

check: auparse_test
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py \
		| $(drop_srcdir) > auparse_test.cur
	diff -u $(srcdir)/auparse_test.ref auparse_test.cur
	echo -e "===================\nAuparse Test Passes\n==================="

diffcheck: auparse_test
	./auparse_test > auparse_test.cur
	diff $(srcdir)/auparse_test.ref auparse_test.cur

memcheck: auparse_test
	valgrind --leak-check=yes --show-reachable=yes ./auparse_test 

pycheck: auparse_test.py ${top_builddir}/bindings/python/build/*/auparse.so
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py

pydiffcheck: auparse_test.py ${top_builddir}/bindings/python/build/*/auparse.so
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs \
		srcdir=$(srcdir) $(srcdir)/auparse_test.py \
		| $(drop_srcdir) > auparse_test.cur
	diff $(srcdir)/auparse_test.ref auparse_test.cur

pymemcheck: auparse_test.py ${top_builddir}/bindings/python/build/*/auparse.so
	LD_LIBRARY_PATH=${top_builddir}/auparse/.libs srcdir=$(srcdir) valgrind --leak-check=yes --show-reachable=yes python $(srcdir)/auparse_test.py

${top_builddir}/bindings/python/build/*/auparse.so: ${top_srcdir}/bindings/python/auparse_python.c
	cd ${top_builddir}/bindings/python && make
clean-generic:
	rm -f *.cur
