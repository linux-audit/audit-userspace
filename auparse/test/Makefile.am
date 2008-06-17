# Makefile.am -- 
# Copyright 2006-07 Red Hat Inc., Durham, North Carolina.
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
check_SCRIPTS = auparse_test.py
EXTRA_DIST = auparse_test.ref README

INCLUDES = -I.. -I${top_srcdir}/lib

auparse_test_SOURCES = auparse_test.c
auparse_test_LDFLAGS = -static
auparse_test_LDADD = -L../.libs/ -L../../lib/.libs -lauparse -laudit
auparse_test_DEPENDENCIES = ../.libs/libauparse.a ../*.c ../*.h

check: auparse_test
	LD_LIBRARY_PATH=../.libs ./auparse_test.py > auparse_test.cur
	diff -u auparse_test.ref auparse_test.cur

diffcheck: auparse_test
	./auparse_test > auparse_test.cur
	diff auparse_test.ref auparse_test.cur

memcheck: auparse_test
	valgrind --leak-check=yes --show-reachable=yes ./auparse_test 

pycheck: auparse_test.py ../../bindings/python/build/*/auparse.so
	LD_LIBRARY_PATH=../.libs ./auparse_test.py

pydiffcheck: auparse_test.py ../../bindings/python/build/*/auparse.so
	LD_LIBRARY_PATH=../.libs ./auparse_test.py > auparse_test.cur
	diff auparse_test.ref auparse_test.cur

pymemcheck: auparse_test.py ../../bindings/python/build/*/auparse.so
	LD_LIBRARY_PATH=../.libs valgrind --leak-check=yes --show-reachable=yes python ./auparse_test.py

../../bindings/python/build/*/auparse.so: ../../bindings/python/auparse_python.c
	cd ../../bindings/python && make
clean-generic:
	rm -f *.cur
