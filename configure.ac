dnl
define([AC_INIT_NOTICE],
[### Generated automatically using autoconf version] AC_ACVERSION [
### Copyright 2005-08 Steve Grubb <sgrubb@redhat.com>
###
### Permission is hereby granted, free of charge, to any person obtaining a
### copy of this software and associated documentation files (the "Software"),
### to deal in the Software without restriction, including without limitation
### the rights to use, copy, modify, merge, publish, distribute, sublicense,
### and/or sell copies of the Software, and to permit persons to whom the
### Software is furnished to do so, subject to the following conditions:
###
### The above copyright notice and this permission notice shall be included
### in all copies or substantial portions of the Software.
###
### THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
### IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
### FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
### THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
### OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
### ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
### OTHER DEALINGS IN THE SOFTWARE.
###
### For usage, run `./configure --help'
### For more detailed information on installation, read the file `INSTALL'.
###
### If configuration succeeds, status is in the file `config.status'.
### A log of configuration tests is in `config.log'.
])

AC_REVISION($Revision: 1.3 $)dnl
AC_INIT(audit,1.7.5)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)

echo Configuring auditd $VERSION

AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AM_PATH_PYTHON

echo .
echo Checking for programs

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK

echo .
echo Checking for header files
AC_HEADER_STDC
AC_HEADER_TIME

AC_C_CONST
AC_C_INLINE
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])

#AC_CHECK_LIB(pthread, pthread_create)
AM_PROG_CC_C_O

ALLWARNS=""
ALLDEBUG="-g"
OPT="-O"
if test x"$GCC" = x"yes"; then
  OPT="-O2 -pipe"
  case "$target" in
    *linux*)
             ALLWARNS="-W -Wall -Wundef -Wpointer-arith -Wcast-align \
-Wwrite-strings -Waggregate-return -Wstrict-prototypes \
-Wmissing-prototypes -Wmissing-declarations -Wredundant-decls \
-Wnested-externs -Winline -Wfloat-equal -Wchar-subscripts"
             ;;
    esac
fi

ALLDEBUG="-g"
AC_ARG_WITH(debug,
[  --with-debug            turn on debugging [[default=no]]],
[
if test "x${withval}" = xyes; then
        DEBUG="$ALLDEBUG"
        OPT="-O"
        AM_CONDITIONAL(DEBUG, true)
else
        DEBUG=""
        AM_CONDITIONAL(DEBUG, false)
fi
],
[ DEBUG=""; AM_CONDITIONAL(DEBUG, false) ])

AC_ARG_WITH(warn,
[  --with-warn             turn on warnings [[default=yes]]],
[
if test "x${withval}" = xyes; then
        WARNS="$ALLWARNS"
else
        WARNS=""
fi
],WARNS="$ALLWARNS")

AC_ARG_WITH(apparmor,
AS_HELP_STRING([--with-apparmor],[enable AppArmor events]),
use_apparmor=$withval,
use_apparmor=no)
if test x$use_apparmor != xno ; then
      AC_DEFINE(WITH_APPARMOR,1,[Define if you want to enable AppArmor events.])
fi

AC_ARG_WITH(prelude,
AS_HELP_STRING([--with-prelude],[enable prelude IDS support]),
use_prelude=$withval,
use_prelude=no)
if test x$use_prelude = xno ; then
	have_prelude=no;
else
      AC_CHECK_LIB(prelude, prelude_init,
                 have_prelude=yes, have_prelude=no)
      if test x$have_prelude = xno ; then
            AC_MSG_ERROR([Prelude explicitly required and prelude library not found])
      fi
fi
AM_CONDITIONAL(HAVE_PRELUDE, test x$have_prelude = xyes)

AC_CONFIG_SUBDIRS([system-config-audit])
AC_OUTPUT(Makefile lib/Makefile lib/test/Makefile auparse/Makefile auparse/test/Makefile src/Makefile src/mt/Makefile src/libev/Makefile swig/Makefile docs/Makefile init.d/Makefile audisp/Makefile audisp/plugins/Makefile audisp/plugins/builtins/Makefile audisp/plugins/prelude/Makefile audisp/plugins/remote/Makefile audisp/plugins/zos-remote/Makefile audisp/plugins/zos-remote/policy/Makefile bindings/Makefile bindings/python/Makefile tools/Makefile tools/aulastlog/Makefile tools/ausyscall/Makefile)

echo .
echo "

  Auditd Version:         $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
"
