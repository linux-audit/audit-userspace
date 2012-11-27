dnl
define([AC_INIT_NOTICE],
[### Generated automatically using autoconf version] AC_ACVERSION [
### Copyright 2005-12 Steve Grubb <sgrubb@redhat.com>
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
AC_INIT(audit,2.2.2)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)

echo Configuring auditd $VERSION

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
OLDLIBS="$LIBS"
m4_include([src/libev/libev.m4])
libev_LIBS="$LIBS"
LIBS="$OLDLIBS"

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
AM_PROG_CC_C_O
AC_CHECK_DECLS([MS_DIRSYNC], [], [], [[#include <sys/mount.h>]])

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

AC_MSG_CHECKING(whether to create python bindings)
AC_ARG_WITH(python,
AS_HELP_STRING([--with-python],[enable building python bindings]),
use_python=$withval,
use_python=auto)
if test x$use_python = xno ; then
	python_found="no"
	AC_MSG_RESULT(no)
else
AC_MSG_RESULT(testing)
AM_PATH_PYTHON
if test -f /usr/include/python${am_cv_python_version}/Python.h ; then
	python_found="yes"
	AC_MSG_NOTICE(Python bindings will be built)
else
	python_found="no"
	if test x$use_python = xyes ; then
		AC_MSG_ERROR([Python explicitly required and python headers found])
	else
		AC_MSG_WARN("Python headers not found - python bindings will not be made")
	fi
fi
fi
AM_CONDITIONAL(HAVE_PYTHON, test ${python_found} = "yes")

#auditd listener
AC_MSG_CHECKING(whether to include auditd network listener support)
AC_ARG_ENABLE(listener,
	      [AS_HELP_STRING([--disable-listener],
			      [Disable auditd network listener support])],
	      enable_listener=$enableval,
	      enable_listener=yes)
if test "x$enable_listener" != "xno"; then
	AC_DEFINE(USE_LISTENER, 1,
		  [Define if you want to use the auditd network listener.])
fi
AM_CONDITIONAL(ENABLE_LISTENER, test "x$enable_listener" != "xno")
AC_MSG_RESULT($enable_listener)

#gssapi
AC_ARG_ENABLE(gssapi_krb5,
	[AS_HELP_STRING([--enable-gssapi-krb5],[Enable GSSAPI Kerberos 5 support @<:@default=no@:>@])],
        [case "${enableval}" in
         yes) want_gssapi_krb5="yes" ;;
          no) want_gssapi_krb5="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-gssapi-krb5) ;;
         esac],
	[want_gssapi_krb5="no"]
)
if test $want_gssapi_krb5 = yes; then
	AC_CHECK_LIB(gssapi_krb5, gss_acquire_cred, [
		AC_CHECK_HEADER(gssapi/gssapi.h, [
			AC_DEFINE(USE_GSSAPI,,
				  Define if you want to use GSSAPI)
			gss_libs="-lgssapi_krb5 -lkrb5"
			AC_SUBST(gss_libs)
		])
	])
fi
AM_CONDITIONAL(ENABLE_GSSAPI, test x$want_gssapi_krb5 = xyes)

#systemd
AC_ARG_ENABLE(systemd,
	[AS_HELP_STRING([--enable-systemd],[Enable systemd init scripts @<:@default=no@:>@])],
        [case "${enableval}" in
         yes) want_systemd="yes" ;;
          no) want_systemd="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-systemd) ;;
         esac],
	[want_systemd="no"]
)
AM_CONDITIONAL(ENABLE_SYSTEMD, test x$want_systemd = xyes)

ALLDEBUG="-g"
AC_ARG_WITH(debug,
[  --with-debug            turn on debugging [[default=no]]],
[
if test "x${withval}" = xyes; then
        DEBUG="$ALLDEBUG"
        OPT="-O"
        AM_CONDITIONAL(DEBUG, true)
else
        DEBUG="-DNDEBUG"
        AM_CONDITIONAL(DEBUG, false)
fi
],
[ DEBUG="-DNDEBUG"; AM_CONDITIONAL(DEBUG, false) ])

AC_ARG_WITH(warn,
[  --with-warn             turn on warnings [[default=yes]]],
[
if test "x${withval}" = xyes; then
        WARNS="$ALLWARNS"
else
        WARNS=""
fi
],WARNS="$ALLWARNS")

AC_MSG_CHECKING(whether to include alpha processor support)
AC_ARG_WITH(alpha,
AS_HELP_STRING([--with-alpha],[enable Alpha processor support]),
use_alpha=$withval,
use_alpha=no)
if test x$use_alpha != xno ; then
      AC_DEFINE(WITH_ALPHA,1,[Define if you want to enable Alpha processor support.])
fi
AM_CONDITIONAL(USE_ALPHA, test x$use_alpha = xyes)
AC_MSG_RESULT($use_alpha)

AC_MSG_CHECKING(whether to include arm eabi processor support)
AC_ARG_WITH(armeb,
AS_HELP_STRING([--with-armeb],[enable Arm eabi processor support]),
use_armeb=$withval,
use_armeb=no)
if test x$use_armeb != xno ; then
      AC_DEFINE(WITH_ARMEB,1,[Define if you want to enable Arm eabi processor support.])
fi
AM_CONDITIONAL(USE_ARMEB, test x$use_armeb = xyes)
AC_MSG_RESULT($use_armeb)

AC_MSG_CHECKING(whether to use apparmor)
AC_ARG_WITH(apparmor,
AS_HELP_STRING([--with-apparmor],[enable AppArmor events]),
use_apparmor=$withval,
use_apparmor=no)
if test x$use_apparmor != xno ; then
      AC_DEFINE(WITH_APPARMOR,1,[Define if you want to enable AppArmor events.])
fi
AC_MSG_RESULT($use_apparmor)

AC_MSG_CHECKING(whether to use prelude)
AC_ARG_WITH(prelude,
AS_HELP_STRING([--with-prelude],[enable prelude IDS support]),
use_prelude=$withval,
use_prelude=no)
AC_MSG_RESULT($use_prelude)
if test x$use_prelude = xno ; then
	have_prelude=no;
else
      AC_CHECK_LIB(prelude, prelude_init,
                 have_prelude=yes, have_prelude=no)
      if test x$have_prelude = xno ; then
        AC_MSG_ERROR([Prelude explicitly required and prelude library not found])
      else
	LIBPRELUDE_CFLAGS=`libprelude-config --pthread-cflags 2>/dev/null`
	LIBPRELUDE_LDFLAGS=`libprelude-config --ldflags 2>/dev/null`
        AC_MSG_RESULT(yes)
      fi
fi
AM_CONDITIONAL(HAVE_PRELUDE, test x$have_prelude = xyes)

AC_MSG_CHECKING(whether to use libwrap)
AC_ARG_WITH(libwrap,
[  --with-libwrap[=PATH]   Compile in libwrap (tcp_wrappers) support.],
[ case "$withval" in
	no)
		AC_MSG_RESULT(no)
		;;
	yes)
		AC_MSG_RESULT(yes)
		AC_CHECK_HEADER(tcpd.h, [],
			AC_MSG_ERROR([Could not find libwrap headers]),)
		AC_CHECK_LIB(wrap, request_init, [ LIBWRAP_LIBS="-lwrap" ])
		AC_CHECK_LIB(nsl, yp_get_default_domain, [
			LIBWRAP_LIBS="$LIBWRAP_LIBS -lnsl" ])
		;;
	*)
		AC_MSG_RESULT(yes)
		if test -d "$withval"; then
			LIBWRAP_LIBS="-L$withval -lwrap"
		else
			LIBWRAP_LIBS="$withval"
		fi
		AC_CHECK_HEADER(tcpd.h, [],
			AC_MSG_ERROR([Could not find libwrap headers]))
		AC_CHECK_LIB(wrap, request_init, [])
		AC_CHECK_LIB(nsl, yp_get_default_domain, [
			LIBWRAP_LIBS="$LIBWRAP_LIBS -lnsl" ])
		OLDLIBS="$LIBS"
		LIBS="$LIBWRAP_LIBS $LIBS"
		AC_TRY_LINK([ int allow_severity; int deny_severity; ],
			[ hosts_access(); ], [],
			[ AC_MSG_ERROR(Could not find the $withval library.  You must first install tcp_wrappers.) ])
		LIBS="$OLDLIBS"
		;;
	esac ],
	AC_MSG_RESULT(no)
)
if test x"$LIBWRAP_LIBS" != "x"; then
	AC_DEFINE_UNQUOTED(HAVE_LIBWRAP, [], Define if tcp_wrappers support is enabled )
fi

# See if we want to support lower capabilities for plugins
LIBCAP_NG_PATH

AC_SUBST(DEBUG)
AC_SUBST(LIBWRAP_LIBS)
#AC_SUBST(libev_LIBS)
AC_SUBST(LIBPRELUDE_CFLAGS)
AC_SUBST(LIBPRELUDE_LDFLAGS)

AC_OUTPUT(Makefile lib/Makefile lib/test/Makefile auparse/Makefile auparse/test/Makefile src/Makefile src/mt/Makefile src/libev/Makefile src/test/Makefile swig/Makefile docs/Makefile init.d/Makefile audisp/Makefile audisp/plugins/Makefile audisp/plugins/builtins/Makefile audisp/plugins/prelude/Makefile audisp/plugins/remote/Makefile audisp/plugins/zos-remote/Makefile bindings/Makefile bindings/python/Makefile tools/Makefile tools/aulast/Makefile tools/aulastlog/Makefile tools/ausyscall/Makefile tools/auvirt/Makefile)

echo .
echo "

  Auditd Version:         $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
"
