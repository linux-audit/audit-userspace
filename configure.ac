
dnl
define([AC_INIT_NOTICE],
[### Generated automatically using autoconf version] AC_ACVERSION [
### Copyright 2005-24 Steve Grubb <sgrubb@redhat.com>
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
AC_INIT([audit], [4.0.2])
AC_PREREQ([2.50])dnl
AC_CONFIG_HEADERS([config.h])

echo Configuring auditd $VERSION

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE
LT_INIT
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
AX_PROG_CC_FOR_BUILD

echo .
echo Checking for header files
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([time_t])
dnl; next is needed for old compilers and plugins/ids/Makefile.am
AM_PROG_CC_C_O
AC_CHECK_DECLS([AUDIT_FEATURE_VERSION], [], [], [[#include <linux/audit.h>]])
AC_CHECK_MEMBERS([struct audit_status.feature_bitmap], [], [], [[#include <linux/audit.h>]])
AC_CHECK_DECLS([AUDIT_VERSION_BACKLOG_WAIT_TIME], [], [], [[#include <linux/audit.h>]])
AC_CHECK_DECLS([AUDIT_STATUS_BACKLOG_WAIT_TIME], [], [], [[#include <linux/audit.h>]])
AC_CHECK_DECLS([AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL], [], [], [[#include <linux/audit.h>]])
AC_CHECK_DECLS([ADDR_NO_RANDOMIZE],,, [#include <sys/personality.h>])
dnl; posix_fallocate is used in audisp-remote
AC_CHECK_FUNCS([posix_fallocate])
dnl; signalfd is needed for libev
AC_CHECK_FUNC([signalfd], [], [ AC_MSG_ERROR([The signalfd system call is necessary for auditd]) ])
dnl; check if rawmemchr is available
AC_CHECK_FUNCS([rawmemchr])
dnl; check if faccessat is available
AC_CHECK_FUNCS([faccessat])
dnl; check if strndupa is available
AC_LINK_IFELSE(
  [AC_LANG_SOURCE(
    [[
      #define _GNU_SOURCE
      #include <string.h>
      int main() { (void) strndupa("test", 10); return 0; }]])],
 [AC_DEFINE(HAVE_STRNDUPA, 1, [Let us know if we have it or not])],
 []
)

AC_MSG_CHECKING(__attr_access support)
AC_COMPILE_IFELSE(
  [AC_LANG_SOURCE(
    [[
      #include <stdio.h>
      int audit_fgets(char *buf, size_t blen, int fd)
        __attr_access ((__write_only__, 1, 2));
      int main(void) { return 0; }]])],
  [ACCESS="yes"],
  [ACCESS="no"]
)
AC_MSG_RESULT($ACCESS)

AC_MSG_CHECKING(__attr_dealloc_free support)
AC_COMPILE_IFELSE(
  [AC_LANG_SOURCE(
    [[
      #include <stdio.h>
      extern char *audit_encode_nv_string(const char *name, const char *value,
                                          unsigned int vlen)
                                          __attr_dealloc_free;
      int main(void) { return 0; }]])],
  [DEALLOC="yes"],
  [DEALLOC="no"]
)
AC_MSG_RESULT($DEALLOC)

dnl; pthread_yield is used in zos-remote
OLDLIBS="$LIBS"
AC_SEARCH_LIBS(pthread_yield, pthread, 
	[AC_DEFINE(HAVE_PTHREAD_YIELD, 1, [Define to 1 if we have pthread_yield])], [])
LIBS="$OLDLIBS"

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

withval=""
AC_MSG_CHECKING(whether to create python3 bindings)
AC_ARG_WITH(python3,
AS_HELP_STRING([--with-python3],[enable building python3 bindings]),
use_python3=$withval,
use_python3=auto)
if test "x$use_python3" = xno ; then
	AC_MSG_RESULT(no)
else
	AC_MSG_RESULT(investigating)
	AC_PATH_PROG([use_python3], [python3-config], [no])
	if test "x$use_python3" = xno ; then
		if test "x$withval" = xyes ; then
			echo "Python3 bindings were selected but python3-config was not found."
			echo "Please ensure that it's installed or pass --without-python3 to ./configure"
			exit 1
		fi
		echo "Python3 bindings will NOT be built"
	else
	echo "Python3 bindings WILL be built"
	use_python3=yes
	AM_PATH_PYTHON([3.1],, [:])
	PYTHON3_CFLAGS=`python3-config --cflags 2> /dev/null`
	PYTHON3_LIBS=`python3-config --libs 2> /dev/null`
	PYTHON3_INCLUDES=`python3-config --includes 2> /dev/null`
	AC_SUBST(PYTHON3_CFLAGS)
	AC_SUBST(PYTHON3_LIBS)
	AC_SUBST(PYTHON3_INCLUDES)
	fi
fi
AM_CONDITIONAL(USE_PYTHON3, test ${use_python3} = "yes")

if test "x$use_python" = "xyes" || test "x$use_python3" = "xyes" ; then
	AC_CHECK_PROG([SWIG],[swig],[swig], [no])
	AS_IF([test x"$SWIG" == x"no"], [AC_MSG_ERROR([Please install swig before configuring (required by python/python3).])])
fi

withval=""
AC_MSG_CHECKING(whether to create Go language bindings)
AC_ARG_WITH(golang,
AS_HELP_STRING([--with-golang],[enable building golang bindings]),
use_golang=$withval,
use_golang=auto)
if test "x$use_golang" = xno ; then
    golang_found="no"
    AC_MSG_RESULT(no)
else
    AC_MSG_RESULT(testing)
    AC_CHECK_PROG([GOLANG],[go],[go],[no])
    AS_IF([test "x$GOLANG" != "xno"],[
	AC_MSG_NOTICE(Go bindings will be built)
        golang_found="yes"

        # Substitute some golang environment.
        GOROOT=`$GOLANG env GOROOT`
        AC_SUBST([GOROOT])
    ], [
	if test "x$use_golang" = xyes ; then
		AC_MSG_ERROR([Go language explicitly requested and program not found])
	else
		AC_MSG_WARN(Go not found - go bindings will not be made)
	fi
    ])
fi
AM_CONDITIONAL(HAVE_GOLANG, test "x${golang_found}" = "xyes")

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

#audisp zos-remote plugin
AC_ARG_ENABLE(zos-remote,
	      [AS_HELP_STRING([--disable-zos-remote],
			      [Disable audisp ZOS remote plugin])],
	      enable_zos_remote=$enableval,
	      enable_zos_remote=yes)
if test $enable_zos_remote = yes; then
	AC_CHECK_HEADER(lber.h, ldap_headers=yes, ldap_headers=no)
	AC_CHECK_LIB(lber, ber_free, LDAP_LDADD=-llber)
	if test x$LDAP_LDADD = x ; then
		AC_MSG_ERROR(zos remote support was requested but the openldap library was not found)
	fi
	if test $ldap_headers = no ; then
		AC_MSG_ERROR(openldap libraries found but headers are missing)
	fi
fi

AC_MSG_CHECKING(whether to include audisp ZOS remote plugin)
AM_CONDITIONAL(ENABLE_ZOS_REMOTE, test "x$enable_zos_remote" != "xno")
AC_MSG_RESULT($enable_zos_remote)

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

# ids
AC_MSG_CHECKING(whether to enable experimental options)
AC_ARG_ENABLE(experimental,
	[AS_HELP_STRING([--enable-experimental],[Enable experimental audit components @<:@default=no@:>@])],
        [case "${enableval}" in
         yes) want_exper="yes" ;;
          no) want_exper="no" ;;
           *) AC_MSG_ERROR(bad value ${enableval} for --enable-experimental) ;;
         esac],
	[want_exper="no"]
)
AM_CONDITIONAL(ENABLE_EXPERIMENTAL, test x$want_exper = xyes)
AC_MSG_RESULT($want_exper)

# linux/fanotify.h
AC_CHECK_HEADER(linux/fanotify.h, [ AC_DEFINE(USE_FANOTIFY, [],
	[Defined when fanotify headers are found]) ])

withval=""
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

withval=""
AC_ARG_WITH(warn,
[  --with-warn             turn on warnings [[default=yes]]],
[
if test "x${withval}" = xyes; then
        WARNS="$ALLWARNS"
else
        WARNS=""
fi
],WARNS="$ALLWARNS")

WFLAGS=""
AC_MSG_CHECKING(for -Wformat-truncation)
TMPCFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} -Wformat-truncation"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[WFLAGS="-Wno-format-truncation"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)])
CFLAGS="${TMPCFLAGS}"
CFLAGS="${CFLAGS} -Wunused-but-set-variable"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[WFLAGS="${WFLAGS} -Wno-unused-but-set-variable"
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)])
CFLAGS="${TMPCFLAGS}"
AC_SUBST(WFLAGS)

withval=""
AC_MSG_CHECKING(whether to include arm eabi processor support)
AC_ARG_WITH(arm,
AS_HELP_STRING([--with-arm],[enable Arm eabi processor support]),
use_arm=$withval,
use_arm=no)
if test x$use_arm != xno ; then
      AC_DEFINE(WITH_ARM,1,[Define if you want to enable Arm eabi processor support.])
fi
AM_CONDITIONAL(USE_ARM, test x$use_arm = xyes)
AC_MSG_RESULT($use_arm)

withval=""
AC_MSG_CHECKING(whether to include aarch64 processor support)
AC_ARG_WITH(aarch64,
AS_HELP_STRING([--with-aarch64],[enable Aarch64 processor support]),
use_aarch64=$withval,
use_aarch64=no)
if test x$use_aarch64 != xno ; then
      AC_DEFINE(WITH_AARCH64,1,[Define if you want to enable Aarch64 processor support.])
fi
AM_CONDITIONAL(USE_AARCH64, test x$use_aarch64 = xyes)
AC_MSG_RESULT($use_aarch64)

withval=""
AC_MSG_CHECKING(whether to use apparmor)
AC_ARG_WITH(apparmor,
AS_HELP_STRING([--with-apparmor],[enable AppArmor events]),
use_apparmor=$withval,
use_apparmor=no)
if test x$use_apparmor != xno ; then
      AC_DEFINE(WITH_APPARMOR,1,[Define if you want to enable AppArmor events.])
fi
AC_MSG_RESULT($use_apparmor)

withval=""
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
		AC_LINK_IFELSE([AC_LANG_PROGRAM(
			[[ int allow_severity; int deny_severity; ]],
			[[ hosts_access(); ]])],[],
			[ AC_MSG_ERROR(Could not find the $withval library.  You must first install tcp_wrappers.) ])
		LIBS="$OLDLIBS"
		;;
	esac ],
	AC_MSG_RESULT(no)
)
if test x"$LIBWRAP_LIBS" != "x"; then
	AC_DEFINE_UNQUOTED(HAVE_LIBWRAP, [], Define if tcp_wrappers support is enabled )
fi

withval=""
AC_MSG_CHECKING(whether to include io_uring support)
AC_ARG_WITH(io_uring,
AS_HELP_STRING([--with-io_uring],[enable io_uring support]),
use_io_uring=$withval,
use_io_uring=no)
if test x$use_io_uring != xno ; then
     AC_DEFINE(WITH_IO_URING,1,[Define if you want to enable io_uring support.])
fi
# AM_CONDITIONAL(USE_IO_URING, test x$use_io_uring = xyes)
AC_MSG_RESULT($use_io_uring)

# linux/ipx.h - deprecated in 2018
AC_CHECK_HEADER(linux/ipx.h, ipx_headers=yes, ipx_headers=no)
if test $ipx_headers = yes ; then
	AC_DEFINE(HAVE_IPX_HEADERS,1,[IPX packet interpretation])
fi

# See if we want to support lower capabilities for plugins
LIBCAP_NG_PATH

AC_SUBST(DEBUG)
AC_SUBST(LIBWRAP_LIBS)
#AC_SUBST(libev_LIBS)

AC_CONFIG_FILES(Makefile common/Makefile lib/Makefile lib/audit.pc lib/test/Makefile auparse/Makefile auparse/test/Makefile auparse/auparse.pc src/Makefile src/libev/Makefile src/test/Makefile docs/Makefile rules/Makefile init.d/Makefile audisp/Makefile audisp/plugins/Makefile audisp/plugins/af_unix/Makefile audisp/plugins/remote/Makefile audisp/plugins/zos-remote/Makefile audisp/plugins/syslog/Makefile audisp/plugins/filter/Makefile audisp/plugins/ids/Makefile audisp/plugins/ids/rules/Makefile audisp/plugins/statsd/Makefile bindings/Makefile bindings/python/Makefile bindings/python/python3/Makefile bindings/golang/Makefile bindings/swig/Makefile bindings/swig/src/Makefile bindings/swig/python3/Makefile tools/Makefile tools/aulast/Makefile tools/aulastlog/Makefile tools/ausyscall/Makefile m4/Makefile)
AC_OUTPUT

echo .
echo "

  Auditd Version:         $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
  __attr_access support:  $ACCESS
  __attr_dealloc_free support:  $DEALLOC
"
