# Process this file with autoconf to produce a configure script.
AC_INIT([system-config-audit], [0.4.10], [mitr@redhat.com])
AC_COPYRIGHT(
[Copyright (C) 2007, 2009 Red Hat, Inc.  All rights reserved.

This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU General
Public License v.2.  This program is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY expressed or implied, including the implied
warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.  You should have received a copy of
the GNU General Public License along with this program; if not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.  Any Red Hat trademarks that are incorporated in the source
code or documentation are not subject to the GNU General Public License and may
only be used or replicated with the express permission of Red Hat, Inc.

Red Hat Author: Miloslav Trmac <mitr@redhat.com>])
AC_PREREQ(2.59)
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_SRCDIR([src/main_window.py])
AC_CONFIG_AUX_DIR([admin])
AM_INIT_AUTOMAKE([dist-bzip2 no-define subdir-objects -Wall])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AM_PATH_PYTHON([2.4])
GETTEXT_PACKAGE=$PACKAGE
AC_SUBST([GETTEXT_PACKAGE])
IT_PROG_INTLTOOL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Checks for libraries.
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14.6])

# Checks for system services.
AC_SYS_LARGEFILE

# Miscellanous hackery.

# Modify CFLAGS after all tests are run (some of them would fail because
# of the -Werror).
if test "$GCC" = yes ; then
    AC_CACHE_CHECK([for available GCC warning flags],
                   [mitr_cv_prog_gcc_warnings],
    [mitr_cv_prog_gcc_warnings=""
    for i in -Wall -W -Wcast-align -Wmissing-noreturn -Wnested-externs dnl
-Wpointer-arith -Wshadow -Wstrict-prototypes -Wundef -Wwrite-strings; do
        oldcflags=$CFLAGS
        CFLAGS="$CFLAGS $i"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
                [mitr_cv_prog_gcc_warnings="$mitr_cv_prog_gcc_warnings $i"])
        CFLAGS=$oldcflags
     done])
     CFLAGS="$CFLAGS $mitr_cv_prog_gcc_warnings"
     AC_MSG_CHECKING([whether we should use -Werror])
     AC_ARG_ENABLE([Werror],
                   AS_HELP_STRING([--enable-Werror],
                        [use -Werror if compiling with gcc (default is NO)]),
                   [], enable_Werror=no)
     if test "x$enable_Werror" != xno; then
        CFLAGS="$CFLAGS -Werror"
     fi
     AC_MSG_RESULT([$enable_Werror])
fi

AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT
