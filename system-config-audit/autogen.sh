#! /bin/sh
set -x -e
autopoint -f
# intltool bug: it tries to use $aux_dir/po/Makefile.in.in
ln -s ../po admin/po
intltoolize --force
rm admin/po

aclocal -I m4
autoconf -Wall
autoheader -Wall
automake -Wall --add-missing
#./configure --enable-Werror
