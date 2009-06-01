#! /bin/sh
set -x -e
autopoint -f
# intltool bug: it tries to use $aux_dir/po/Makefile.in.in in older versions
ln -s ../po admin/po
# ... and it puts dummy intltool-*.in to ., not to $aux_dir in newer versions
rm admin/intltool-{extract,merge,update}.in
touch admin/intltool-{extract,merge,update}.in
intltoolize --force
rm admin/po

aclocal -I m4
autoconf -Wall
autoheader -Wall
automake -Wall --add-missing
#./configure --enable-Werror
