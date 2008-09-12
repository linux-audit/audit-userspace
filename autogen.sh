#! /bin/sh
set -x -e
# --no-recursive is available only in recent autoconf versions
autoreconf -fv --install
(cd system-config-audit; ./autogen.sh)
mv INSTALL.tmp INSTALL
