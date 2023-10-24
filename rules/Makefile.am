# Makefile.am --
# Copyright 2016-19 Red Hat Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor 
# Boston, MA 02110-1335, USA.
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#

CONFIG_CLEAN_FILES = *.rej *.orig

EXTRA_DIST = 10-base-config.rules 10-no-audit.rules 11-loginuid.rules \
12-ignore-error.rules  12-cont-fail.rules \
20-dont-audit.rules 21-no32bit.rules 22-ignore-chrony.rules \
23-ignore-filesystems.rules \
30-stig.rules 30-pci-dss-v31.rules 30-ospp-v42.rules \
30-ospp-v42-1-create-failed.rules 30-ospp-v42-1-create-success.rules \
30-ospp-v42-2-modify-failed.rules 30-ospp-v42-2-modify-success.rules \
30-ospp-v42-3-access-failed.rules 30-ospp-v42-3-access-success.rules \
30-ospp-v42-4-delete-failed.rules 30-ospp-v42-4-delete-success.rules \
30-ospp-v42-5-perm-change-failed.rules \
30-ospp-v42-5-perm-change-success.rules \
30-ospp-v42-6-owner-change-failed.rules \
30-ospp-v42-6-owner-change-success.rules \
31-privileged.rules 32-power-abuse.rules \
40-local.rules 41-containers.rules 42-injection.rules 43-module-load.rules \
44-installers.rules \
70-einval.rules 71-networking.rules \
99-finalize.rules README-rules

rulesdir = $(datadir)/audit-rules
dist_rules_DATA = $(EXTRA_DIST)

