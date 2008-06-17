# A simple object holding all configuration.
#
# Copyright (C) 2007 Red Hat, Inc.  All rights reserved.
# This copyrighted material is made available to anyone wishing to use, modify,
# copy, or redistribute it subject to the terms and conditions of the GNU
# General Public License v.2.  This program is distributed in the hope that it
# will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
# implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.  You should have
# received a copy of the GNU General Public License along with this program; if
# not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
# incorporated in the source code or documentation are not subject to the GNU
# General Public License and may only be used or replicated with the express
# permission of Red Hat, Inc.
#
# Red Hat Author: Miloslav Trmac <mitr@redhat.com>
from auditd_config import AuditdConfig
from audit_rules import AuditRules

__all__ = ('Config')

class Config(object):
    '''The top-level holder of audit configuration.'''

    def __init__(self, client):
        self.client = client
        self.auditd = AuditdConfig()
        self.rules = AuditRules()

    def read(self):
        '''Read all configuration files.

        Raise IOError on error.  Invalid lines are reported on stdout and
        otherwise ignored.

        '''
        self.auditd.read(self.client)
        self.rules.read(self.client)

    def write(self):
        '''Write all configuration files.

        Raise IOError on error, ValueError on invalid configuration.

        '''
        self.auditd.write(self.client)
        self.rules.write(self.client)

    def apply(self):
        '''Apply the current configuration.

        Raise IOError on error.

        '''
        self.client.apply()

    def __eq__(self, config):
        if type(config) is not Config:
            return NotImplemented
        # See AuditdConfig.__eq__, AuditRules.__eq__
        return self.auditd == config.auditd and self.rules == config.rules

    def __ne__(self, config):
        return not self.__eq__(config)
