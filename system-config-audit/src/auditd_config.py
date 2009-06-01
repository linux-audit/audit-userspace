# Auditd.conf parsing and updating.
#
# Copyright (C) 2007, 2008 Red Hat, Inc.  All rights reserved.
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
import re
import sys

import server
import util

__all__ = ('AuditdConfig')

# A shorthand
ParsingError = util.ParsingError

class AuditdConfig(object):

    '''Audit daemon config file.'''

    FAILURE_EMAIL = 'email'
    FAILURE_EXEC = 'exec'
    FAILURE_HALT = 'halt'
    FAILURE_IGNORE = 'ignore'
    FAILURE_SINGLE = 'single'
    FAILURE_SUSPEND = 'suspend'
    FAILURE_SYSLOG = 'syslog'
    # 'exec' is excluded
    __failure_action_values = {'email': FAILURE_EMAIL, 'halt': FAILURE_HALT,
                               'ignore': FAILURE_IGNORE,
                               'single': FAILURE_SINGLE,
                               'suspend': FAILURE_SUSPEND,
                               'syslog': FAILURE_SYSLOG}

    FLUSH_DATA = 'data'
    FLUSH_INCREMENTAL = 'incremental'
    FLUSH_NONE = 'none'
    FLUSH_SYNC = 'sync'
    __flush_values = {'data': FLUSH_DATA, 'incremental': FLUSH_INCREMENTAL,
                      'none': FLUSH_NONE, 'sync': FLUSH_SYNC}

    FORMAT_NOLOG = 'nolog'
    FORMAT_RAW = 'raw'
    __format_values = {'nolog': FORMAT_NOLOG, 'raw': FORMAT_RAW}

    NAME_FQD = 'fqd'
    NAME_HOSTNAME = 'hostname'
    NAME_NONE = 'none'
    NAME_NUMERIC = 'numeric'
    NAME_USER = 'user'
    __name_values = {'fqd': NAME_FQD, 'hostname': NAME_HOSTNAME,
                     'none': NAME_NONE, 'numeric': NAME_NUMERIC,
                     'user': NAME_USER}

    QOS_LOSSLESS = 'lossless'
    QOS_LOSSY = 'lossy'
    __disp_qos_values = {'lossy': QOS_LOSSY, 'lossless' : QOS_LOSSLESS}

    SIZE_IGNORE = 'ignore'
    SIZE_KEEP_LOGS = 'keep_logs'
    SIZE_ROTATE = 'rotate'
    SIZE_SUSPEND = 'suspend'
    SIZE_SYSLOG = 'syslog'
    __size_action_values = {'ignore': SIZE_IGNORE, 'keep_logs': SIZE_KEEP_LOGS,
                            'rotate': SIZE_ROTATE, 'suspend': SIZE_SUSPEND,
                            'syslog': SIZE_SYSLOG}

    # Used to make sure __eq__() doesn't miss anything.  The space savings, if
    # any, are not really important.
    __slots__ = ('action_mail_acct', 'admin_space_left',
                 'admin_space_left_action', 'admin_space_left_exe',
                 'disk_error_action', 'disk_error_exe', 'disk_full_action',
                 'disk_full_exe', 'disp_qos', 'dispatcher',
                 'flush', 'freq',
                 'log_file', 'log_format', 'log_group',
                 'max_log_file', 'max_log_file_action',
                 'name', 'name_format', 'num_logs',
                 'priority_boost',
                 'space_left', 'space_left_action', 'space_left_exe')

    def __init__(self):
        self.action_mail_acct = 'root'
        self.admin_space_left = 0
        self.admin_space_left_action = self.FAILURE_IGNORE
        self.admin_space_left_exe = None
        self.disk_error_action = self.FAILURE_SYSLOG
        self.disk_error_exe = None
        self.disk_full_action = self.FAILURE_IGNORE
        self.disk_full_exe = None
        self.disp_qos = self.QOS_LOSSY
        self.dispatcher = None
        self.flush = self.FLUSH_NONE
        self.freq = 0
        self.log_file = '/var/log/audit/audit.log'
        self.log_format = self.FORMAT_RAW
        self.log_group = 'root'
        self.max_log_file = 0
        self.max_log_file_action = self.SIZE_IGNORE
        self.name = None
        self.name_format = self.NAME_NONE
        self.num_logs = 0
        self.priority_boost = 4
        self.space_left = 0
        self.space_left_action = self.FAILURE_IGNORE
        self.space_left_exe = None

    __whitespace_re = re.compile(' +')
    @staticmethod
    def __tokenize_line(line):
        '''Split a line into tokens.

        Return the token array, with a[1] == '=', or None if the line contains
        no tokens.  Raise ParsingError on error.

        '''
        # Avoid empty leading and trailing empty strings in the split
        # result if line starts or ends with spaces
        line = line.strip(' ')
        if not line or line.startswith('#'):
            return None
        a = AuditdConfig.__whitespace_re.split(line)
        if len(a) < 3 or len(a) > 4:
            raise ParsingError('Invalid number of tokens')
        if a[1] != '=':
            raise ParsingError('Missing equal sign')
        return a

    @staticmethod
    def __parse_action(value, value2):
        '''Parse an action specification.

        Return (action, exe), where exe may be None if it is not necessary.
        Raise ParsingError on error.

        '''
        value = value.lower()
        if value == 'exec':
            if value2 is None:
                raise ParsingError('Two values are expected for the "exec" '
                                   'action')
            return (AuditdConfig.FAILURE_EXEC, value2)
        else:
            # auditd ignores value2 if it is present
            try:
                return (AuditdConfig.__failure_action_values[value], None)
            except KeyError:
                raise ParsingError('Invalid value')

    def __interpret_option(self, name, unused_equals, value, value2 = None):
        '''Handle a single configuration file option.

        Raise ParsingError on error.

        '''
        name = name.lower()

        if name == 'admin_space_left_action':
            (action, exe) = self.__parse_action(value, value2)
            self.admin_space_left_action = action
            if exe is not None:
                self.admin_space_left_exe = exe
        elif name == 'disk_error_action':
            (action, exe) = self.__parse_action(value, value2)
            if action == self.FAILURE_EMAIL:
                raise ParsingError('Invalid value')
            self.disk_error_action = action
            if exe is not None:
                self.disk_error_exe = exe
        elif name == 'disk_full_action':
            (action, exe) = self.__parse_action(value, value2)
            if action == self.FAILURE_EMAIL:
                raise ParsingError('Invalid value')
            self.disk_full_action = action
            if exe is not None:
                self.disk_full_exe = exe
        elif name == 'space_left_action':
            (action, exe) = self.__parse_action(value, value2)
            self.space_left_action = action
            if exe is not None:
                self.space_left_exe = exe
        else:
            if value2 is not None:
                raise ParsingError('Only one value is expected for this '
                                   'keyword')

            if name == 'action_mail_acct':
                self.action_mail_acct = value
            elif name == 'admin_space_left':
                self.admin_space_left = util.parse_unsigned(value)
            elif name == 'disp_qos':
                try:
                    self.disp_qos = self.__disp_qos_values[value.lower()]
                except KeyError:
                    raise ParsingError('Invalid value')
            elif name == 'dispatcher':
                self.dispatcher = value
            elif name == 'flush':
                try:
                    self.flush = self.__flush_values[value.lower()]
                except KeyError:
                    raise ParsingError('Invalid value')
            elif name == 'freq':
                self.freq = util.parse_unsigned(value)
            elif name == 'log_file':
                self.log_file = value
            elif name == 'log_format':
                try:
                    self.log_format = self.__format_values[value.lower()]
                except KeyError:
                    raise ParsingError('Invalid value')
            elif name == 'log_group':
                self.log_group = value
            elif name == 'max_log_file':
                self.max_log_file = util.parse_unsigned(value)
            elif name == 'max_log_file_action':
                try:
                    self.max_log_file_action = \
                        self.__size_action_values[value.lower()]
                except KeyError:
                    raise ParsingError('Invalid value')
            elif name == 'name':
                self.name = value
            elif name == 'name_format':
                try:
                    self.name_format = self.__name_values[value.lower()]
                except KeyError:
                    raise ParsingError('Invalid value')
            elif name == 'num_logs':
                v = util.parse_unsigned(value)
                if v > 99:
                    raise ParsingError('Invalid value, valid range is 0..99')
                self.num_logs = v
            elif name == 'priority_boost':
                self.priority_boost = util.parse_unsigned(value)
            elif name == 'space_left':
                self.space_left = util.parse_unsigned(value)
            else:
                raise ParsingError('Unknown keyword')

    def read(self, client):
        '''Read the auditd configuration file using client.

        Raise IOError on error.  Invalid lines are reported on stderr (in
        English), but otherwise ignored.

        '''
        contents = client.read_file(server.FILE_AUDITD_CONF)
        line_no = 0
        for line in contents.splitlines():
            line_no += 1
            try:
                a = self.__tokenize_line(line)
                if a is not None:
                    self.__interpret_option(*a)
            except ParsingError, e:
                print >> sys.stderr, "auditd.conf:%d: %s" % (line_no, str(e))

    def __option_values(self):
        '''Return option values to write to the config file.

        Raise ValueError on invalid configuration.

	'''
        vals = {
            'action_mail_acct': self.action_mail_acct,
            'admin_space_left': str(self.admin_space_left),
            'admin_space_left_action': self.admin_space_left_action,
            'disk_error_action': self.disk_error_action,
            'disk_full_action': self.disk_full_action,
            'disp_qos': self.disp_qos,
            'flush': self.flush,
            'freq': str(self.freq),
            'log_file': self.log_file,
            'log_format': self.log_format,
            'log_group': self.log_group,
            'max_log_file': str(self.max_log_file),
            'max_log_file_action': self.max_log_file_action,
            'name_format': self.name_format,
            'num_logs': str(self.num_logs),
            'priority_boost': str(self.priority_boost),
            'space_left': str(self.space_left),
            'space_left_action': self.space_left_action
            }
        if self.dispatcher is not None:
            vals['dispatcher'] = self.dispatcher
        if self.name is not None:
            vals['name'] = self.name
        vals2 = {}
        if self.admin_space_left_action.lower() == self.FAILURE_EXEC:
            if self.admin_space_left_exe is None:
                raise ValueError, 'non-None admin_space_left_exe required'
            vals2['admin_space_left_action'] = self.admin_space_left_exe
        if self.disk_error_action.lower() == self.FAILURE_EXEC:
            if self.disk_error_exe is None:
                raise ValueError, 'non-None disk_error_exe required'
            vals2['disk_error_action'] = self.disk_error_exe
        if self.disk_full_action.lower() == self.FAILURE_EXEC:
            if self.disk_full_exe is None:
                raise ValueError, 'non-None disk_full_exe required'
            vals2['disk_full_action'] = self.disk_full_exe
        if self.space_left_action.lower() == self.FAILURE_EXEC:
            if self.space_left_exe is None:
                raise ValueError, 'non-None space_left_exe required'
            vals2['space_left_action'] = self.space_left_exe
        return (vals, vals2)

    __case_insensitive_values = {
        'admin_space_left_action': None,
        'disk_error_action': None,
        'disk_full_action': None,
        'space_left_action': None,
        'disp_qos': None,
        'flush': None,
        'log_format': None,
        'max_log_file_action': None,
        'name_format': None
        }
    def __updated_line(self, vals, vals2, used, line):
        '''Return line updated with vals and vals2.

        If line contains an option, mark it in used.

        '''
        orig_line = line.rstrip('\n')
        try:
            a = self.__tokenize_line(line)
        except ParsingError:
            a = None
        if a is None:
            return orig_line
        keyword_lower = a[0].lower()
        used[keyword_lower] = True
        try:
            new_val = vals[keyword_lower]
        except KeyError:
            return orig_line

        new_val2 = vals2.get(keyword_lower)
        changed = False
        if keyword_lower in self.__case_insensitive_values:
            if new_val.lower() != a[2].lower():
                changed = True
        else:
            if new_val != a[2]:
                changed = True
        if new_val2 is not None:
            if len(a) != 4 or a[3] != new_val2:
                changed = True
        else:
            if len(a) != 3:
                changed = True
        if not changed:
            return orig_line
        elif new_val2 is not None:
            return '%s = %s %s' % (a[0], new_val, new_val2)
        else:
            return '%s = %s' % (a[0], new_val)

    def write(self, client):
        '''Write current state to the auditd configuration file using client.

        Raise IOError on error, ValueError on invalid configuration.

        '''
        (vals, vals2) = self.__option_values()
        used = {}
        for var in vals.iterkeys():
            used[var] = False

        lines = []
        old_contents = client.read_file(server.FILE_AUDITD_CONF)
        for line in old_contents.splitlines():
            lines.append(self.__updated_line(vals, vals2, used, line))

        for var in vals.iterkeys():
            if not used[var]:
                val2 = vals2.get(var)
                if val2 is not None:
                    lines.append('%s = %s %s' % (var, vals[var], val2))
                else:
                    lines.append('%s = %s' % (var, vals[var]))

        contents = '\n'.join(lines)
        if len(contents) != 0:
            contents = contents + '\n'
        client.write_file(server.FILE_AUDITD_CONF, contents)

    def __eq__(self, config):
        if type(config) is not AuditdConfig:
            return NotImplemented
        # This is OK because all attributes have primitive values.
        for attr in self.__slots__:
            if getattr(self, attr) != getattr(config, attr):
                return False
        return True

    def __ne__(self, config):
        return not self.__eq__(config)
