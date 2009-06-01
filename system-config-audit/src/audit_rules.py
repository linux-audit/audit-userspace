# audit.rules parsing and creation.
#
# Copyright (C) 2007, 2008, 2009 Red Hat, Inc.  All rights reserved.
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
import getopt
from gettext import gettext as _
import grp
import os.path
import pwd
import re
import sys

import audit

import lists
import server
import util

__all__ = ('AuditRules',
           'Field', 'FieldType',
           'Rule')

# A shorthand
ParsingError = util.ParsingError


class FieldType(object):

    '''A rule field type.'''

    @staticmethod
    def parse_value(string, op, rule):
        '''Return a field value parsed from string.

        Raise ParsingError on error.  The op and rule are parsed to allow more
        checking; rule is expected to be used only in _ArchFieldType.

        '''
        raise NotImplementedError

    @staticmethod
    def value_text(value):
        '''Return a string representing value.'''
        raise NotImplementedError

    @staticmethod
    def hints():
        '''Return a list of strings to offer to the user as possible values.'''
        return []

    @staticmethod
    def usual_operators(_):
        '''Return a list of operators to offer to the user as most useful.'''
        return Field.all_operators

class _UIDFieldType(FieldType):
    @staticmethod
    def parse_value(string, *unused):
        try:
            return int(string)
        except ValueError:
            try:
                pw = pwd.getpwnam(string)
            except KeyError:
                raise ParsingError(_('Unknown user "%s"') % string)
            return pw.pw_uid

    @staticmethod
    def value_text(value):
        try:
            return pwd.getpwuid(value).pw_name
        except KeyError:
            return str(value)

    @staticmethod
    def hints():
        return sorted((pw.pw_name for pw in pwd.getpwall()))

    @staticmethod
    def usual_operators(_):
        return (Field.OP_EQ, Field.OP_NE, Field.OP_LT, Field.OP_LE, Field.OP_GE,
                Field.OP_GT)

class _GIDFieldType(FieldType):
    @staticmethod
    def parse_value(string, *unused):
        try:
            return int(string)
        except ValueError:
            try:
                gr = grp.getgrnam(string)
            except KeyError:
                raise ParsingError(_('Unknown group "%s"') % string)
            return gr.gr_gid

    @staticmethod
    def value_text(value):
        try:
            return grp.getgrgid(value).gr_name
        except KeyError:
            return str(value)

    @staticmethod
    def hints():
        return sorted((gr.gr_name for gr in grp.getgrall()))

    @staticmethod
    def usual_operators(_):
        return (Field.OP_EQ, Field.OP_NE, Field.OP_LT, Field.OP_LE, Field.OP_GE,
                Field.OP_GT)

class _MsgTypeFieldType(FieldType):
    @staticmethod
    def parse_value(string, *_):
        return util.parse_msgtype(string)

    @staticmethod
    def value_text(value):
        return util.msgtype_string(value)

    @staticmethod
    def hints():
        return lists.sorted_event_type_names

class _FileTypeFieldType(FieldType):
    @staticmethod
    def parse_value(string, *_):
        return util.parse_filetype(string)

    @staticmethod
    def value_text(value):
        return util.filetype_string(value)

    @staticmethod
    def hints():
        return lists.sorted_file_type_names

    @staticmethod
    def usual_operators(_):
        return (Field.OP_EQ, Field.OP_NE)

class _StringFieldType(FieldType):
    @staticmethod
    def parse_value(string, *_):
        return string

    @staticmethod
    def value_text(value):
        return value

class _FilterKeyFieldType(_StringFieldType):
    @staticmethod
    def parse_value(string, *unused):
        if len(string) > audit.AUDIT_MAX_KEY_LEN:
            raise ParsingError(_('Key value "%s" too long') % string)
        if util.is_ids_key(string) and util.parse_ids_key(string) is None:
            raise ParsingError(_('Invalid IDS key "%s"') % string)
        return string

class _ArchFieldType(FieldType):
    @staticmethod
    def parse_value(string, op, rule):
        if rule.syscalls:
            raise ParsingError(_('Architecture can not be changed after system '
                                 'calls are selected'))
        if op not in (Field.OP_EQ, Field.OP_NE):
            raise ParsingError(_('The only valid operators for "%s" are "=" '
                                 'and "!="') %
                               audit.audit_field_to_name(audit.AUDIT_ARCH))
        rule.machine = util.parse_elf(string)
        return string

    @staticmethod
    def value_text(value):
        return value

    @staticmethod
    def hints():
        return lists.sorted_machine_names

    @staticmethod
    def usual_operators(_):
        return (Field.OP_EQ, Field.OP_NE)

class _PermFieldType(FieldType):
    @staticmethod
    def parse_value(string, op, *unused):
        if op != Field.OP_EQ:
            raise ParsingError(_('The only valid operator for "%s" is "="') %
                               audit.audit_field_to_name(audit.AUDIT_PERM))
        val = 0
        for c in string:
            if c == 'r':
                val |= audit.AUDIT_PERM_READ
            elif c == 'w':
                val |= audit.AUDIT_PERM_WRITE
            elif c == 'x':
                val |= audit.AUDIT_PERM_EXEC
            elif c == 'a':
                val |= audit.AUDIT_PERM_ATTR
            else:
                raise ParsingError(_('Unknown permission "%(char)c" in '
                                     '"%(perms)s"') %
                                   {'char': c, 'perms': string})
        return val

    @staticmethod
    def value_text(value):
        s = []
        if (value & audit.AUDIT_PERM_READ) != 0:
            s.append('r')
        if (value & audit.AUDIT_PERM_WRITE) != 0:
            s.append('w')
        if (value & audit.AUDIT_PERM_EXEC) != 0:
            s.append('x')
        if (value & audit.AUDIT_PERM_ATTR) != 0:
            s.append('a')
        return ''.join(s)

    @staticmethod
    def usual_operators(_):
        return (Field.OP_EQ)

class _IntFieldType(FieldType):
    @staticmethod
    def parse_value(string, *unused):
        try:
            return int(string)
        except ValueError:
            raise ParsingError(_('Invalid integer value "%s"') % string)

    @staticmethod
    def value_text(value):
        return str(value)

    @staticmethod
    def usual_operators(var):
        if var in (audit.AUDIT_ARG0, audit.AUDIT_ARG1, audit.AUDIT_ARG2,
                   audit.AUDIT_ARG3):
            return Field.all_operators
        else:
            return (Field.OP_EQ, Field.OP_NE, Field.OP_LT, Field.OP_LE,
                    Field.OP_GE, Field.OP_GT)

class _InodeFieldType(_IntFieldType):
    @staticmethod
    def parse_value(string, op, *unused):
        if op not in (Field.OP_EQ, Field.OP_NE):
            raise ParsingError(_('The only valid operators for "%s" are "=" '
                                 'and "!="') %
                               audit.audit_field_to_name(audit.AUDIT_INODE))
        return _IntFieldType.parse_value(string)

    @staticmethod
    def usual_operators(_):
        return (Field.OP_EQ, Field.OP_NE)


class Field(object):

    '''A single rule field.'''

    OP_EQ = '='
    OP_GE = '>='
    OP_GT = '>'
    OP_LE = '<='
    OP_LT = '<'
    OP_MASK = '&'
    OP_NE = '!='
    OP_TEST = '&='
    # Uses an user-friendly order
    all_operators = (OP_EQ, OP_NE, OP_LT, OP_LE, OP_GE, OP_GT, OP_MASK, OP_TEST)

    def __init__(self):
        self.var = None # audit.AUDIT_*
        self.op = None # Usable as an user-readable representation
        self.value = None

    __field_type_map = {
        audit.AUDIT_ARCH: _ArchFieldType,
        audit.AUDIT_DIR: _StringFieldType,
        audit.AUDIT_EGID: _GIDFieldType, audit.AUDIT_EUID: _UIDFieldType,
        audit.AUDIT_FILETYPE: _FileTypeFieldType,
        audit.AUDIT_FILTERKEY: _FilterKeyFieldType,
        audit.AUDIT_FSGID: _GIDFieldType, audit.AUDIT_FSUID: _UIDFieldType,
        audit.AUDIT_GID: _GIDFieldType,
        audit.AUDIT_INODE: _InodeFieldType,
        audit.AUDIT_LOGINUID: _UIDFieldType,
        audit.AUDIT_MSGTYPE: _MsgTypeFieldType,
        audit.AUDIT_OBJ_LEV_HIGH: _StringFieldType,
        audit.AUDIT_OBJ_LEV_LOW: _StringFieldType,
        audit.AUDIT_OBJ_ROLE: _StringFieldType,
        audit.AUDIT_OBJ_TYPE: _StringFieldType,
        audit.AUDIT_OBJ_USER: _StringFieldType,
        audit.AUDIT_PERM: _PermFieldType,
        audit.AUDIT_SGID: _GIDFieldType,
        audit.AUDIT_SUBJ_ROLE: _StringFieldType,
        audit.AUDIT_SUBJ_SEN: _StringFieldType,
        audit.AUDIT_SUBJ_TYPE: _StringFieldType,
        audit.AUDIT_SUBJ_USER: _StringFieldType,
        audit.AUDIT_SUID: _UIDFieldType,
        audit.AUDIT_UID: _UIDFieldType,
        audit.AUDIT_WATCH: _StringFieldType,
        }
    @classmethod
    def get_field_type(cls, field):
        '''Return a FieldType for the specified field.'''
        return cls.__field_type_map.get(field, _IntFieldType)

    __op_name_map = { '!=': OP_NE, '=': OP_EQ, '&': OP_MASK, '&=': OP_TEST,
                      '<': OP_LT, '<=': OP_LE, '>': OP_GT, '>=': OP_GE }
    def parse_triple(self, var_name, op_name, value, rule = None):
        '''Parse the rule from elements.

        Raise ParsingError on error.  The object state is undefined after an
        error.  rule may be omitted if var_name never specifies
        audit.AUDIT_ARCH.

        '''
        try:
            self.var = audit.audit_name_to_field(var_name)
        except OSError:
            raise ParsingError(_('Unknown field "%s"') % var_name)
        try:
            self.op = self.__op_name_map[op_name]
        except KeyError:
            raise ParsingError(_('Unknown operator "%s"') % op_name)
        self.value = self.get_field_type(self.var).parse_value(value, self.op,
                                                               rule)

    def parse(self, string, rule):
        '''Parse the rule from a string representation.

        Raise ParsingError on error.  The object state is undefined after an
        error.

        '''
        # To avoid ambiguities, check the longest operators first.
        for op in sorted(self.__op_name_map.iterkeys(), key = len,
                         reverse = True):
            i = string.find(op)
            if i != -1:
                (var, value) = (string[:i], string[(i + len(op)):])
                break
        else:
            raise ParsingError(_('Operator missing in "%s"') % string)
        self.parse_triple(var, op, value, rule)

    def parse_special(self, var, string):
        '''Parse a special-cased parameter for var = string.

        Raise ParsingError on error.  The object state is undefined after an
        error.

        '''
        self.var = var
        self.op = self.OP_EQ
        self.value = self.get_field_type(self.var).parse_value(string, self.op)

    def option_text(self, rule):
        '''Return a string representing this field as an auditctl option.

        Use rule to determine the correct syntax.

        '''
        val = self._value_text()
        if self.var == audit.AUDIT_FILTERKEY:
            assert self.op == self.OP_EQ
            return '-k %s' % val
        elif (self.var == audit.AUDIT_PERM and
              len([f for f in rule.fields
                   if f.var in (audit.AUDIT_DIR, audit.AUDIT_WATCH)]) == 1):
            assert self.op == self.OP_EQ
            return '-p %s' % val
        else:
            return '-F %s%s%s' % (audit.audit_field_to_name(self.var), self.op,
                                  val)

    def user_text(self):
        '''Return an user-readable string representing this field.'''
        return '%s %s %s' % (audit.audit_field_to_name(self.var), self.op,
                             self._value_text())

    def _value_text(self):
        '''Return a string representing self.value.'''
        return self.get_field_type(self.var).value_text(self.value)

    def __eq__(self, field):
        if type(field) is not Field:
            return NotImplemented
        return (self.var == field.var and self.op == field.op and
                self.value == field.value)

    def __ne__(self, field):
        return not self.__eq__(field)


class Rule(object):

    '''A single audit rule.'''

    ACTION_ALWAYS = 'always'
    ACTION_NEVER = 'never'

    SYSCALLS_ALL = 'all'

    def __init__(self):
        self.action = None
        self.fields = []
        # The machine type used for system calls in this rule
        self.machine = util.audit_machine_id
        # System call numbers.  May include the special value SYSCALLS_ALL.
        self.syscalls = []

    def validate(self, list, rules):
        '''Validate the rule, for usage within list in rules.

        Raise ParsingError on error.

        '''
        for var in (field.var for field in self.fields):
            if list is rules.exclude_rules and var != audit.AUDIT_MSGTYPE:
                raise ParsingError('Field type "%s" is invalid in "exclude" '
                                   'rules' % audit.audit_field_to_name(var))
            if list is not rules.exclude_rules and var == audit.AUDIT_MSGTYPE:
                raise ParsingError('Field type "%s" is valid only "exclude" '
                                   'rules' % audit.audit_field_to_name(var))
            if (list is not rules.exit_rules and
                var in (audit.AUDIT_DIR, audit.AUDIT_OBJ_USER,
                        audit.AUDIT_OBJ_ROLE, audit.AUDIT_OBJ_TYPE,
                        audit.AUDIT_OBJ_LEV_LOW, audit.AUDIT_OBJ_LEV_HIGH,
                        audit.AUDIT_WATCH)):
                raise ParsingError('Field type "%s" is valid only in system '
                                   'call exit and watch rules' %
                                   audit.audit_field_to_name(var))
            if (list is rules.entry_rules and
                var in (audit.AUDIT_DEVMAJOR, audit.AUDIT_DEVMINOR,
                        audit.AUDIT_INODE, audit.AUDIT_EXIT,
                        audit.AUDIT_SUCCESS)):
                raise ParsingError('Field type "%s" is not valid in system '
                                   'call entry rules' %
                                   audit.audit_field_to_name(var))
        if list is rules.exclude_rules and len(self.fields) > 1:
            # FIXME: this is to avoid -F msgtype=1 -F msgtype=2 not doing the
            # right thing, but it prevents range expressions from working
            raise ParsingError('Only one field is allowed in "exclude" rules')
        keys = (field.value for field in self.fields
                if field.var == audit.AUDIT_FILTERKEY)
        if len('\x01'.join(keys)) > audit.AUDIT_MAX_KEY_LEN:
            raise ParsingError('Total key length is too long')
        # FIXME: more checks?

    def command_text(self, rules, list, list_name):
        '''Represent self as a string within a list with list_name in rules.'''
        o = []
        used_fields = set(field.var for field in self.fields)
        watches = [field for field in self.fields
                   if field.var in (audit.AUDIT_DIR, audit.AUDIT_WATCH)]
        if (list is rules.exit_rules and
            self.syscalls == [self.SYSCALLS_ALL] and
            used_fields.issubset(set((audit.AUDIT_DIR, audit.AUDIT_FILTERKEY,
                                      audit.AUDIT_PERM, audit.AUDIT_WATCH))) and
            len(watches) == 1 and watches[0].op == Field.OP_EQ):
            o.append('-w %s' % watches[0].value)
            watch_used = True
        else:
            o.append('-a %s,%s' % (list_name, self.action))
            watch_used = False
        # Add fields before syscalls because -F arch=... may change the meaning
        # of syscall names.  But add AUDIT_FILTERKEY only after -S, auditctl
        # stubbornly insists on that order.
        for f in self.fields:
            if (f.var != audit.AUDIT_FILTERKEY and
                (f.var not in (audit.AUDIT_DIR, audit.AUDIT_WATCH) or
                 not watch_used)):
                o.append(f.option_text(self))
        # exclude_rules and user_rules are not syscall related.  -w implies
        # -S all.
        if (list is not rules.exclude_rules and
            list is not rules.user_rules and not watch_used):
            for s in self.syscalls:
                if s == self.SYSCALLS_ALL:
                    o.append('-S all')
                else:
                    o.append('-S %s' % util.syscall_string(s, self.machine))
        for f in self.fields:
            if f.var == audit.AUDIT_FILTERKEY:
                o.append(f.option_text(self))
        return ' '.join(o)

    def __eq__(self, rule):
        if type(rule) is not Rule:
            return NotImplemented
        if (self.action != rule.action or
            len(self.fields) != len(rule.fields) or
            self.machine != rule.machine or
            set(self.syscalls) != set(rule.syscalls)):
            return False
        for i in xrange(len(self.fields)):
            if self.fields[i] != rule.fields[i]: # See Field.__eq__
                return False
        return True

    def __ne__(self, rule):
        return not self.__eq__(rule)


class AuditRules(object):

    '''Audit rules and kernel config file.'''

    AUDIT_DISABLED = '0'
    AUDIT_ENABLED = '1'
    AUDIT_LOCKED = '2'

    FAILURE_SILENT = '0'
    FAILURE_PRINTK = '1'
    FAILURE_PANIC = '2'

    RATE_LIMIT_DISABLED = 0

    # __slots__ is used to make sure __eq__ doesn't miss anything.  The space
    # savings, if any, are not really important.
    __rule_list_slots = ('entry_rules', 'exclude_rules', 'exit_rules',
                         'task_rules',
                         'user_rules')
    __primitive_slots = ('audit_enabled',
                         'backlog_limit',
                         'failure_handling',
                         'rate_limit')
    __slots__ = __primitive_slots + __rule_list_slots

    def __init__(self):
        # The kernel default may be changed using a command line option.  It is
        # not actually relevant, because auditd is started before audit.rules
        # are loaded and auditd always enables auditing.
        self.audit_enabled = self.AUDIT_ENABLED
        self.backlog_limit = 64
        self.failure_handling = self.FAILURE_PRINTK
        self.rate_limit = self.RATE_LIMIT_DISABLED
        self.__empty_rule_lists()

    def __empty_rule_lists(self):
        for attr in self.__rule_list_slots:
            setattr(self, attr, [])

    def __interpret_line(self, args):
        '''Handle a single configuration file command.

        Raise ParsingError on error.

        '''
        try:
            (opts, arguments) = \
                   getopt.getopt(args, 'A:DF:S:W:a:b:d:e:f:ihlk:m:p:r:sw:')
        except getopt.error, e:
            raise ParsingError(e.msg)
        if arguments:
            raise ParsingError('Unexpected non-option arguments "%s"' %
                               ' '.join(arguments))
        rule = Rule()
        rule_operation = None
        rule_list = None
        for (opt, arg) in opts:
            if opt in ('-A', '-a', '-d'):
                if rule.action is not None:
                    raise ParsingError('Action already specified for a rule')
                i = arg.find(',')
                if i == -1:
                    raise ParsingError('Missing comma in "%s"' % arg)
                (dest, action) = (arg[:i], arg[i + 1:])
                if dest == 'task':
                    rule_list = self.task_rules
                elif dest == 'entry':
                    rule_list = self.entry_rules
                elif dest == 'exit':
                    rule_list = self.exit_rules
                elif dest == 'user':
                    rule_list = self.user_rules
                elif dest == 'exclude':
                    rule_list = self.exclude_rules
                else:
                    raise ParsingError('Unknown rule list "%s"' % dest)
                if action == 'never':
                    rule.action = Rule.ACTION_NEVER
                elif action == 'always':
                    rule.action = Rule.ACTION_ALWAYS
                elif action == 'possible':
                    raise ParsingError('Rule action "possible" is deprecated')
                else:
                    raise ParsingError('Unknown rule action "%s"' % action)
                rule_operation = opt
            elif opt == '-D':
                self.__empty_rule_lists()
            elif opt == '-F':
                field = Field()
                # This may have the nasty side effect of changing rule.machine
                field.parse(arg, rule)
                rule.fields.append(field)
            elif opt == '-S':
                if arg == 'all':
                    sc = Rule.SYSCALLS_ALL
                else:
                    sc = util.parse_syscall(arg, rule.machine)
                if sc not in rule.syscalls:
                    rule.syscalls.append(sc)
            elif opt == '-W' or opt == '-w':
                if rule.action is not None:
                    raise ParsingError('Action already specified for a rule')
                if (set(field.var for field in rule.fields).
                    intersection((audit.AUDIT_DIR, audit.AUDIT_WATCH))):
                    raise ParsingError('Two paths specified for a rule')
                rule.action = Rule.ACTION_ALWAYS
                field = Field()
                if os.path.isdir(arg):
                    field.parse_special(audit.AUDIT_DIR, arg)
                else:
                    field.parse_special(audit.AUDIT_WATCH, arg)
                rule.fields.append(field)
                if opt == '-W':
                    rule_operation = '-d'
                else:
                    rule_operation = '-a'
                rule_list = self.exit_rules
            elif opt == '-b':
                self.backlog_limit = util.parse_unsigned(arg)
            elif opt == '-e':
                if arg == '0':
                    self.audit_enabled = self.AUDIT_DISABLED
                elif arg == '1':
                    self.audit_enabled = self.AUDIT_ENABLED
                elif arg == '2':
                    self.audit_enabled = self.AUDIT_LOCKED
                else:
                    raise ParsingError('Invalid value "%s" of option -e' % arg)
            elif opt == '-f':
                if arg == '0':
                    self.failure_handling = self.FAILURE_SILENT
                elif arg == '1':
                    self.failure_handling = self.FAILURE_PRINTK
                elif arg == '2':
                    self.failure_handling = self.FAILURE_PANIC
                else:
                    raise ParsingError('Invalid value "%s" of option -f' % arg)
            elif opt == '-h' or opt == '-i' or opt == '-l':
                pass # Ignore
            elif opt == '-k':
                # This will be ignored if -k is used with -l or -D.
                field = Field()
                field.parse_special(audit.AUDIT_FILTERKEY, arg)
                rule.fields.append(field)
            elif opt == '-m':
                pass # Ignore
            elif opt == '-p':
                field = Field()
                field.parse_special(audit.AUDIT_PERM, arg)
                for i in xrange(len(rule.fields)):
                    if rule.fields[i].var == audit.AUDIT_PERM:
                        rule.fields[i] = field
                        break
                else:
                    rule.fields.append(field)
            elif opt == '-r':
                self.rate_limit = util.parse_unsigned(arg)
            elif opt == '-s':
                pass # Ignore
    	if rule_list is not None:
            if rule.syscalls:
                if rule_list is self.task_rules:
                    raise ParsingError('System calls cannot be used in task '
                                        'rules')
                if rule_list is self.user_rules:
                    raise ParsingError('System calls cannot be used in user '
                                       'rules')
                if rule_list is self.exclude_rules:
                    raise ParsingError('System calls cannot be used in '
                                        'exclude rules')
            if rule_list is not self.task_rules and not rule.syscalls:
                rule.syscalls.append(Rule.SYSCALLS_ALL)
            rule.validate(rule_list, self)
            for i in xrange(len(rule_list)):
                if rule_list[i] == rule: # See Rule.__eq__
                    same = i
                    break
            else:
                same = None
            if rule_operation in ('-a', '-A'):
                if same is not None:
                    raise ParsingError('The same rule already exists in this '
                                       'list')
                if rule_operation == '-a':
                    rule_list.append(rule)
                else:
                    rule_list.insert(0, rule)
            elif rule_operation == '-d':
                if same is None:
                    raise ParsingError('The rule does not exist in the list')
                del rule_list[same]

    __whitespace_re = re.compile(' +')
    def read(self, client):
        '''Read the auditd configuration file using client.

        Raise IOError on error.  Invalid lines are reported on stderr (in
        English), but otherwise ignored.

        '''
        contents = client.read_file(server.FILE_AUDIT_RULES)
        line_no = 0
        for line in contents.splitlines():
            line_no += 1
            line = line.strip(' ')
            if not line:
                continue
            if line.startswith('#'):
                continue
            try:
                self.__interpret_line(self.__whitespace_re.split(line))
            except ParsingError, e:
                print >> sys.stderr, "audit.rules:%d: %s" % (line_no, str(e))

    def write(self, client):
        '''Write current state to the auditd configuration file using client.

        Raise IOError on error.

        '''
        # Unlike AuditdConfig, we don't try to preserve the original structure
        # and comments in audit.rules.  The structure less simple, and rule
        # order matters, so the heuristic would have to be rather complex and
        # fragile.  Maybe sometime later.
        lines = []
        if self.audit_enabled != self.AUDIT_LOCKED:
            lines.append('-e %s' % self.audit_enabled)
        else:
            lines.append('-e %s' % self.AUDIT_ENABLED)
        lines += ['-f %s' % self.failure_handling,
                  '-b %d' % self.backlog_limit,
                  '-r %d' % self.rate_limit,
                  '',
                  '-D']
        for (rules, list_name) in ((self.entry_rules, 'entry'),
                                   (self.exclude_rules, 'exclude'),
                                   (self.exit_rules, 'exit'),
                                   (self.task_rules, 'task'),
                                   (self.user_rules, 'user')):
            for r in rules:
                lines.append(r.command_text(self, rules, list_name))
        if self.audit_enabled == self.AUDIT_LOCKED:
            lines.append('-e %s' % self.audit_enabled)

        contents = '\n'.join(lines) + '\n'
        client.write_file(server.FILE_AUDIT_RULES, contents)

    def __eq__(self, rules):
        if type(rules) is not AuditRules:
            return NotImplemented
        for attr in self.__primitive_slots:
            if getattr(self, attr) != getattr(rules, attr):
                return False
        for attr in self.__rule_list_slots:
            l0 = getattr(self, attr)
            l1 = getattr(rules, attr)
            if len(l0) != len(l1):
                return False
            for i in xrange(len(l0)):
                if l0[i] != l1[i]: # See Rule.__ne__
                    return False
        return True

    def __ne__(self, rules):
        return not self.__eq__(rules)
