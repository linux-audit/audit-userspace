# Rule list dialog.
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
from gettext import gettext as _

import audit
import gtk

from audit_rules import Rule
from dialog_base import DialogBase
from rule_table import RuleTable

__all__ = ('RuleListDialog')

def N_(s): return s

class _ExitTable(RuleTable):
    _column_titles = (N_('Key'), N_('System Calls'), N_('Condition'),
                      N_('Action'))
    excluded_fields = (audit.AUDIT_MSGTYPE,)

    @staticmethod
    def _new_rule():
        rule = Rule()
        rule.action = rule.ACTION_ALWAYS
        rule.syscalls = [rule.SYSCALLS_ALL]
        return rule

    def _update_row(self, it, rule):
        self._row_set_filter_key(it, 1, rule)
        self._row_set_syscalls(it, 2, rule)
        self._row_set_fields(it, 3, rule)
        self._row_set_action(it, 4, rule)

class _EntryTable(RuleTable):
    _column_titles = (N_('Key'), N_('System Calls'), N_('Condition'),
                      N_('Action'))
    excluded_fields = ((audit.AUDIT_DIR, audit.AUDIT_EXIT, audit.AUDIT_SUCCESS,
                        audit.AUDIT_WATCH) + _ExitTable.excluded_fields)

    @staticmethod
    def _new_rule():
        rule = Rule()
        rule.action = rule.ACTION_ALWAYS
        rule.syscalls = [rule.SYSCALLS_ALL]
        return rule

    def _update_row(self, it, rule):
        self._row_set_filter_key(it, 1, rule)
        self._row_set_syscalls(it, 2, rule)
        self._row_set_fields(it, 3, rule)
        self._row_set_action(it, 4, rule)

class _TaskTable(RuleTable):
    _action_labels = (N_('Allow auditing'), N_('Do not audit'))
    _column_titles = (N_('Key'), N_('Condition'), N_('Action'))
    excluded_fields = (
        audit.AUDIT_ARCH, audit.AUDIT_ARG0, audit.AUDIT_ARG1, audit.AUDIT_ARG2,
        audit.AUDIT_ARG3,
        audit.AUDIT_DEVMAJOR, audit.AUDIT_DEVMINOR,
        audit.AUDIT_EXIT,
        audit.AUDIT_FILTERKEY,
        audit.AUDIT_INODE,
        audit.AUDIT_LOGINUID,
        audit.AUDIT_OBJ_LEV_HIGH, audit.AUDIT_OBJ_LEV_LOW,
        audit.AUDIT_OBJ_ROLE, audit.AUDIT_OBJ_TYPE, audit.AUDIT_OBJ_USER,
        audit.AUDIT_PERM, audit.AUDIT_PPID,
        audit.AUDIT_SUCCESS
        ) + _EntryTable.excluded_fields

    @staticmethod
    def _new_rule():
        rule = Rule()
        rule.action = rule.ACTION_ALWAYS
        return rule

    def _update_row(self, it, rule):
        self._row_set_filter_key(it, 1, rule)
        self._row_set_fields(it, 2, rule)
        self._row_set_action(it, 3, rule)

class RuleListDialog(DialogBase):

    '''Rule list dialog.'''

    _glade_widget_names = ('entry_delete', 'entry_down', 'entry_edit',
                           'entry_insert', 'entry_table', 'entry_up',
                           'exit_delete', 'exit_down', 'exit_edit',
                           'exit_insert', 'exit_table', 'exit_up',
                           'task_delete', 'task_down', 'task_edit',
                           'task_insert', 'task_table', 'task_up')
    def __init__(self, parent):
        DialogBase.__init__(self, 'rule_list_dialog', parent)

        self.task = _TaskTable(self.window, self.task_table, self.task_up,
                               self.task_down, self.task_insert,
                               self.task_delete, self.task_edit)
        self.entry = _EntryTable(self.window, self.entry_table, self.entry_up,
                                 self.entry_down, self.entry_insert,
                                 self.entry_delete, self.entry_edit)
        self.exit = _ExitTable(self.window, self.exit_table, self.exit_up,
                               self.exit_down, self.exit_insert,
                               self.exit_delete, self.exit_edit)

    def run(self, task_rules, entry_rules, exit_rules):
        '''Show the dialog to modify task_rules, entry_rules and exit_rules.'''
        self.task.load(task_rules)
        self.entry.load(entry_rules)
        self.exit.load(exit_rules)
        if self.window.run() == gtk.RESPONSE_OK:
            self.task.save(task_rules)
            self.entry.save(entry_rules)
            self.exit.save(exit_rules)
