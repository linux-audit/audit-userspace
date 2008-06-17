# Event type rule list dialog.
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
import sets

import audit
import gtk

from audit_rules import Rule
from dialog_base import DialogBase
from event_type_dialog import EventTypeDialog
import lists
from rule_table import RuleTable
import util

__all__ = ('TypeListDialog')

def N_(s): return s

class _UserTable(RuleTable):
    _column_titles = (N_('Condition'), N_('Action'))
    excluded_fields = tuple(sets.Set(lists.field_vars).
                            difference((audit.AUDIT_LOGINUID, audit.AUDIT_GID,
                                        audit.AUDIT_PID, audit.AUDIT_UID)))

    @staticmethod
    def _new_rule():
        rule = Rule()
        rule.action = rule.ACTION_ALWAYS
        rule.syscalls = [rule.SYSCALLS_ALL]
        return rule

    def _update_row(self, it, rule):
        self._row_set_fields(it, 1, rule)
        self._row_set_action(it, 2, rule)

class _ExcludeTable(RuleTable):
    _column_titles = (N_('Condition'),)

    @staticmethod
    def _validate_rule(rule):
        if len(rule.fields) > 1:
            return 'More than one field in an exclude rule'
        if rule.fields and rule.fields[0].var != audit.AUDIT_MSGTYPE:
            return 'Unexpected field type in an exclude rule'
        return None

    @staticmethod
    def _new_rule():
        rule = Rule()
        rule.action = rule.ACTION_ALWAYS
        return rule

    @classmethod
    def _new_dialog(_, parent):
        return EventTypeDialog(parent)

    def _update_row(self, it, rule):
        if not rule.fields:
            text = _('Any type')
        else:
            field = rule.fields[0]
            assert field.var == audit.AUDIT_MSGTYPE
            text = '%s %s %s' % (_('Type'), field.op,
                                 util.msgtype_string(field.value))
        self.store.set_value(it, 1, text)

class TypeListDialog(DialogBase):

    '''Event type rule list dialog.'''

    _glade_widget_names = ('msg_delete', 'msg_down', 'msg_edit', 'msg_insert',
                           'msg_table', 'msg_up',
                           'user_delete', 'user_down', 'user_edit',
                           'user_insert', 'user_table', 'user_up')
    def __init__(self, parent):
        DialogBase.__init__(self, 'type_list_dialog', parent)

        self.user = _UserTable(self.window, self.user_table, self.user_up,
                               self.user_down, self.user_insert,
                               self.user_delete, self.user_edit)
        self.exclude = _ExcludeTable(self.window, self.msg_table, self.msg_up,
                                     self.msg_down, self.msg_insert,
                                     self.msg_delete, self.msg_edit)

    def run(self, config):
        '''Show the dialog to modify task_rules, entry_rules and exit_rules.'''
        self.user.load(config.rules.user_rules)
        self.exclude.load(config.rules.exclude_rules)
        if self.window.run() == gtk.RESPONSE_OK:
            self.user.save(config.rules.user_rules)
            self.exclude.save(config.rules.exclude_rules)
