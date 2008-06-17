# Watch list dialog.
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

from audit_rules import Field, Rule
from dialog_base import DialogBase
from rule_table import RuleTable
from watch_dialog import WatchDialog

__all__ = ('WatchListDialog',
           'is_watch_rule')

def N_(s): return s

class _WatchTable(RuleTable):
    _column_titles = (N_('Key'), N_('Path'), N_('Operations'))

    @staticmethod
    def _validate_rule(rule):
        if rule.action != rule.ACTION_ALWAYS:
            return 'Action in watch table is not "always"'
        counts = {}
        for f in rule.fields:
            counts[f.var] = counts.get(f.var, 0) + 1
        if ((counts.get(audit.AUDIT_DIR, 0)
             + counts.get(audit.AUDIT_WATCH, 0)) > 1 or
            counts.get(audit.AUDIT_PERM, 0) > 1):
            return 'Duplicate dir/watch or perm field'
        if not set(counts.iterkeys()).issubset(set((audit.AUDIT_DIR,
                                                    audit.AUDIT_FILTERKEY,
                                                    audit.AUDIT_PERM,
                                                    audit.AUDIT_WATCH))):
            return 'Unexpected fields in watch table'
        if rule.SYSCALLS_ALL not in rule.syscalls:
            return 'Non-default syscalls in watch table'
        return None

    @staticmethod
    def _new_rule():
        rule = Rule()
        rule.action = rule.ACTION_ALWAYS
        rule.syscalls = [rule.SYSCALLS_ALL]
        return rule

    @classmethod
    def _new_dialog(_, parent):
        return WatchDialog(parent)

    def _update_row(self, it, rule):
        self._row_set_filter_key(it, 1, rule)
        for field in rule.fields:
            if field.var in (audit.AUDIT_DIR, audit.AUDIT_WATCH):
                text = field.value
                break
        else:
            text = ''
        self.store.set_value(it, 2, text)
        for field in rule.fields:
            if field.var == audit.AUDIT_PERM:
                perm = field.value
                break
        else:
            perm = (audit.AUDIT_PERM_READ | audit.AUDIT_PERM_WRITE |
                    audit.AUDIT_PERM_EXEC | audit.AUDIT_PERM_ATTR)
        self.store.set_value(it, 3, Field.get_field_type(audit.AUDIT_PERM).
                             value_text(perm))

def is_watch_rule(rule):
    '''Return True if exit rule is suitable for the WatchListDialog.'''
    return _WatchTable._validate_rule(rule) is None

class WatchListDialog(DialogBase):

    '''Watch list dialog.'''

    _glade_widget_names = ('watch_delete', 'watch_down', 'watch_edit',
                           'watch_insert', 'watch_table', 'watch_up')
    def __init__(self, parent):
        DialogBase.__init__(self, 'watch_list_dialog', parent)

        self.table = _WatchTable(self.window, self.watch_table, self.watch_up,
                                 self.watch_down, self.watch_insert,
                                 self.watch_delete, self.watch_edit)

    def run(self, rules):
        '''Show the dialog to modify rules.'''
        self.table.load(rules)
        if self.window.run() == gtk.RESPONSE_OK:
            self.table.save(rules)
