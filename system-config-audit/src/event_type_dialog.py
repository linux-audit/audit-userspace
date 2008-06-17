# Event type rule dialog.
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
import gobject

from audit_rules import Field
from dialog_base import DialogBase
import lists
import util

__all__ = ('EventTypeDialog')

# For convenience
ParsingError = util.ParsingError

class EventTypeDialog(DialogBase):

    '''Message type filter dialog.'''

    _glade_widget_names = ('event_type_any', 'event_type_condition',
                           'event_type_op', 'event_type_value')
    def __init__(self, parent):
        DialogBase.__init__(self, 'event_type_dialog', parent)

        util.connect_and_run(self.event_type_condition, 'toggled',
                             self.__event_type_condition_toggled)
        self.op_store = gtk.ListStore(gobject.TYPE_STRING)
        # Most operators are unlikely to be used, but the dialog must be able to
        # represent them
        for op in (Field.OP_EQ, Field.OP_NE, ''):
            self.op_store.append((op,))
        for op in Field.all_operators:
            if op not in (Field.OP_EQ, Field.OP_NE):
                self.op_store.append((op,))
        self.event_type_op.set_model(self.op_store)
        cell = gtk.CellRendererText()
        self.event_type_op.pack_start(cell, True)
        self.event_type_op.set_attributes(cell, text = 0)
        self.event_type_op.set_row_separator_func(util.is_row_separator)

        store = gtk.ListStore(gobject.TYPE_STRING)
        for name in lists.event_type_names:
            store.append((name,))
        self.event_type_value.set_model(store)
        self.event_type_value.set_text_column(0)

    def run(self, rule):
        '''Show the dialog to modify rule.'''
        self._load_rule(rule)
        res = self.window.run()
        while res == gtk.RESPONSE_OK and not self._validate_values():
            res = self.window.run()
        if res == gtk.RESPONSE_OK:
            self._save_rule(rule)
        return res

    def _load_rule(self, rule):
        '''Modify dialog controls to reflect rule.'''
        assert len(rule.fields) <= 1
        has_field = len(rule.fields) == 1
        self.event_type_any.set_active(not has_field)
        self.event_type_condition.set_active(has_field)
        if has_field:
            field = rule.fields[0]
            assert field.var == audit.AUDIT_MSGTYPE
            util.set_combo_option(self.event_type_op, field.op)
            util.set_combo_entry_text(self.event_type_value,
                                      util.msgtype_string(field.value))
        else:
            self.event_type_op.set_active(-1)
            self.event_type_value.set_active(-1)
            self.event_type_value.child.set_text('')

    def _save_rule(self, rule):
        '''Modify rule to reflect dialog state.'''
        del rule.fields[:]
        if self.event_type_condition.get_active():
            f = Field()
            f.var = audit.AUDIT_MSGTYPE
            f.op = self.op_store.get_value(self.event_type_op.get_active_iter(),
                                           0)
            try:
                f.value = util.parse_msgtype(self.event_type_value.child.
                                             get_text())
            except ParsingError:
                assert False, 'Should have been validated'
            rule.fields.append(f)

    def _validate_get_failure(self):
        if self.event_type_condition.get_active():
            if self.event_type_op.get_active() == -1:
                return (_('No operator was selected'), None, self.event_type_op)
            try:
                util.parse_msgtype(self.event_type_value.child.get_text())
            except ParsingError, e:
                return (str(e), None, self.event_type_value)
        return None

    def __event_type_condition_toggled(self, *_):
        util.set_sensitive_all(self.event_type_condition.get_active(),
                               self.event_type_op, self.event_type_value)
