# Common rule table behavior.
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
import sys

import audit
import gobject
import gtk

from audit_rules import Rule
from rule_dialog import RuleDialog
import util

__all__ = ('RuleTable')

def N_(s): return s

class RuleTable(object):

    '''A rule table and its associated buttons.'''

    _action_labels = (N_('Audit'), N_('Do not audit'))

    def __init__(self, window, tree_view, up_button, down_button, insert_button,
                 delete_button, edit_button):
        '''Initialize a table.

        The subclass must supply _column_titles.

        '''
        self.window = window
        self.up_button = up_button
        self.down_button = down_button
        self.delete_button = delete_button
        self.edit_button = edit_button
        self.store = gtk.ListStore(gobject.TYPE_PYOBJECT,
                                   *((gobject.TYPE_STRING,)
                                     * len(self._column_titles)))
        tree_view.set_model(self.store)
        column = 1
        for title in self._column_titles:
            c = gtk.TreeViewColumn(_(title), gtk.CellRendererText(),
                                   text = column)
            c.set_resizable(True)
            tree_view.append_column(c)
            column += 1
        tree_view.connect('row-activated', self.__edit_button_clicked)
        self.selection = tree_view.get_selection()
        util.connect_and_run(self.selection, 'changed',
                             self.__selection_changed)
        up_button.connect('clicked', self.__up_button_clicked)
        down_button.connect('clicked', self.__down_button_clicked)
        insert_button.connect('clicked', self.__insert_button_clicked)
        delete_button.connect('clicked', self.__delete_button_clicked)
        edit_button.connect('clicked', self.__edit_button_clicked)

    def load(self, rules):
        '''Load self.store from rules.'''
        self.store.clear()
        for rule in rules:
            err = self._validate_rule(rule)
            if err is not None:
                # FIXME: GUI?
                print >> sys.stderr, err
                continue
            it = self.store.append()
            self.store.set_value(it, 0, rule)
            self._update_row(it, rule)

    def save(self, rules):
        '''Save self.store to rules.'''
        del rules[:]
        it = self.store.get_iter_first()
        while it is not None:
            rules.append(self.store.get_value(it, 0))
            it = self.store.iter_next(it)

    @staticmethod
    def _validate_rule(rule):
        '''Check whether a rule is valid and may be loaded.

        Return an error message, or None if OK.

        '''
        return None

    @staticmethod
    def _new_rule():
        '''Return a new rule to be edited.'''
        raise NotImplementedError

    @classmethod
    def _new_dialog(cls, parent):
        '''Return a dialog for rule editing, transient for parent.

        The default implementations requires defined values of excluded_fields
        and _action_labels'''
        return RuleDialog(parent, cls.excluded_fields, _(cls._action_labels[0]),
                          _(cls._action_labels[1]))

    def _update_row(self, it, rule):
        '''Update the text in self.store row selected by it for rule.'''
        raise NotImplementedError

    def _row_set_filter_key(self, it, column, rule):
        '''Set column column in it to the key of rule.'''
        keys = (field.value for field in rule.fields
                if field.var == audit.AUDIT_FILTERKEY)
        self.store.set_value(it, column, util.keys_string(keys))

    def _row_set_syscalls(self, it, column, rule):
        '''Set column column in it to the syscalls of rule.'''
        if Rule.SYSCALLS_ALL in rule.syscalls:
            text = _('Any')
        else:
            text = ', '.join((util.syscall_string(sc, rule.machine)
                              for sc in rule.syscalls))
        self.store.set_value(it, column, text)

    def _row_set_fields(self, it, column, rule):
        '''Set column column in it to the fields of rule.'''
        conds = (f.user_text() for f in rule.fields
                 if f.var != audit.AUDIT_FILTERKEY)
        # TRANSLATORS: This string is used to connect audit rule conditions.
        self.store.set_value(it, column, _(' and ').join(conds))

    def _row_set_action(self, it, column, rule):
        '''Set column column in it to the action of rule.'''
        if rule.action == Rule.ACTION_ALWAYS:
            text = _(self._action_labels[0])
        elif rule.action == Rule.ACTION_NEVER:
            text = _(self._action_labels[1])
        else:
            assert False, 'Unknown rule action %s' % rule.action
        self.store.set_value(it, column, text)

    def __selection_changed(self, *_):
        (model, it) = self.selection.get_selected()
        util.set_sensitive_all(it is not None,
                               self.delete_button, self.edit_button)
        self.up_button.set_sensitive(it is not None and
                                     model.get_path(it) !=
                                     model.get_path(model.get_iter_first()))
        self.down_button.set_sensitive(it is not None and
                                       model.iter_next(it) is not None)

    def __up_button_clicked(self, *_):
        util.tree_model_move_up(self.selection)
        self.__selection_changed()

    def __down_button_clicked(self, *_):
        util.tree_model_move_down(self.selection)
        self.__selection_changed()

    def __insert_button_clicked(self, *_):
        rule = self._new_rule()
        dlg = self._new_dialog(self.window)
        res = dlg.run(rule)
        dlg.destroy()
        if res == gtk.RESPONSE_OK:
            (model, it) = self.selection.get_selected()
            it = model.insert_before(it)
            model.set_value(it, 0, rule)
            self._update_row(it, rule)
            self.selection.select_iter(it)

    def __delete_button_clicked(self, *_):
        util.tree_model_delete(self.selection)
        self.__selection_changed()

    def __edit_button_clicked(self, *_):
        (model, it) = self.selection.get_selected()
        if it is None:
            return
        rule = model.get_value(it, 0)
        dlg = self._new_dialog(self.window)
        res = dlg.run(rule)
        dlg.destroy()
        if res == gtk.RESPONSE_OK:
            self._update_row(it, rule)

