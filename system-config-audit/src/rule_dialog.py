# Rule dialog.
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
from gettext import gettext as _
import re

import audit
import gtk
import gobject

import audit_rules
from dialog_base import DialogBase
import field_help
import lists
from key_list_dialog import KeyListDialog
import util

__all__ = ('RuleDialog')

# Shorthands
Rule = audit_rules.Rule
Field = audit_rules.Field

class RuleDialog(DialogBase):

    '''Audit rule dialog.'''

    _glade_widget_names = ('rule_always', 'rule_arch', 'rule_arch_present',
                           'rule_arch_vbox',
                           'rule_field_add', 'rule_field_delete',
                           'rule_field_down', 'rule_field_op', 'rule_field_up',
                           'rule_field_value', 'rule_field_var',
                           'rule_field_var_info', 'rule_fields',
                           'rule_keys', 'rule_keys_change', 'rule_keys_hbox',
                           'rule_keys_present',
                           'rule_never', 'rule_notebook',
                           'rule_syscall_add', 'rule_syscall_delete',
                           'rule_syscall_name', 'rule_syscalls',
                           'rule_syscalls_not_all')

    def __init__(self, parent, excluded_fields, action_always_label,
                 action_never_label):
        '''Initialize a rule dialog, removing fields for excluded_fields.

        If audit.AUDIT_ARCH is in excluded_fields, all syscall handling is
        removed as well.

        '''
        DialogBase.__init__(self, 'rule_dialog', parent,
                            notebook_name = 'rule_notebook')
        self.excluded_fields = excluded_fields

        self.rule_always.set_label(action_always_label)
        util.connect_and_run(self.rule_always, 'toggled',
                             self.__rule_always_toggled)
        if audit.AUDIT_FILTERKEY not in self.excluded_fields:
            util.connect_and_run(self.rule_keys_present, 'toggled',
                                 self.__rule_keys_present_toggled)
            self.rule_keys_change.connect('clicked',
                                          self.__rule_keys_change_clicked)
        else:
            self.rule_keys_hbox.destroy()
        self.rule_never.set_label(action_never_label)
        if audit.AUDIT_ARCH not in self.excluded_fields:
            util.connect_and_run(self.rule_arch_present, 'toggled',
                                 self.__rule_arch_present_toggled)
            self.arch_store = gtk.ListStore(gobject.TYPE_STRING)
            for name in lists.sorted_machine_names:
                self.arch_store.append((name,))
            for name in ('', 'b32', 'b64'):
                self.arch_store.append((name,))
            self.rule_arch.set_model(self.arch_store)
            self.rule_arch.set_text_column(0)
            self.rule_arch.set_row_separator_func(util.is_row_separator)
        else:
            self.rule_arch_vbox.destroy()

        if audit.AUDIT_ARCH not in self.excluded_fields:
            util.connect_and_run(self.rule_syscalls_not_all, 'toggled',
                                 self.__rule_syscalls_not_all_toggled)
            self.syscall_store = gtk.ListStore(gobject.TYPE_STRING)
            self.rule_syscalls.set_model(self.syscall_store)
            c = gtk.TreeViewColumn(_('System Call'), gtk.CellRendererText(),
                                   text = 0)
            self.rule_syscalls.append_column(c)
            self.syscalls_selection = self.rule_syscalls.get_selection()
            util.connect_and_run(self.syscalls_selection, 'changed',
                                 self.__syscalls_selection_changed)
            self.rule_syscall_delete.connect('clicked',
                                             self.__rule_syscall_delete_clicked)
            self.syscall_name_store = gtk.ListStore(gobject.TYPE_STRING)
            self.rule_syscall_name.set_model(self.syscall_name_store)
            self.rule_syscall_name.set_text_column(0)
            self.rule_syscall_add.connect('clicked',
                                          self.__rule_syscall_add_clicked)
            self.fields_page = 2
        else:
            self.rule_notebook.remove_page(1)
            self.fields_page = 1

        self.fields_store = gtk.ListStore(gobject.TYPE_PYOBJECT,
                                          gobject.TYPE_STRING)
        self.rule_fields.set_model(self.fields_store)
        c = gtk.TreeViewColumn(_('Condition'), gtk.CellRendererText(), text = 1)
        self.rule_fields.append_column(c)
        self.fields_selection = self.rule_fields.get_selection()
        util.connect_and_run(self.fields_selection, 'changed',
                             self.__fields_selection_changed)
        self.rule_field_up.connect('clicked', self.__rule_field_up_clicked)
        self.rule_field_down.connect('clicked', self.__rule_field_down_clicked)
        self.rule_field_delete.connect('clicked',
                                       self.__rule_field_delete_clicked)
        self.rule_field_add.connect('clicked', self.__rule_field_add_clicked)
        self.field_var_store = gtk.ListStore(gobject.TYPE_STRING)
        fields = (field for field in lists.field_vars
                  if (field not in (audit.AUDIT_ARCH, audit.AUDIT_FILTERKEY) and
                      field not in self.excluded_fields))
        for name in sorted(lists.ids_to_names(fields,
                                              audit.audit_field_to_name)):
            self.field_var_store.append((name,))
        self.rule_field_var.set_model(self.field_var_store)
        cell = gtk.CellRendererText()
        self.rule_field_var.pack_start(cell, True)
        self.rule_field_var.set_attributes(cell, text = 0)
        util.connect_and_run(self.rule_field_var, 'changed',
                             self.__rule_field_var_changed)
        self.field_op_store = gtk.ListStore(gobject.TYPE_STRING)
        for op in Field.all_operators:
            self.field_op_store.append((op,))
        self.rule_field_op.set_model(self.field_op_store)
        cell = gtk.CellRendererText()
        self.rule_field_op.pack_start(cell, True)
        self.rule_field_op.set_attributes(cell, text = 0)
        self.rule_field_op.set_row_separator_func(util.is_row_separator)
        self.field_value_store = gtk.ListStore(gobject.TYPE_STRING)
        self.rule_field_value.set_model(self.field_value_store)
        self.rule_field_value.set_text_column(0)

        self.keys = []
        self.machine_id = None
        self.last_arch_name = None
        if audit.AUDIT_ARCH not in self.excluded_fields:
            util.connect_and_run(self.rule_arch.child, 'focus-out-event',
                                 self.__rule_arch_focus_out)

    def run(self, rule):
        '''Show the dialog to modify rule.'''
        self._load_rule(rule)
        res = self.window.run()
        while res == gtk.RESPONSE_OK and not self._validate_values():
            res = self.window.run()
        if res == gtk.RESPONSE_OK:
            self._save_rule(rule)
        return res

    __action_map = (('rule_always', Rule.ACTION_ALWAYS),
                    ('rule_never', Rule.ACTION_NEVER))
    def _load_rule(self, rule):
        '''Modify dialog controls to reflect rule.'''
        self._radio_set(rule.action, self.__action_map)
        if audit.AUDIT_FILTERKEY not in self.excluded_fields:
            self.keys = [f.value for f in rule.fields
                         if f.var == audit.AUDIT_FILTERKEY]
            self.rule_keys_present.set_active(len(self.keys) != 0)
            self.__update_rule_keys()
        if audit.AUDIT_ARCH not in self.excluded_fields:
            for f in rule.fields:
                if f.var == audit.AUDIT_ARCH:
                    self.rule_arch_present.set_active(True)
                    try:
                        m = util.parse_elf(f.value)
                    except util.ParsingError:
                        assert False, 'Rule should not have been created'
                    util.set_combo_entry_text(self.rule_arch, f.value)
                    break
            else:
                self.rule_arch_present.set_active(False)
                self.rule_arch.set_active(-1)
                self.rule_arch.child.set_text('')
                m = util.audit_machine_id
            assert rule.machine == m
            self.__rule_arch_changed()

        if audit.AUDIT_ARCH not in self.excluded_fields:
            self.syscall_store.clear()
            if Rule.SYSCALLS_ALL in rule.syscalls:
                self.rule_syscalls_not_all.set_active(False)
            else:
                self.rule_syscalls_not_all.set_active(True)
                for sc in rule.syscalls:
                    name = util.syscall_string(sc, self.machine_id)
                    self.syscall_store.append((name,))

        self.fields_store.clear()
        for field in rule.fields:
            if field.var not in (audit.AUDIT_ARCH, audit.AUDIT_FILTERKEY):
                it = self.fields_store.append()
                self.fields_store.set_value(it, 0, field)
                self.__update_fields_store_row(it)

    def _save_rule(self, rule):
        '''Modify rule to reflect dialog state.'''
        rule.action = self._radio_get(self.__action_map)

        del rule.fields[:]
        if (audit.AUDIT_FILTERKEY not in self.excluded_fields and
            self.rule_keys_present.get_active()):
            for key in self.keys:
                f = Field()
                f.var = audit.AUDIT_FILTERKEY
                f.op = Field.OP_EQ
                f.value = key
                rule.fields.append(f)
        if audit.AUDIT_ARCH not in self.excluded_fields:
            if self.rule_arch_present.get_active():
                f = Field()
                f.var = audit.AUDIT_ARCH
                f.op = Field.OP_EQ
                f.value = self.rule_arch.child.get_text()
                try:
                    rule.machine = util.parse_elf(f.value)
                except util.ParsingError:
                    assert False, 'Should have been validated'
                rule.fields.append(f)
            else:
                rule.machine = util.audit_machine_id
        it = self.fields_store.get_iter_first()
        while it is not None:
            rule.fields.append(self.fields_store.get_value(it, 0))
            it = self.fields_store.iter_next(it)

        if audit.AUDIT_ARCH not in self.excluded_fields:
            del rule.syscalls[:]
            if self.rule_syscalls_not_all.get_active():
                it = self.syscall_store.get_iter_first()
                while it is not None:
                    name = self.syscall_store.get_value(it, 0)
                    try:
                        sc = util.parse_syscall(name, self.machine_id)
                    except util.ParsingError:
                        assert False, 'Should have been validated'
                    rule.syscalls.append(sc)
                    it = self.syscall_store.iter_next(it)
                assert len(rule.syscalls) > 0
            else:
                rule.syscalls.append(Rule.SYSCALLS_ALL)

    def _validate_get_failure(self):
        if (audit.AUDIT_ARCH not in self.excluded_fields and
            self.rule_arch_present.get_active()):
            try:
                util.parse_elf(self.rule_arch.child.get_text())
            except util.ParsingError, e:
                return (str(e), 0, self.rule_arch)
        if (audit.AUDIT_ARCH not in self.excluded_fields and
            self.rule_syscalls_not_all.get_active()):
            it = self.syscall_store.get_iter_first()
            while it is not None:
                name = self.syscall_store.get_value(it, 0)
                try:
                    util.parse_syscall(name, self.machine_id)
                except util.ParsingError, e:
                    self.syscalls_selection.select_iter(it)
                    return (str(e), 1, self.rule_syscalls)
                it = self.syscall_store.iter_next(it)
            if self.syscall_store.get_iter_first() is None:
                return (_('The system call list must not be empty'), 1,
                        self.rule_syscalls)
        return None

    def __update_rule_keys(self):
        '''Update text in self.rule_keys'''
        if len(self.keys) != 0:
            self.rule_keys.set_text(util.keys_string(self.keys))
        else:
            self.rule_keys.set_markup('<i>%s</i>' % _('No key'))

    def __update_fields_store_row(self, it):
        '''Update the text in the self.fields_store row selected by it.'''
        field = self.fields_store.get_value(it, 0)
        self.fields_store.set_value(it, 1, field.user_text())

    def __rule_always_toggled(self, *_):
        if audit.AUDIT_FILTERKEY not in self.excluded_fields:
            util.set_sensitive_all(self.rule_always.get_active(),
                                   self.rule_keys_present,
                                   # self.rule_keys, self.rule_keys_change
                                   # excluded
                                   )
            self.__rule_keys_present_toggled()

    def __rule_keys_present_toggled(self, *_):
        util.set_sensitive_all(self.rule_always.get_active() and
                               self.rule_keys_present.get_active(),
                               self.rule_keys, self.rule_keys_change)

    def __rule_keys_change_clicked(self, *_):
        dlg = KeyListDialog(self.window)
        res = dlg.run(self.keys)
        dlg.destroy()
        if res == gtk.RESPONSE_OK:
            self.__update_rule_keys()

    def __rule_arch_present_toggled(self, *_):
        self.rule_arch.set_sensitive(self.rule_arch_present.get_active())

    def __rule_syscalls_not_all_toggled(self, *_):
        util.set_sensitive_all(self.rule_syscalls_not_all.get_active(),
                               self.rule_syscalls, self.rule_syscall_delete,
                               self.rule_syscall_name, self.rule_syscall_add)

    def __syscalls_selection_changed(self, *_):
        (model, it) = self.syscalls_selection.get_selected()
        self.rule_syscall_delete.set_sensitive(it is not None)

    def __rule_syscall_delete_clicked(self, *_):
        util.tree_model_delete(self.syscalls_selection)

    def __rule_syscall_add_clicked(self, *_):
        name = self.rule_syscall_name.child.get_text()
        try:
            util.parse_syscall(name, self.machine_id)
        except util.ParsingError, e:
            self._modal_error_dialog(str(e))
            self.rule_syscall_name.grab_focus()
            return
        it = self.syscall_store.get_iter_first()
        while it is not None:
            next = self.syscall_store.get_value(it, 0)
            if name == next:
                break
            if name < next:
                self.syscall_store.insert_before(it, (name,))
                break
            it = self.syscall_store.iter_next(it)
        else:
            self.syscall_store.insert_before(None, (name,))

    def __rule_arch_focus_out(self, *_):
        try:
            self.__rule_arch_changed()
        except util.ParsingError, e:
            # Changing the focus within a focus change callback looks evil,
            # defer it until it is safe.  Don't return focus to
            # self.rule_arch.child, because that wouldn't allow the user to
            # choose another architecture from the combo box.
            def callback():
                self._modal_error_dialog(str(e))
                self.rule_notebook.set_current_page(0)
                return False
            gobject.idle_add(callback)
        return False

    __non_exit_syscall_re = re.compile('execve|vm86')
    def __rule_arch_changed(self):
        '''Recompute self.machine_id and self.syscall_name_store.

        Raise ParsingError if the self.rule_arch.child is invalid.

        '''
        if not self.rule_arch_present.get_active():
            machine = util.audit_machine_id
            self.last_arch_name = None
        else:
            name = self.rule_arch.child.get_text()
            if self.last_arch_name is not None and name == self.last_arch_name:
                return
            machine = util.parse_elf(name) # May raise ParsingError
        if self.machine_id == machine:
            return
        self.machine_id = machine
        self.syscall_name_store.clear()

        def sc_to_name(sc):
            return audit.audit_syscall_to_name(sc, machine)
        names = lists.ids_to_names(lists.syscalls, sc_to_name)
        names.sort()
        # As an UGLY special case, some system calls never exit.  Exclude them
        # from exit filters == filters where the exit value is available.
        keep_non_exit = audit.AUDIT_EXIT in self.excluded_fields
        for name in names:
            if (keep_non_exit or
                self.__non_exit_syscall_re.search(name) is None):
                self.syscall_name_store.append((name,))

    def __fields_selection_changed(self, *_):
        (model, it) = self.fields_selection.get_selected()
        self.rule_field_delete.set_sensitive(it is not None)
        self.rule_field_up.set_sensitive(it is not None and
                                         model.get_path(it) !=
                                         model.get_path(model.get_iter_first()))
        self.rule_field_down.set_sensitive(it is not None and
                                           model.iter_next(it) is not None)

    def __rule_field_up_clicked(self, *_):
        util.tree_model_move_up(self.fields_selection)
        self.__fields_selection_changed()

    def __rule_field_down_clicked(self, *_):
        util.tree_model_move_down(self.fields_selection)
        self.__fields_selection_changed()

    def __rule_field_delete_clicked(self, *_):
        util.tree_model_delete(self.fields_selection)

    def __rule_field_add_clicked(self, *_):
        it = self.rule_field_var.get_active_iter()
        if it is None:
            return
        var = self.field_var_store.get_value(it, 0)
        it = self.rule_field_op.get_active_iter()
        if it is None:
            return
        op = self.field_op_store.get_value(it, 0)
        field = Field()
        try:
            field.parse_triple(var, op, self.rule_field_value.child.get_text())
        except util.ParsingError, e:
            self.rule_notebook.set_current_page(self.fields_page)
            self._modal_error_dialog(str(e))
            # Guess which widget is incorrect
            self.rule_field_value.child.grab_focus()
            return
        (model, it) = self.fields_selection.get_selected()
        it = model.insert_before(it)
        model.set_value(it, 0, field)
        self.__update_fields_store_row(it)
        self.fields_selection.select_iter(it)

    def __rule_field_var_changed(self, *_):
        it = self.rule_field_var.get_active_iter()
        util.set_sensitive_all(it is not None,
                               self.rule_field_op, self.rule_field_value,
                               self.rule_field_add)
        if it is None:
            self.rule_field_var_info.set_text('')
            return
        name = self.field_var_store.get_value(it, 0)
        try:
            var = audit.audit_name_to_field(name)
        except OSError:
            var = None

        it = self.rule_field_op.get_active_iter()
        if it:
            old_op = self.field_op_store.get_value(it, 0)
        else:
            old_op = None
        self.field_op_store.clear()
        self.field_value_store.clear()
        if var is not None:
            field_type = Field.get_field_type(var)
            ops = field_type.usual_operators(var)
            for op in ops:
                self.field_op_store.append((op,))
            if set(ops) != set(Field.all_operators):
                self.field_op_store.append(('',))
                for op in Field.all_operators:
                    if op not in ops:
                        self.field_op_store.append((op,))
            for hint in field_type.hints():
                self.field_value_store.append((hint,))
        else:
            for op in Field.all_operators:
                self.field_op_store.append((op,))
        if old_op is not None:
            util.set_combo_option(self.rule_field_op, old_op)
        self.rule_field_var_info.set_text(field_help.field_help(var))
