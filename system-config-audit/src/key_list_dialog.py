# Key list dialog.
#
# Copyright (C) 2008 Red Hat, Inc.  All rights reserved.
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

from dialog_base import DialogBase
from key_dialog import KeyDialog
import util

__all__ = ('KeyListDialog')

class KeyListDialog(DialogBase):

    '''Key list dialog.'''

    _glade_widget_names = ('keys_add', 'keys_delete', 'keys_down', 'keys_edit',
                           'keys_list', 'keys_up')

    def __init__(self, parent):
        DialogBase.__init__(self, 'key_list_dialog', parent)

        self.keys_store = gtk.ListStore(gobject.TYPE_STRING)
        self.keys_list.set_model(self.keys_store)
        c = gtk.TreeViewColumn(_('Key'), gtk.CellRendererText(), text = 0)
        self.keys_list.append_column(c)
        self.keys_list.connect('row-activated', self.__keys_edit_clicked)
        self.keys_selection = self.keys_list.get_selection()
        util.connect_and_run(self.keys_selection, 'changed',
                             self.__keys_selection_changed)
        self.keys_up.connect('clicked', self.__keys_up_clicked)
        self.keys_down.connect('clicked', self.__keys_down_clicked)
        self.keys_delete.connect('clicked', self.__keys_delete_clicked)
        self.keys_add.connect('clicked', self.__keys_add_clicked)
        self.keys_edit.connect('clicked', self.__keys_edit_clicked)

    def run(self, keys):
        '''Show the dialog to modify the keys list.'''
        self._load_keys(keys)
        res = self.window.run()
        while res == gtk.RESPONSE_OK and not self._validate_values():
            res = self.window.run()
        if res == gtk.RESPONSE_OK:
            self._save_keys(keys)
        return res

    def _load_keys(self, keys):
        '''Modify dialog controls to reflect keys.'''
        self.keys_store.clear()
        for key in keys:
            self.keys_store.append((key,))

    def _save_keys(self, keys):
        '''Modify keys to reflect dialog state.'''
        del keys[:]
        it = self.keys_store.get_iter_first()
        while it is not None:
            keys.append(self.keys_store.get_value(it, 0))
            it = self.keys_store.iter_next(it)

    def _validate_get_failure(self):
        keys = []
        it = self.keys_store.get_iter_first()
        while it is not None:
            keys.append(self.keys_store.get_value(it, 0))
            it = self.keys_store.iter_next(it)
        if len('\x01'.join(keys)) > audit.AUDIT_MAX_KEY_LEN:
            return (_('Total key length is too long'), None, self.keys_list)
        return None

    def __keys_selection_changed(self, *_):
        (model, it) = self.keys_selection.get_selected()
        util.set_sensitive_all(it is not None,
                               self.keys_delete, self.keys_edit)
        self.keys_up.set_sensitive(it is not None and
                                   model.get_path(it) !=
                                   model.get_path(model.get_iter_first()))
        self.keys_down.set_sensitive(it is not None and
                                     model.iter_next(it) is not None)

    def __keys_up_clicked(self, *_):
        util.tree_model_move_up(self.keys_selection)
        self.__keys_selection_changed()

    def __keys_down_clicked(self, *_):
        util.tree_model_move_down(self.keys_selection)
        self.__keys_selection_changed()

    def __keys_delete_clicked(self, *_):
        util.tree_model_delete(self.keys_selection)

    def __keys_add_clicked(self, *_):
        dlg = KeyDialog(self.window)
        (res, key) = dlg.run('')
        dlg.destroy()
        if res == gtk.RESPONSE_OK:
            (model, it) = self.keys_selection.get_selected()
            it = model.insert_after(it)
            model.set_value(it, 0, key)
            self.keys_selection.select_iter(it)

    def __keys_edit_clicked(self, *_):
        (model, it) = self.keys_selection.get_selected()
        if it is None:
            return
        key = model.get_value(it, 0)
        dlg = KeyDialog(self.window)
        (res, key) = dlg.run(key)
        dlg.destroy()
        if res == gtk.RESPONSE_OK:
            model.set_value(it, 0, key)
