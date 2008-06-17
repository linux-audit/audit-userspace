# Key properties dialog.
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
import gobject
import gtk

from dialog_base import DialogBase
import lists
import util

__all__ = ('KeyDialog')

class KeyDialog(DialogBase):

    '''Key properties dialog.'''

    _glade_widget_names = ('key_ids_severity', 'key_ids_severity_label',
                           'key_ids_type', 'key_ids_type_label', 'key_is_ids',
                           'key_is_text', 'key_text')
    def __init__(self, parent):
        DialogBase.__init__(self, 'key_dialog', parent)
        util.connect_and_run(self.key_is_text, 'toggled',
                             self.__key_is_text_toggled)
        self.key_text.set_max_length(audit.AUDIT_MAX_KEY_LEN)
        util.connect_and_run(self.key_is_ids, 'toggled',
                             self.__key_is_ids_toggled)
        self.type_store = gtk.ListStore(gobject.TYPE_STRING,
                                        gobject.TYPE_STRING)
        for (type_, label) in lists.ids_types:
            self.type_store.append((type_, _(label)))
        self.key_ids_type.set_model(self.type_store)
        cell = gtk.CellRendererText()
        self.key_ids_type.pack_start(cell, True)
        self.key_ids_type.set_attributes(cell, text = 1)
        self.severity_store = gtk.ListStore(gobject.TYPE_STRING,
                                            gobject.TYPE_STRING)
        for (severity, label) in lists.ids_severities:
            self.severity_store.append((severity, _(label)))
        self.key_ids_severity.set_model(self.severity_store)
        cell = gtk.CellRendererText()
        self.key_ids_severity.pack_start(cell, True)
        self.key_ids_severity.set_attributes(cell, text = 1)

    def run(self, key):
        '''Show the dialog to modify or create key.

        Return (dialog result, modified key or None).

        '''
        self._load_key(key)
        res = self.window.run()
        while res == gtk.RESPONSE_OK and not self._validate_values():
            res = self.window.run()
        if res == gtk.RESPONSE_OK:
            key = self._save_key()
        else:
            key = None
        return (res, key)

    def _load_key(self, key):
        '''Modify dialog controls to reflect key.'''
        ids_key = util.parse_ids_key(key)
        # Silently show invalid IDS keys as text, only refuse them when closing
        # the dialog.
        if ids_key is None:
            self.key_is_text.set_active(True)
            self.key_text.set_text(key)
        else:
            self.key_is_ids.set_active(True)
            (type_, severity) = ids_key
            util.set_combo_option(self.key_ids_type, type_)
            util.set_combo_option(self.key_ids_severity, severity)

    def _save_key(self):
        '''Return key value corresponding to dialog state.'''
        if self.key_is_text.get_active():
            return self.key_text.get_text()
        else:
            type_ = self.type_store.get_value(self.key_ids_type
                                              .get_active_iter(), 0)
            severity = self.severity_store.get_value(self.key_ids_severity
                                                     .get_active_iter(), 0)
            return 'ids-%s-%s' % (type_, severity)

    def _validate_get_failure(self):
        if self.key_is_text.get_active():
            key = self.key_text.get_text()
            if util.is_ids_key(key) and util.parse_ids_key(key) is None:
                return (_('Invalid IDS key value'), None, self.key_text)
        return None

    def __key_is_text_toggled(self, *_):
        self.key_text.set_sensitive(self.key_is_text.get_active())

    def __key_is_ids_toggled(self, *_):
        util.set_sensitive_all(self.key_is_ids.get_active(),
                               self.key_ids_type_label, self.key_ids_type,
                               self.key_ids_severity_label,
                               self.key_ids_severity)
