# Watch rule dialog.
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
import os.path

import audit
import gtk
import gobject

from audit_rules import Field
from dialog_base import DialogBase
from key_list_dialog import KeyListDialog
import util

__all__ = ('WatchDialog')

class WatchDialog(DialogBase):

    '''Watch rule dialog.'''

    _glade_widget_names = ('watch_attr', 'watch_exec', 'watch_keys',
                           'watch_keys_change', 'watch_keys_present',
                           'watch_path', 'watch_path_browse', 'watch_read',
                           'watch_write')
    def __init__(self, parent):
        DialogBase.__init__(self, 'watch_dialog', parent)

        util.connect_and_run(self.watch_keys_present, 'toggled',
                             self.__watch_keys_present_toggled)
        self.watch_keys_change.connect('clicked',
                                       self.__watch_keys_change_clicked)
        self._setup_browse_button(self.watch_path_browse, self.watch_path,
                                  _('Watched File'),
                                  gtk.FILE_CHOOSER_ACTION_SAVE)

        self.keys = []

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
        assert rule.action == rule.ACTION_ALWAYS
        self.keys = []
        have_path = False
        have_perm = False
        for f in rule.fields:
            if f.var == audit.AUDIT_FILTERKEY:
                self.keys.append(f.value)
            elif f.var in (audit.AUDIT_DIR, audit.AUDIT_WATCH):
                assert not have_path
                have_path = True
                self.watch_path.set_text(f.value)
            elif f.var == audit.AUDIT_PERM:
                assert not have_perm
                have_perm = True
                self.watch_read.set_active((f.value & audit.AUDIT_PERM_READ) !=
                                           0)
                self.watch_write.set_active((f.value &
                                             audit.AUDIT_PERM_WRITE) != 0)
                self.watch_exec.set_active((f.value & audit.AUDIT_PERM_EXEC) !=
                                           0)
                self.watch_attr.set_active((f.value & audit.AUDIT_PERM_ATTR) !=
                                           0)
        self.watch_keys_present.set_active(len(self.keys) != 0)
        self.__update_watch_keys()
        if not have_path:
            self.watch_path.set_text('')
        if not have_perm:
            for w in (self.watch_read, self.watch_write, self.watch_exec,
                      self.watch_attr):
                w.set_active(True)

    def _save_rule(self, rule):
        '''Modify rule to reflect dialog state.'''
        assert rule.action == rule.ACTION_ALWAYS
        del rule.fields[:]
        if self.watch_keys_present.get_active():
            for key in self.keys:
                f = Field()
                f.var = audit.AUDIT_FILTERKEY
                f.op = Field.OP_EQ
                f.value = key
                rule.fields.append(f)
        path = self.watch_path.get_text()
        f = Field()
        if os.path.isdir(path):
            f.var = audit.AUDIT_DIR
        else:
            f.var = audit.AUDIT_WATCH
        f.op = Field.OP_EQ
        f.value = path
        rule.fields.append(f)
        perm = 0
        for (w, mask) in ((self.watch_read, audit.AUDIT_PERM_READ),
                          (self.watch_write, audit.AUDIT_PERM_WRITE),
                          (self.watch_exec, audit.AUDIT_PERM_EXEC),
                          (self.watch_attr, audit.AUDIT_PERM_ATTR)):
            if w.get_active():
                perm |= mask
        if mask != (audit.AUDIT_PERM_READ | audit.AUDIT_PERM_WRITE |
                    audit.AUDIT_PERM_EXEC | audit.AUDIT_PERM_ATTR):
            f = Field()
            f.var = audit.AUDIT_PERM
            f.op = Field.OP_EQ
            f.value = perm
            rule.fields.append(f)

    def _validate_get_failure(self):
        if not self.watch_path.get_text():
            return (_('The watched file path must not be empty'), None,
                    self.watch_path)
        return None

    def __update_watch_keys(self):
        '''Update self.watch_keys text.'''
        if len(self.keys) != 0:
            self.watch_keys.set_text(util.keys_string(self.keys))
        else:
            self.watch_keys.set_markup('<i>%s</i>' % _('No key'))

    def __watch_keys_present_toggled(self, *_):
        util.set_sensitive_all(self.watch_keys_present.get_active(),
                               self.watch_keys, self.watch_keys_change)

    def __watch_keys_change_clicked(self, *_):
        dlg = KeyListDialog(self.window)
        res = dlg.run(self.keys)
        dlg.destroy()
        if res == gtk.RESPONSE_OK:
            self.__update_watch_keys()
