# Main application window.
# coding=utf-8
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
import copy
from gettext import gettext as _

import audit
import gtk

from config import Config
from dialog_base import DialogBase
from global_dialog import GlobalDialog
from rule_list_dialog import RuleListDialog
from save_dialog import SaveDialog
from type_list_dialog import TypeListDialog
from watch_list_dialog import WatchListDialog, is_watch_rule
import settings
import util

def exit_watch_rules(rules):
    '''Split exit rules to lists for WatchListDialog and RuleListDialog.

    Return (RuleListDialog rules, WatchListDialog rules).

    '''
    exit_rules = []
    watch_rules = []
    for rule in rules:
        if is_watch_rule(rule):
            watch_rules.append(rule)
        else:
            exit_rules.append(rule)
    return (exit_rules, watch_rules)


class MainWindow(DialogBase):

    '''Main window of system-config-audit.'''

    _glade_widget_names = ('config_global_edit', 'config_rules_edit',
                           'config_rules_label', 'config_save', 'config_state',
                           'config_types_edit', 'config_types_label',
                           'config_watches_edit', 'config_watches_label',
                           'enabled_change_button',
                           'menu_about', 'menu_quit',
                           'status_auditd_pid', 'status_backlog',
                           'status_enabled', 'status_lost', 'status_refresh')

    def __init__(self):
        DialogBase.__init__(self, 'app_window', None)

        self.window.connect('delete-event', self.__menu_quit_activate)
        self.menu_quit.connect('activate', self.__menu_quit_activate)
        self.menu_about.connect('activate', self.__menu_about_activate)

        self.enabled_change_button.connect('clicked',
                                           self.__enabled_change_button_clicked)
        self.status_refresh.connect('clicked', self.__status_refresh_clicked)
        self.config_save.connect('clicked', self.__config_save_clicked)

        self.config_watches_edit.connect('clicked',
                                         self.__config_watches_edit_clicked)
        self.config_rules_edit.connect('clicked',
                                       self.__config_rules_edit_clicked)
        self.config_types_edit.connect('clicked',
                                       self.__config_types_edit_clicked)
        self.config_global_edit.connect('clicked',
                                        self.__config_global_edit_clicked)


    def _refresh_status(self):
        '''Refresh status displayed in the window.'''
        try:
            status = self.client.audit_status()
        except IOError:
            status = None
        if status is not None:
            (_1, enabled, _2, pid, _3, _4, lost, backlog) = status
            self.enabled_value = enabled
            if enabled == 0:
                self.status_enabled.set_text(_('Auditing disabled.'))
                self.enabled_change_button.set_label(_('_Enable'))
                self.enabled_change_button.set_sensitive(True)
            elif enabled == 1:
                self.status_enabled.set_text(_('Auditing enabled.'))
                self.enabled_change_button.set_label(_('_Disable'))
                self.enabled_change_button.set_sensitive(True)
            elif enabled == 2:
                self.status_enabled.set_text(_('Auditing enabled and locked.'))
                self.enabled_change_button.set_label(_('_Disable'))
                self.enabled_change_button.set_sensitive(False)
            else:
                self.status_enabled.set_text(_('Unknown auditing status %s.')
                                             % enabled)
                self.enabled_change_button.set_label(_('???'))
                self.enabled_change_button.set_sensitive(False)
            self.status_auditd_pid.set_text(str(pid))
            self.status_lost.set_text(str(lost))
            self.status_backlog.set_text(str(backlog))
        else:
            self.enabled_value = None
            self.status_enabled.set_text(_('Error determining auditing status'))
            self.enabled_change_button.set_label(_('???'))
            self.enabled_change_button.set_sensitive(False)
            self.status_auditd_pid.set_text('')
            self.status_lost.set_text('')
            self.status_backlog.set_text('')

    def run(self, client):
        '''Run the main window, using client to access configuration.'''
        self.client = client
        self.config = Config(client)
        try:
            self.config.read()
        except IOError, e:
            util.modal_error_dialog(None, _('Error reading audit '
                                            'configuration: %s') % e.strerror)
            return
        self.original_config = copy.deepcopy(self.config)
        self.config_saved = False
        self._refresh_status()
        self._refresh_config_stats()
        self.window.show()
        gtk.main()

    def _save(self):
        '''Update self.config and save it.

        Return True if saved successfully, False otherwise.'''
        if self.config == self.original_config: # See Config.__ne__
            return True
        dlg = SaveDialog(self.window)
        (res, apply_config) = dlg.run(self.config.rules)
        dlg.destroy()
        if not res:
            return False
        try:
            self.config.write()
        except IOError, e:
            util.modal_error_dialog(self.window, _('Error writing audit '
                                                   'configuration: %s') %
                                    e.strerror)
            return False
        self.config_saved = True
        self.original_config = copy.deepcopy(self.config)
        self._refresh_config_stats()
        if apply_config:
            try:
                self.config.apply()
            except IOError, e:
                # e.strerror is usually useless here
                util.modal_error_dialog(self.window, _('Error applying audit '
                                                       'configuration'))
                return True # _Saved_ successfully, even if not applied
        return True

    def _refresh_config_stats(self):
        '''Update configuration statistics.'''
        rules = self.config.rules
        (exit_rules, watch_rules) = exit_watch_rules(rules.exit_rules)
        self.config_watches_label.set_text(str(len(watch_rules)))
        self.config_rules_label.set_text(str(len(rules.task_rules) +
                                             len(rules.entry_rules) +
                                             len(exit_rules)))
        self.config_types_label.set_text(str(len(rules.user_rules) +
                                             len(rules.exclude_rules)))
        if self.config != self.original_config: # See Config.__ne__
            self.config_state.set_text(_('Configuration modified.'))
            self.config_save.set_sensitive(True)
        else:
            if self.config_saved:
                self.config_state.set_text(_('Configuration saved.'))
            else:
                self.config_state.set_text(_('Configuration unchanged.'))
            self.config_save.set_sensitive(False)

    def __menu_quit_activate(self, *unused):
        if self.config != self.original_config: # See Config.__ne__
            dlg = gtk.MessageDialog(self.window, gtk.DIALOG_DESTROY_WITH_PARENT,
                                    gtk.MESSAGE_WARNING, gtk.BUTTONS_NONE,
                                    _('Save changes to the audit configuration '
                                      'before closing?'))
            RESPONSE_DISCARD = 1
            RESPONSE_SAVE = 2
            dlg.add_buttons(_('Close without Saving'), RESPONSE_DISCARD,
                            gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                            gtk.STOCK_SAVE, RESPONSE_SAVE)
            # FIXME: time information
            dlg.format_secondary_text(_("If you don't save, your changes will "
                                        "be discarded."))
            resp = dlg.run()
            dlg.destroy()
            if resp == RESPONSE_SAVE:
                if not self._save():
                    return True # I/O error or canceled, don't close
            elif resp != RESPONSE_DISCARD:
                return True # Don't quit, user canceled or closed the dialog
        gtk.main_quit()
        return False

    def __menu_about_activate(self, *unused):
        dlg = gtk.AboutDialog()
        dlg.set_name(_('Audit Configuration'))
        dlg.set_version(settings.version)
        dlg.set_copyright('Copyright © 2007 Red Hat, Inc.')
        dlg.set_license('''Copyright © 2007 Red Hat, Inc.  All rights reserved.

This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU General
Public License v.2.  This program is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY expressed or implied, including the implied
warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.  You should have received a copy of
the GNU General Public License along with this program; if not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.  Any Red Hat trademarks that are incorporated in the source
code or documentation are not subject to the GNU General Public License and may
only be used or replicated with the express permission of Red Hat, Inc.''')
        dlg.set_authors(('Miloslav Trmač <mitr@redhat.com>',))
        s = _('translator-credits')
        if s != 'translator-credits':
            dlg.set_translator_credits(s)
        dlg.run()
        dlg.destroy()

    def __enabled_change_button_clicked(self, *_):
        if self.enabled_value not in (0, 1):
            return
        try:
            self.client.audit_enable(1 - self.enabled_value)
        except IOError, e:
            util.modal_error_dialog(self.window,
                                    _('Error changing auditing status: %s') %
                                    e.strerror)
        self._refresh_status()

    def __status_refresh_clicked(self, *_):
        self._refresh_status()

    def __config_watches_edit_clicked(self, *_):
        rules = self.config.rules
        (exit_rules, watch_rules) = exit_watch_rules(rules.exit_rules)
        dlg = WatchListDialog(self.window)
        dlg.run(watch_rules)
        dlg.destroy()
        rules.exit_rules = exit_rules + watch_rules
        self._refresh_config_stats()

    def __config_rules_edit_clicked(self, *_):
        rules = self.config.rules
        (exit_rules, watch_rules) = exit_watch_rules(rules.exit_rules)
        dlg = RuleListDialog(self.window)
        dlg.run(rules.task_rules, rules.entry_rules, exit_rules)
        dlg.destroy()
        rules.exit_rules = exit_rules + watch_rules
        self._refresh_config_stats()

    def __config_types_edit_clicked(self, *_):
        dlg = TypeListDialog(self.window)
        dlg.run(self.config)
        dlg.destroy()
        self._refresh_config_stats()

    def __config_global_edit_clicked(self, *_):
        dlg = GlobalDialog(self.window)
        dlg.run(self.config)
        dlg.destroy()
        self._refresh_config_stats()

    def __config_save_clicked(self, *_):
        self._save()
