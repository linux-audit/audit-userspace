# Common dialog code.
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
import os

import gtk.glade

import settings

__all__ = ('DialogBase')

class DialogBase(object):

    '''Commmon utilities for dialogs.'''

    def __init__(self, toplevel_name, parent, notebook_name = None):
        '''Create a window from the glade file and get references to widgets.

        If notebook_name is not None, use it in validate_values().  Make the
        window transient for parent.

        '''
        glade_xml = gtk.glade.XML(settings.glade_file_path, toplevel_name)
        for name in self._glade_widget_names:
            w = glade_xml.get_widget(name)
            assert w is not None, 'Widget %s not found in glade file' % name
            setattr(self, name, w)
        # This name is special :)
        self.window = glade_xml.get_widget(toplevel_name)
        if parent is not None:
            self.window.set_transient_for(parent)
        if notebook_name is None:
            self.__notebook_widget = None
        else:
            self.__notebook_widget = glade_xml.get_widget(notebook_name)
            assert self.__notebook_widget is not None

    def destroy(self):
        '''Destroy the dialog.'''
        self.window.destroy()

    def _validate_get_failure(self):
        '''Check whether the window state is a valid configuration.

        Return None if it is valid.  Otherwise, return (message, notebook page
        index or None, widget).

        '''
        raise NotImplementedError()

    def _validate_values(self):
        '''Check whether the dialog state is a valid configuration.

        Return True if it is valid.  Otherwise, display an error message and
        return False.

        '''
        a = self._validate_get_failure()
        if a is None:
            return True
        (msg, page, widget) = a
        if self.__notebook_widget is not None:
            self.__notebook_widget.set_current_page(page)
        self._modal_error_dialog(msg)
        widget.grab_focus()
        return False

    def _modal_error_dialog(self, msg):
        '''Show a modal error dialog.'''
        dlg = gtk.MessageDialog(self.window, gtk.DIALOG_DESTROY_WITH_PARENT,
                                gtk.MESSAGE_ERROR, gtk.BUTTONS_CLOSE, msg)
        dlg.run()
        dlg.destroy()

    def _radio_set(self, value, pairs):
        '''Update the "active" state of several toggle buttons.

        The pairs parameter is a tuple of (widget name, expected value) pairs.
        Expected value is either a single value, or a tuple of possible values.

        '''
        for (name, expected) in pairs:
            if type(expected) == tuple:
                active = value in expected
            else:
                active = value == expected
            getattr(self, name).set_active(active)

    def _radio_get(self, pairs):
        '''Get the "active" button from a group of radio buttons.

        The pairs parameter is a tuple of (widget name, return value) pairs.
        If no widget is active, an assertion will fail.

        '''
        for (name, value) in pairs:
            if getattr(self, name).get_active():
                return value
        assert False, 'No widget is active'

    def _setup_browse_button(self, button, entry, title, action):
        '''Set up a "Browse" button for a path entry.'''
        button.connect('clicked', self.__browse_button_clicked, entry, title,
                       action)

    def __browse_button_clicked(self, unused, entry, title, action):
        if action == gtk.FILE_CHOOSER_ACTION_SAVE:
            stock_accept = gtk.STOCK_SAVE
        else:
            stock_accept = gtk.STOCK_OPEN
        dlg = gtk.FileChooserDialog(title, self.window, action,
                                    (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                     stock_accept, gtk.RESPONSE_ACCEPT))
        path = entry.get_text()
        if action == gtk.FILE_CHOOSER_ACTION_SAVE:
            dlg.set_current_folder(os.path.dirname(path))
            dlg.set_current_name(os.path.basename(path))
        else:
            dlg.set_filename(path)
        r = dlg.run()
        if r == gtk.RESPONSE_ACCEPT:
            entry.set_text(dlg.get_filename())
        dlg.destroy()

