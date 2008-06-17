# Configuration save dialog.
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
import gtk

from dialog_base import DialogBase

__all__ = ('SaveDialog')

class SaveDialog(DialogBase):

    '''Configuration save dialog.'''

    _glade_widget_names = ('save_apply', 'save_config_locked')
    def __init__(self, parent):
        DialogBase.__init__(self, 'save_dialog', parent)

    def run(self, rules):
        '''Show the dialog, modify rules.audit_enabled.

        Return (saving confirmed, apply changes).

        '''
        self.save_config_locked.set_active(rules.audit_enabled ==
                                           rules.AUDIT_LOCKED)
        self.save_apply.set_active(True)
        res = self.window.run() == gtk.RESPONSE_OK
        if res:
            if self.save_config_locked.get_active():
                rules.audit_enabled = rules.AUDIT_LOCKED
            else:
                rules.audit_enabled = rules.AUDIT_ENABLED
            apply_config = self.save_apply.get_active()
        else:
            apply_config = False
        return (res, apply_config)
