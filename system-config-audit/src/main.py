# The main program.
# coding=utf-8
#
# Copyright (C) 2007 Red Hat, Inc.  All rights reserved.
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

import gettext
import gtk.glade
import locale
import os
import sys

from client import Client
from main_window import MainWindow
import settings
import util

_ = gettext.gettext

if __name__ == '__main__':
    locale.setlocale(locale.LC_ALL, '')
    gettext.bindtextdomain(settings.gettext_domain, settings.localedir)
    gettext.bind_textdomain_codeset(settings.gettext_domain, 'utf-8')
    gettext.textdomain(settings.gettext_domain)
    gtk.glade.bindtextdomain(settings.gettext_domain, settings.localedir)
    gtk.glade.textdomain(settings.gettext_domain)

    try:
        cl = Client()
    except OSError, e:
        util.modal_error_dialog(None, _('Error running '
                                        'system-config-audit-server: %s') %
                                e.strerror)
        sys.exit(1)

    w = MainWindow()
    w.run(cl)
