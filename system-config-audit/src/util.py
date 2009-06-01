# Common utilities.
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

import audit
import gtk

import lists

__all__ = ('ParsingError',
           'audit_machine_id',
           'connect_and_run',
           'filetype_string',
           'is_ids_key', 'is_row_separator',
           'key_string',
           'modal_error_dialog', 'msgtype_string',
           'parse_elf', 'parse_filetype', 'parse_ids_key', 'parse_msgtype',
           'parse_syscall', 'parse_unsigned',
           'set_combo_entry_text', 'set_sensitive_all', 'syscall_string',
           'tree_model_delete', 'tree_model_move_down', 'tree_model_move_up',
           'write_new_file')

audit_machine_id = audit.audit_detect_machine()

 # GUI utilities

def connect_and_run(widget, signal, handler):
    '''Setup a signal for widget, and call the handler.'''
    widget.connect(signal, handler)
    handler()

def is_row_separator(model, it):
    '''Returns True if it represents a separator row.'''
    return model.get_value(it, 0) == ''

def modal_error_dialog(parent, msg):
    '''Show a modal error dialog.'''
    dlg = gtk.MessageDialog(parent, gtk.DIALOG_DESTROY_WITH_PARENT,
                            gtk.MESSAGE_ERROR, gtk.BUTTONS_CLOSE, msg)
    dlg.run()
    dlg.destroy()

def set_sensitive_all(sensitive, *widgets):
    '''Set sensitivity of widgets to the specified value.'''
    for w in widgets:
        w.set_sensitive(sensitive)

def set_combo_entry_text(combo, string):
    '''Set combo value to string.

    Assumes the model has a single gobject.TYPE_STRING value.

    '''
    model = combo.get_model()
    it = model.get_iter_first()
    while it is not None:
        if model.get_value(it, 0) == string:
            combo.set_active_iter(it)
            break
        it = model.iter_next(it)
    else:
        combo.set_active(-1)
        combo.child.set_text(string)

def set_combo_option(combo, string):
    '''Set combo value to string.

    If string is not found, unset the value.  Assumes the model has the
    searched string in its first column with type gobject.TYPE_STRING.

    '''
    model = combo.get_model()
    it = model.get_iter_first()
    while it is not None:
        if model.get_value(it, 0) == string:
            combo.set_active_iter(it)
            break
        it = model.iter_next(it)
    else:
        combo.set_active(-1)

def tree_model_delete(selection):
    '''Remove the item selected by selection in a gtk.TreeModel.'''
    (model, it) = selection.get_selected()
    if it is not None:
        # FIXME? confirm
        model.remove(it)

def tree_model_move_down(selection):
    '''Try to move the item selected by selection in a gtk.TreeModel down.'''
    (model, it) = selection.get_selected()
    if it is None:
        return
    it2 = model.iter_next(it)
    if it2 is not None:
        model.move_after(it, it2)

def tree_model_move_up(selection):
    '''Try to move the item selected by selection in a gtk.TreeModel up.'''
    (model, it) = selection.get_selected()
    if it is None:
        return
    path = model.get_path(it)
    if path != model.get_path(model.get_iter_first()):
        # Ugly - but pygtk doesn't seem to support gtk_tree_path_prev()
        model.move_before(it, model.get_iter((path[0] - 1,)))


 # Audit string parsing

class ParsingError(Exception):
    '''An error message reported from a parse_* function.'''
    pass

_machine_to_32bit = { audit.MACH_86_64: audit.MACH_X86,
                      audit.MACH_PPC64: audit.MACH_PPC,
                      audit.MACH_S390X: audit.MACH_S390 }

_machine_bits = { audit.MACH_X86: 32, audit.MACH_86_64: 64,
                  audit.MACH_IA64: 64,
                  audit.MACH_PPC64: 64, audit.MACH_PPC: 32,
                  audit.MACH_S390X: 64, audit.MACH_S390: 32,
                  audit.MACH_ALPHA: 64 }

def parse_elf(string):
    '''Parse an ELF machine type identifier usable for -F arch.

    Return an audit (NOT ELF!) machine ID.  Raise ParsingError on error.

    '''
    try:
        arch = int(string)
        try:
            m = audit.audit_elf_to_machine(arch)
        except OSError:
            raise ParsingError(_('Unknown architecture %d') % arch)
    except ValueError:
        if string.lower() == 'b64':
            # The behavior is asymmetric: b64 can't be used to get a 64-bit
            # machine if a 32-bit machine is detected (IOW, a 64-bit kernel is
            # necessary to make 64-bit system calls possible)
            m = audit_machine_id
            if _machine_bits[m] != 64:
                raise ParsingError(_('64-bit architecture not supported'))
        elif string.lower() == 'b32':
            m = _machine_to_32bit.get(audit_machine_id, audit_machine_id)
            if _machine_bits[m] != 32:
                raise ParsingError(_('32-bit architecture not supported'))
        else:
            try:
                m = audit.audit_name_to_machine(string)
            except OSError:
                raise ParsingError(_('Unknown architecture "%s"') % string)
    return m

def parse_filetype(string):
    '''Parse file type string.

    Return file type ID.  Raise ParsingError on error.

    '''
    try:
        return audit.audit_name_to_ftype(string)
    except OSError:
        raise ParsingError(_('Unknown file type "%s"') % string)

def is_ids_key(s):
    '''Return True if s is in the namespace reserved for IDS keys.'''
    return s.startswith('ids-')

def parse_ids_key(key):
    '''Parse IDS key key.

    Return None on error, or a (type, severity) tuple.

    '''
    if not is_ids_key(key):
        return None
    a = key.split('-')
    if len(a) != 3:
        return None
    assert a[0] == 'ids'
    if a[1] not in (type_ for (type_, label) in lists.ids_types):
        return None
    if a[2] not in (severity for (severity, label) in lists.ids_severities):
        return None
    return (a[1], a[2])

def parse_msgtype(string):
    '''Parse a message type.

    Return a message type ID.  Raise ParsingError on error.

    '''
    try:
        v = int(string)
    except ValueError:
        try:
            v = audit.audit_name_to_msg_type(string)
        except OSError:
            raise ParsingError(_('Unknown message type "%s"') % string)
    return v

def parse_syscall(string, machine_id):
    '''Parse a syscall name for the specified machine.

    Return a syscall number.  Raise ParsingError on error.

    '''
    try:
        sc = audit.audit_name_to_syscall(string, machine_id)
    except OSError:
        try:
            sc = int(string, 10)
        except ValueError:
            raise ParsingError(_('Unknown system call "%s"') % string)
        if sc < 0:
            raise ParsingError(_('System call number must be non-negative'))
    return sc

def parse_unsigned(string):
    '''Parse an unsigned number.

    Return the parsed number.  Raise ParsingError on error.

    '''
    try:
        v = int(string, 10)
    except ValueError:
        raise ParsingError(_('Invalid number "%s"') % string)
    if v < 0:
        raise ParsingError(_('Value must be non-negative'))
    return v

def keys_string(keys):
    '''Return a string representing keys.'''
    return _(', ').join(keys)

def filetype_string(filetype):
    '''Return a string representing filetype.'''
    s = audit.audit_ftype_to_name(filetype)
    assert s is not None
    return s

def msgtype_string(msgtype):
    '''Return a string representing msgtype.'''
    s = audit.audit_msg_type_to_name(msgtype)
    if s is None:
        s = str(msgtype)
    return s

def syscall_string(syscall, machine):
    '''Return a string representing syscall on machine.'''
    s = audit.audit_syscall_to_name(syscall, machine)
    if s is None:
        s = str(syscall)
    return s
