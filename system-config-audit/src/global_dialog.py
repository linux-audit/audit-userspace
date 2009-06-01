# Options dialog (handling everything but audit rules).
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
import socket
import stat
import string

import gtk

import auditd_config
import audit_rules
from config import Config
from dialog_base import DialogBase
import util

__all__ = ('GlobalDialog')

# Shorthands, used only for their constants
AC = auditd_config.AuditdConfig
AR = audit_rules.AuditRules

_email_command = '/usr/lib/sendmail'

def _set_optional_text(widget, text):
    '''Update the text (which may be None) in an entry widget.'''
    if text is None:
        text = ''
    widget.set_text(text)


class GlobalDialog(DialogBase):

    '''Global configuration dialog.'''

    _glade_widget_names = ('action_mail_acct', 'admin_space_left',
                           'admin_space_left_email', 'admin_space_left_exe',
                           'admin_space_left_exe_browse',
                           'admin_space_left_exec', 'admin_space_left_halt',
                           'admin_space_left_ignore', 'admin_space_left_single',
                           'admin_space_left_suspend',
                           'admin_space_left_syslog',
                           'backlog_max', 'backlog_max_label1',
                           'backlog_max_label2',
                           'disk_error_exe', 'disk_error_exe_browse',
                           'disk_error_exec', 'disk_error_halt',
                           'disk_error_ignore', 'disk_error_single',
                           'disk_error_suspend', 'disk_error_syslog',
                           'disk_full_exe', 'disk_full_exe_browse',
                           'disk_full_exec', 'disk_full_halt',
                           'disk_full_ignore', 'disk_full_single',
                           'disk_full_suspend', 'disk_full_syslog',
                           'disk_space_label', 'disp_qos_label',
                           'disp_qos_lossless', 'disp_qos_lossless_msg',
                           'disp_qos_lossy', 'dispatcher', 'dispatcher_browse',
                           'dispatcher_enabled', 'dispatcher_label',
                           'flush_incremental', 'flush_incremental_label2',
                           'flush_label', 'flush_none', 'flush_not_sync',
                           'freq',
                           'kernel_fail_ignore', 'kernel_fail_panic',
                           'kernel_fail_syslog',
                           'log_file', 'log_file_browse', 'log_file_label',
                           'log_format_raw',
                           'max_log_file', 'max_log_file_ignore',
                           'max_log_file_keep_logs', 'max_log_file_label',
                           'max_log_file_label2', 'max_log_file_rotate',
                           'max_log_file_rotate_label2', 'max_log_file_suspend',
                           'max_log_file_syslog',
                           'name', 'name_format_fqd', 'name_format_hostname',
                           'name_format_not_none', 'name_format_numeric',
                           'name_format_user', 'num_logs',
                           'priority_boost',
                           'rate_limit', 'rate_limit_enabled',
                           'rate_limit_enabled_label2',
                           'space_left', 'space_left_email', 'space_left_exe',
                           'space_left_exe_browse', 'space_left_exec',
                           'space_left_halt', 'space_left_ignore',
                           'space_left_single', 'space_left_suspend',
                           'space_left_syslog')
    def __init__(self, parent):
        DialogBase.__init__(self, 'global_config', parent,
                            notebook_name = 'global_config_notebook')

        util.connect_and_run(self.rate_limit_enabled, 'toggled',
                             self.__rate_limit_enabled_toggled)

        util.connect_and_run(self.dispatcher_enabled, 'toggled',
                             self.__dispatcher_enabled_toggled)
        self._setup_browse_button(self.dispatcher_browse, self.dispatcher,
                                  _('Program'), gtk.FILE_CHOOSER_ACTION_OPEN)

        util.connect_and_run(self.log_format_raw, 'toggled',
                             self.__log_format_raw_toggled)
        util.connect_and_run(self.log_file, 'focus-out-event',
                             self.__log_file_focus_out)
        self._setup_browse_button(self.log_file_browse, self.log_file,
                                  _('Log File'), gtk.FILE_CHOOSER_ACTION_SAVE)
        util.connect_and_run(self.flush_incremental, 'toggled',
                             self.__flush_incremental_toggled)
        self.freq.connect('value-changed', self.__freq_value_changed)
        util.connect_and_run(self.max_log_file_keep_logs, 'toggled',
                             self.__max_log_file_keep_logs_toggled)
        util.connect_and_run(self.max_log_file_rotate, 'toggled',
                             self.__max_log_file_rotate_toggled)
        util.connect_and_run(self.name_format_not_none, 'toggled',
                             self.__name_format_not_none_toggled)
        hostname = socket.gethostname()
        # TRANSLATORS: This is one of the options on the "Log File" tab of the
        # "Settings" dialog.  It directs auditd to store the system host name
        # (the parameter replaced by %s) without any modification.
        self.name_format_hostname.set_label(_('Host name as-_is (%s)')
                                            % hostname)
        try:
            # AI_PASSIVE is probably not necessary, but that's what auditd uses.
            addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM, 0,
                                       socket.AI_ADDRCONFIG |
                                       socket.AI_CANONNAME | socket.AI_PASSIVE)
        except socket.gaierror:
            addrs = ()
        if addrs:
            fqd_label = _('_Fully-qualified host name (%s)') % addrs[0][3]
            numeric_label = _('I_P address (%s)') % addrs[0][4][0]
        else:
            fqd_label = _('_Fully-qualified host name')
            numeric_label = _('I_P address')
        self.name_format_fqd.set_label(fqd_label)
        self.name_format_numeric.set_label(numeric_label)
        util.connect_and_run(self.name_format_user, 'toggled',
                             self.__name_format_user_toggled)

        util.connect_and_run(self.space_left_exec, 'toggled',
                             self.__space_left_exec_toggled)
        self._setup_browse_button(self.space_left_exe_browse,
                                  self.space_left_exe, _('Program'),
                                  gtk.FILE_CHOOSER_ACTION_OPEN)
        util.connect_and_run(self.admin_space_left_exec, 'toggled',
                             self.__admin_space_left_exec_toggled)
        self._setup_browse_button(self.admin_space_left_exe_browse,
                                  self.admin_space_left_exe, _('Program'),
                                  gtk.FILE_CHOOSER_ACTION_OPEN)

        util.connect_and_run(self.disk_full_exec, 'toggled',
                             self.__disk_full_exec_toggled)
        self._setup_browse_button(self.disk_full_exe_browse, self.disk_full_exe,
                                  _('Program'), gtk.FILE_CHOOSER_ACTION_OPEN)
        util.connect_and_run(self.disk_error_exec, 'toggled',
                             self.__disk_error_exec_toggled)
        self._setup_browse_button(self.disk_error_exe_browse,
                                  self.disk_error_exe, _('Program'),
                                  gtk.FILE_CHOOSER_ACTION_OPEN)

    def run(self, config):
        '''Show the dialog to modify config.'''
        self._load_config(config)
        res = self.window.run()
        while res == gtk.RESPONSE_OK and not self._validate_values():
            res = self.window.run()
        if res == gtk.RESPONSE_OK:
            self._save_config(config)

    __admin_space_left_map = (('admin_space_left_ignore', AC.FAILURE_IGNORE),
                              ('admin_space_left_syslog', AC.FAILURE_SYSLOG),
                              ('admin_space_left_email', AC.FAILURE_EMAIL),
                              ('admin_space_left_exec', AC.FAILURE_EXEC),
                              ('admin_space_left_suspend', AC.FAILURE_SUSPEND),
                              ('admin_space_left_single', AC.FAILURE_SINGLE),
                              ('admin_space_left_halt', AC.FAILURE_HALT))
    __disk_full_map = (('disk_full_ignore', AC.FAILURE_IGNORE),
                       ('disk_full_syslog', AC.FAILURE_SYSLOG),
                       ('disk_full_exec', AC.FAILURE_EXEC),
                       ('disk_full_suspend', AC.FAILURE_SUSPEND),
                       ('disk_full_single', AC.FAILURE_SINGLE),
                       ('disk_full_halt', AC.FAILURE_HALT))
    __disk_error_map = (('disk_error_ignore', AC.FAILURE_IGNORE),
                        ('disk_error_syslog', AC.FAILURE_SYSLOG),
                        ('disk_error_exec', AC.FAILURE_EXEC),
                        ('disk_error_suspend', AC.FAILURE_SUSPEND),
                        ('disk_error_single', AC.FAILURE_SINGLE),
                        ('disk_error_halt', AC.FAILURE_HALT))
    __kernel_fail_map = (('kernel_fail_ignore', AR.FAILURE_SILENT),
                         ('kernel_fail_syslog', AR.FAILURE_PRINTK),
                         ('kernel_fail_panic', AR.FAILURE_PANIC))
    __name_format_map = (('name_format_hostname', AC.NAME_HOSTNAME),
                         ('name_format_fqd', AC.NAME_FQD),
                         ('name_format_numeric', AC.NAME_NUMERIC),
                         ('name_format_user', AC.NAME_USER))
    __space_left_map = (('space_left_ignore', AC.FAILURE_IGNORE),
                        ('space_left_syslog', AC.FAILURE_SYSLOG),
                        ('space_left_email', AC.FAILURE_EMAIL),
                        ('space_left_exec', AC.FAILURE_EXEC),
                        ('space_left_suspend', AC.FAILURE_SUSPEND),
                        ('space_left_single', AC.FAILURE_SINGLE),
                        ('space_left_halt', AC.FAILURE_HALT))
    __disp_qos_map = (('disp_qos_lossy', AC.QOS_LOSSY),
                      ('disp_qos_lossless', AC.QOS_LOSSLESS))
    __max_log_file_map = (('max_log_file_ignore', AC.SIZE_IGNORE),
                          ('max_log_file_syslog', AC.SIZE_SYSLOG),
                          ('max_log_file_suspend', AC.SIZE_SUSPEND),
                          ('max_log_file_keep_logs',
                           (AC.SIZE_KEEP_LOGS, AC.SIZE_ROTATE)))
    def _load_config(self, config):
        '''Modify dialog controls to reflect config.'''
        auditd = config.auditd
        rules = config.rules

        self.backlog_max.set_value(rules.backlog_limit)
        self.rate_limit_enabled.set_active(rules.rate_limit !=
                                           AR.RATE_LIMIT_DISABLED)
        self.rate_limit.set_value(rules.rate_limit)
        self._radio_set(rules.failure_handling, self.__kernel_fail_map)

        self.priority_boost.set_value(auditd.priority_boost)
        self.action_mail_acct.set_text(auditd.action_mail_acct)
        self.dispatcher_enabled.set_active(auditd.dispatcher is not None)
        _set_optional_text(self.dispatcher, auditd.dispatcher)
        self._radio_set(auditd.disp_qos, self.__disp_qos_map)

        self.log_format_raw.set_active(auditd.log_format == AC.FORMAT_RAW)
        self.log_file.set_text(auditd.log_file)
        self.__log_file_changed()
        self.flush_none.set_active(auditd.flush == AC.FLUSH_NONE)
        self.flush_incremental.set_active(auditd.flush != AC.FLUSH_NONE)
        if auditd.flush == AC.FLUSH_INCREMENTAL:
            freq = auditd.freq
        else:
            freq = 1
        self.freq.set_value(freq)
        self.flush_not_sync.set_active(auditd.flush == AC.FLUSH_DATA)
        self.max_log_file.set_value(auditd.max_log_file)
        self._radio_set(auditd.max_log_file_action, self.__max_log_file_map)
        self.max_log_file_rotate.set_active(auditd.max_log_file_action ==
                                            AC.SIZE_ROTATE)
        self.num_logs.set_value(auditd.num_logs)
        self.name_format_not_none.set_active(auditd.name_format != AC.NAME_NONE)
        self._radio_set(auditd.name_format, self.__name_format_map)
        _set_optional_text(self.name, auditd.name)

        self.space_left.set_value(auditd.space_left)
        self._radio_set(auditd.space_left_action, self.__space_left_map)
        _set_optional_text(self.space_left_exe, auditd.space_left_exe)
        self.admin_space_left.set_value(auditd.admin_space_left)
        self._radio_set(auditd.admin_space_left_action,
                        self.__admin_space_left_map)
        _set_optional_text(self.admin_space_left_exe,
                           auditd.admin_space_left_exe)

        self._radio_set(auditd.disk_full_action, self.__disk_full_map)
        _set_optional_text(self.disk_full_exe, auditd.disk_full_exe)
        self._radio_set(auditd.disk_error_action, self.__disk_error_map)
        _set_optional_text(self.disk_error_exe, auditd.disk_error_exe)

    def _save_config(self, config):
        '''Modify config to reflect dialog state.'''
        def exe_value(action, entry):
            '''Return the value for *_exe, depending on action and an text entry
            widget.'''
            if action != AC.FAILURE_EXEC:
                return None
            else:
                return entry.get_text()
        auditd = config.auditd
        auditd.action_mail_acct = self.action_mail_acct.get_text()
        auditd.admin_space_left = self.admin_space_left.get_value_as_int()
        auditd.admin_space_left_action = self._radio_get(self.
                                                         __admin_space_left_map)
        auditd.admin_space_left_exe = exe_value(auditd.admin_space_left_action,
                                                self.admin_space_left_exe)
        auditd.disk_error_action = self._radio_get(self.__disk_error_map)
        auditd.disk_error_exe = exe_value(auditd.disk_error_action,
                                          self.disk_error_exe)
        auditd.disk_full_action = self._radio_get(self.__disk_full_map)
        auditd.disk_full_exe = exe_value(auditd.disk_full_action,
                                         self.disk_full_exe)
        auditd.disp_qos = self._radio_get(self.__disp_qos_map)
        if self.dispatcher_enabled.get_active():
            auditd.dispatcher = self.dispatcher.get_text()
        else:
            auditd.dispatcher = None
        if self.flush_none.get_active():
            auditd.flush = AC.FLUSH_NONE
        elif self.freq.get_value_as_int() != 1:
            auditd.flush = AC.FLUSH_INCREMENTAL
        elif self.flush_not_sync.get_active():
            auditd.flush = AC.FLUSH_DATA
        else:
            auditd.flush = AC.FLUSH_SYNC
        if auditd.flush == AC.FLUSH_INCREMENTAL:
            auditd.freq = self.freq.get_value_as_int()
        else:
            auditd.freq = 0
        auditd.log_file = self.log_file.get_text()
        if self.log_format_raw.get_active():
            auditd.log_format = AC.FORMAT_RAW
        else:
            auditd.log_format = AC.FORMAT_NOLOG
        auditd.max_log_file = self.max_log_file.get_value_as_int()
        auditd.max_log_file_action = self._radio_get(self.__max_log_file_map)
        if type(auditd.max_log_file_action) == tuple:
            if self.max_log_file_rotate.get_active():
                auditd.max_log_file_action = AC.SIZE_ROTATE
            else:
                auditd.max_log_file_action = AC.SIZE_KEEP_LOGS
        if self.name_format_not_none.get_active():
            auditd.name_format = self._radio_get(self.__name_format_map)
        else:
            auditd.name_format = AC.NAME_NONE
        if auditd.name_format == AC.NAME_USER:
            auditd.name = self.name.get_text()
        else:
            auditd.name = None
        auditd.num_logs = self.num_logs.get_value_as_int()
        auditd.priority_boost = self.priority_boost.get_value_as_int()
        auditd.space_left = self.space_left.get_value_as_int()
        auditd.space_left_action = self._radio_get(self.__space_left_map)
        auditd.space_left_exe = exe_value(auditd.space_left_action,
                                          self.space_left_exe)

        rules = config.rules
        rules.backlog_limit = self.backlog_max.get_value_as_int()
        rules.failure_handling = self._radio_get(self.__kernel_fail_map)
        if self.rate_limit_enabled.get_active():
            rules.rate_limit = self.rate_limit.get_value_as_int()
        else:
            rules.rate_limit = AR.RATE_LIMIT_DISABLED

    def _validate_get_failure(self):
        # Validate single values first
	msg = self.__validate_action_mail_acct(self.action_mail_acct.get_text())
        if msg:
            return (msg, 1, self.action_mail_acct)
	if self.dispatcher_enabled.get_active():
            msg = self.__validate_dispatcher(self.dispatcher.get_text())
            if msg:
                return (msg, 1, self.dispatcher)

	if self.log_format_raw.get_active():
            msg = self.__validate_log_file(self.log_file.get_text())
            if msg:
                return (msg, 2, self.log_file)
            if (self.name_format_not_none.get_active() and
                self.name_format_user.get_active()):
                msg = self.__validate_name(self.name.get_text())
                if msg:
                    return (msg, 2, self.name)

	if self.space_left_email.get_active():
            msg = self.__validate_email_use()
            if msg:
                return (msg, 3, self.space_left_email)
        if self.space_left_exec.get_active():
            msg = self.__validate_exe(self.space_left_exe.get_text())
            if msg:
                return (msg, 3, self.space_left_exe)
	if self.admin_space_left_email.get_active():
            msg = self.__validate_email_use()
            if msg:
                return (msg, 3, self.admin_space_left_email)
        if self.admin_space_left_exec.get_active():
            msg = self.__validate_exe(self.admin_space_left_exe.get_text())
            if msg:
                return (msg, 3, self.admin_space_left_exe)

        if self.disk_full_exec.get_active():
            msg = self.__validate_exe(self.disk_full_exe.get_text())
            if msg:
                return (msg, 4, self.disk_full_exe)
        if self.disk_error_exec.get_active():
            msg = self.__validate_exe(self.disk_error_exe.get_text())
            if msg:
                return (msg, 4, self.disk_error_exe)

        # Now verify the configuration is consistent
        if (self.space_left.get_value_as_int() <=
            self.admin_space_left.get_value_as_int()):
            return (_('First threshold must be larger than second threshold'),
                    3, self.space_left)
        return None

    @staticmethod
    def __validate_action_mail_acct(email):
        '''Validate the "action_mail_acct" setting.

        Return an error message, or None if no error is detected.

        '''
        if len(email) < 2:
            return _('"%s" is too short') % email
        for c in email:
            if (c not in string.ascii_letters and c not in string.digits and
                c not in '@.-_'):
                return (_('"%(email)s" contains an invalid character "%(char)c"') %
                        {'email': email, 'char': c})
        i = email.find('@')
        if i != -1 and email.find('.', i) == -1:
            return _('The domain in "%s" is not fully qualified') % email
        # FIXME? gethostbyname check omitted
        return None

    @staticmethod
    def __validate_dispatcher(path):
        '''Validate the "dispatcher" setting.

        Return an error message, or None if no error is detected.

        '''
        try:
            st = os.stat(path)
        except OSError, e:
            return (_('Error getting attributes of "%(path)s": %(msg)s') %
                    {'path': path, 'msg': e.strerror})
        if not stat.S_ISREG(st.st_mode):
            return _('"%s" is not a regular file') % path
        if st.st_uid != 0:
            return _('"%s" is not owned by root') % path
        if ((st.st_mode & (stat.S_IRWXU | stat.S_IRWXG)) !=
            (stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)):
            return _('Permissions of "%s" should be 075x') % path
        if (st.st_mode & stat.S_IWOTH) != 0:
            return _('"%s" should not be writable by other users') % path
        return None

    @staticmethod
    def __validate_log_file(path):
        '''Validate the "log_file" setting.

        Return an error message, or None if no error is detected.

        '''
        dirname = os.path.dirname(path)
        if not os.path.isdir(dirname):
            return _('"%s" is not an existing directory') % dirname
        try:
            st = os.stat(path)
        except OSError:
            pass
        else:
            if not stat.S_ISREG(st.st_mode):
                return _('"%s" is not a regular file') % path
            if st.st_uid != 0:
                return _('"%s" is not owned by root') % path
            if ((st.st_mode & (stat.S_IWUSR | stat.S_IXUSR | stat.S_IWGRP |
                               stat.S_IXGRP | stat.S_IRWXO)) != stat.S_IWUSR):
                return _('Permissions of "%s" should be 0600 or 0640') % path
        return None

    @staticmethod
    def __validate_name(name):
        '''Validate the "name" setting.

        Return an error message, or None if no error is detected.

        '''
        if name == '':
            return _('The host name may not be empty')
        return None

    @staticmethod
    def __validate_exe(path):
        '''Validate an "*_exe" setting.

        Return an error message, or None if no error is detected.

        '''
        if not path.startswith('/'):
            return _('"%s" is not an absolute path') % path
        try:
            st = os.stat(path)
        except OSError, e:
            return (_('Error getting attributes of "%(path)s": %(msg)s') %
                    {'path': path, 'msg': e.strerror})
        if not stat.S_ISREG(st.st_mode):
            return _('"%s" is not a regular file') % path
        if st.st_uid != 0:
            return _('"%s" is not owned by root') % path
        if ((st.st_mode & (stat.S_IRWXU | stat.S_IRWXG)) !=
            (stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)):
            return _('Permissions of "%s" should be 075x') % path
        if (st.st_mode & stat.S_IWOTH) != 0:
            return _('"%s" should not be writable by other users') % path
        return None

    @staticmethod
    def __validate_email_use():
        '''Validate AC.FAILURE_EMAIL can be used.

        Return an error message, or None if no error is detected.

        '''
        if os.access(_email_command, os.X_OK):
            return (_('Email requested but %s is not executable') %
                    _email_command)
        return None

    def __rate_limit_enabled_toggled(self, *_):
        self.rate_limit.set_sensitive(self.rate_limit_enabled.get_active())

    def __dispatcher_enabled_toggled(self, *_):
        util.set_sensitive_all(self.dispatcher_enabled.get_active(),
                               self.dispatcher_label, self.dispatcher,
                               self.dispatcher_browse, self.disp_qos_label,
                               self.disp_qos_lossy, self.disp_qos_lossless,
                               self.disp_qos_lossless_msg)

    def __log_format_raw_toggled(self, *_):
        util.set_sensitive_all(self.log_format_raw.get_active(),
                               self.log_file_label, self.log_file,
                               self.log_file_browse, self.flush_label,
                               self.flush_none, self.flush_incremental,
                               # self.freq excluded
                               self.flush_incremental_label2,
                               # self.flush_not_sync excluded
                               self.max_log_file_label, self.max_log_file,
                               self.max_log_file_label2,
                               self.max_log_file_ignore,
                               self.max_log_file_syslog,
                               self.max_log_file_suspend,
                               self.max_log_file_keep_logs,
                               # self.max_log_file_rotate, self.num_logs,
                               # self.max_log_file_rotate_label2 excluded
                               )
        # Handles self.freq, self.flush_not_sync
        self.__flush_incremental_toggled()
        # Handles self.max_log_file_rotate, self.num_logs,
        # self.max_log_file_rotate_label2
        self.__max_log_file_keep_logs_toggled()

    def __log_file_focus_out(self, *_):
        self.__log_file_changed()
        return False

    def __log_file_changed(self):
        path = self.log_file.get_text()
        if path:
            while not os.path.ismount(path):
                p = os.path.dirname(path)
                if path == p:
                    break;
                path = p
            self.disk_space_label.set_text(_('The low disk space thresholds '
                                             'apply to the partition which '
                                             'contains the log file (%s).') %
                                           path)
        else:
            self.disk_space_label.set_text(_('The low disk space thresholds '
                                             'apply to the partition which '
                                             'contains the log file.'))

    def __flush_incremental_toggled(self, *_):
        util.set_sensitive_all(self.log_format_raw.get_active() and
                               self.flush_incremental.get_active(),
                               self.freq, # self.flush_not_sync excluded
                               )
        # Handles self.flush_not_sync
        self.__freq_value_changed()

    def __freq_value_changed(self, *_):
        self.flush_not_sync.set_sensitive(self.log_format_raw.get_active() and
                                          self.flush_incremental.
                                          get_active() and
                                          self.freq.get_value_as_int() == 1)

    def __max_log_file_keep_logs_toggled(self, *_):
        util.set_sensitive_all(self.log_format_raw.get_active() and
                               self.max_log_file_keep_logs.get_active(),
                               self.max_log_file_rotate,
                               # self.num_logs excluded
                               self.max_log_file_rotate_label2)
        # Handles self.num_logs
        self.__max_log_file_rotate_toggled()

    def __max_log_file_rotate_toggled(self, *_):
        val = (self.log_format_raw.get_active() and
               self.max_log_file_keep_logs.get_active() and
               self.max_log_file_rotate.get_active())
        self.num_logs.set_sensitive(val)

    def __name_format_not_none_toggled(self, *_):
        util.set_sensitive_all(self.log_format_raw.get_active() and
                               self.name_format_not_none.get_active(),
                               self.name_format_hostname, self.name_format_fqd,
                               self.name_format_numeric,
                               self.name_format_user, # self.name excluded
                               )
        # Handles self.name
        self.__name_format_user_toggled()

    def __name_format_user_toggled(self, *_):
        val = (self.log_format_raw.get_active() and
               self.name_format_not_none.get_active() and
               self.name_format_user.get_active())
        self.name.set_sensitive(val)

    def __disk_full_exec_toggled(self, *_):
        util.set_sensitive_all(self.disk_full_exec.get_active(),
                               self.disk_full_exe, self.disk_full_exe_browse)

    def __disk_error_exec_toggled(self, *_):
        util.set_sensitive_all(self.disk_error_exec.get_active(),
                               self.disk_error_exe, self.disk_error_exe_browse)

    def __space_left_exec_toggled(self, *_):
        util.set_sensitive_all(self.space_left_exec.get_active(),
                               self.space_left_exe, self.space_left_exe_browse)

    def __admin_space_left_exec_toggled(self, *_):
        util.set_sensitive_all(self.admin_space_left_exec.get_active(),
                               self.admin_space_left_exe,
                               self.admin_space_left_exe_browse)
