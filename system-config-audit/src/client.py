# A client to the privileged configuration server.
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
from gettext import gettext as _
import errno
import os
import socket
import struct

import server
import settings

__all__ = ('Client')

class Client(object):

    '''A client to the privileged configuration server.'''

    def __init__(self):
        '''Create a server process and initialize the client.

        May raise OSError.  Note that some errors will be detected only when
        using the client.

        '''
        (self.socket, socket2) = socket.socketpair()
        if os.fork() == 0:
            try:
                self.socket.close()
                os.dup2(socket2.fileno(), 0)
                os.execl(settings.server_path, settings.server_path)
            finally:
                os._exit(127)
        socket2.close()

    def read_file(self, file_id):
        '''Return contents of file file_id.

        Raise IOError on error.

        '''
        self.__send_all(struct.pack('=2I', server.REQ_READ_FILE, file_id))
        self.__recv_errno()
        size = self.__recv_int('=Q')
        return self.__recv_all(size)

    def write_file(self, file_id, data):
        '''Replace file file_id by data.

        Raise IOError on error.

        '''
        self.__send_all(struct.pack('=2I', server.REQ_WRITE_FILE, file_id))
        self.__send_all(struct.pack('=Q', len(data)))
        self.__send_all(data)
        self.__recv_errno()

    def apply(self):
        '''Apply the current configuration.

        Raise IOError on error.

        '''
        self.__send_all(struct.pack('=I', server.REQ_APPLY))
        self.__recv_errno()

    def audit_status(self):
        '''Return audit status as a tuple of integers.

        Raise IOError on error.

        '''
        self.__send_all(struct.pack('=I', server.REQ_AUDIT_STATUS))
        self.__recv_errno()
        fmt = '=8I'
        size = struct.calcsize(fmt)
        data = self.__recv_all(size)
        return struct.unpack(fmt, data)

    def audit_enable(self, value):
        '''Modify the "audit enabled" value.

        Raise IOError on error.

        '''
        self.__send_all(struct.pack('=2I', server.REQ_AUDIT_ENABLE, value))
        self.__recv_errno()

    def __recv(self, size):
        '''self.socket.recv(size), but raise IOError instead of socket.error.'''
        try:
            return self.socket.recv(size)
        except socket.error, e:
            raise IOError(e.errno, e.strerror)

    def __recv_all(self, size):
        '''Receive exactly size bytes.

        Raise IOError on error or if enough data is not available.

        '''
        data = self.__recv(size)
        if len(data) != size:
            # Slow path
            fragments = [data]
            left = size - len(data)
            while left != 0:
                data = self.__recv(left)
                if len(data) == 0:
                    raise IOError(errno.ENODATA, _('Not enough data available'))
                fragments.append(data)
                left -= len(data)
            data = ''.join(fragments)
        return data

    def __recv_int(self, fmt):
        '''Receive an integer (defined using fmt for struct).

        Raise IOError on error.

        '''
        size = struct.calcsize(fmt)
        data = self.__recv_all(size)
        return struct.unpack(fmt, data)[0]

    def __recv_errno(self):
        '''Receive an errno value, and if it is non-zero, raise IOError.'''
        err = self.__recv_int('=I')
        if err != 0:
            raise IOError(err, os.strerror(err))

    def __send(self, data):
        '''self.socket.send(data), but raise IOError instead of socket.error.'''
        try:
            return self.socket.send(data)
        except socket.error, e:
            raise IOError(e.errno, e.strerror)

    def __send_all(self, data):
        '''Send all of data.

        Raise IOError (not socket.error) on error.

        '''
        done = self.__send(data)
        if done != len(data):
            # Slow path
            next = done
            while next < len(data):
                done = self.__send(data[next:])
                next += done
