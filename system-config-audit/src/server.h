/* system-config-audit-server protocol

Copyright (C) 2007 Red Hat, Inc.  All rights reserved.
This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU
General Public License v.2.  This program is distributed in the hope that it
will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.  You should have
received a copy of the GNU General Public License along with this program; if
not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
incorporated in the source code or documentation are not subject to the GNU
General Public License and may only be used or replicated with the express
permission of Red Hat, Inc.

Red Hat Author: Miloslav Trmac <mitr@redhat.com> */

#ifndef SERVER_H__
#define SERVER_H__

/* All transferred integers use the host byte order and bit representation. */

/* The server is started with an unix stream domain socket on STDIN_FILENO,
   and waits for requests.  Each request starts with a 32-bit command: */
#define REQ_READ_FILE 1 	/* Read a configuration file */
#define REQ_WRITE_FILE 2	/* Write a configuration file */
#define REQ_APPLY 3		/* Apply the current configuration */
#define REQ_AUDIT_STATUS 4	/* Get current audit status */
#define REQ_AUDIT_ENABLE 5	/* Enable/disable auditing */

/* REQ_READ_FILE:
   The client sends a 32-bit file ID.
   The server replies with a 32-bit errno value (0 for success).
   If errno is 0, the server sends a 64-bit file size, followed by file data.
   (This assumes no failures can occur after sending the errno value, so the
   server needs to read the file to memory.) */

/* REQ_WRITE_FILE:
   The client sends a 32-bit file ID.
   Then the client sends a 64-bit file size, followed by file data.
   The server replies with a 32-bit errno value (0 for success). */

#define FILE_AUDITD_CONF 1
#define FILE_AUDIT_RULES 2

/* REQ_APPLY:
   The server replies with a 32-bit errno value (0 for success). */

/* REQ_AUDIT_STATUS:
   The server sends a 32-bit errno value (0 for success).
   If errno is 0, the server sends a struct audit_status. */

/* REQ_AUDIT_ENABLE:
   The client sends a 32-bit enable value.
   The server replies with a 32-bit errno value (0 for success). */

#endif
