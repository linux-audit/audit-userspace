/* tty_named_keys.h --
 * Copyright 2008 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Miloslav Trmač <mitr@redhat.com>
 */

E("\x01", "^A")
E("\x02", "^B")
E("\x03", "^C")
E("\x04", "^D")
E("\x05", "^E")
E("\x06", "^F")
E("\x07", "^G")
E("\x08", "^H")
E("\t", "tab")
E("\n", "nl")
E("\x0B", "^K")
E("\x0C", "^L")
E("\r", "ret")
E("\x0E", "^N")
E("\x0F", "^O")
E("\x10", "^P")
E("\x11", "^Q")
E("\x12", "^R")
E("\x13", "^S")
E("\x14", "^T")
E("\x15", "^U")
E("\x16", "^V")
E("\x17", "^W")
E("\x18", "^X")
E("\x19", "^Y")
E("\x1A", "^Z")
/* \x1B handled only after all other escape sequences */
E("\x7F", "backspace")

E("\x1B[A", "up")
E("\x1B[B", "down")
E("\x1B[C", "right")
E("\x1B[D", "left")

E("\x1B""OP", "F1")
E("\x1B""OQ", "F2")
E("\x1B""OR", "F3")
E("\x1B""OS", "F4")
E("\x1B[15~", "F5")
E("\x1B[17~", "F6")
E("\x1B[18~", "F7")
E("\x1B[19~", "F8")
E("\x1B[20~", "F9")
E("\x1B[21~", "F10")
E("\x1B[23~", "F11")
E("\x1B[24~", "F12")

E("\x1B", "esc")
E("\x7F", "backspace")
