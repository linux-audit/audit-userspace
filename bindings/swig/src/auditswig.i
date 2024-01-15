/* Author: Dan Walsh
 *
 * Copyright (C) 2005,2006,2009,2023 Red Hat
 * 
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


%module audit
%{
        #include "../lib/audit_logging.h"
// Have to declare these so they can be wrapped later
extern int audit_elf_to_machine(unsigned int elf);
extern const char *audit_machine_to_name(int machine);
extern const char *audit_syscall_to_name(int sc, int machine);
extern int audit_detect_machine(void);
extern const char *audit_msg_type_to_name(int msg_type);
%}

#if defined(SWIGPYTHON)
%exception audit_open {
  $action
  if (result < 0) {
    PyErr_SetFromErrno(PyExc_OSError);
    return NULL;
  }
}
#endif

%define __signed__
signed
%enddef
#define __attribute(X) /*nothing*/
typedef unsigned __u32;
typedef unsigned uid_t;
/* Sidestep SWIG's limitation of handling c99 Flexible arrays by not:
 * generating setters against them: https://github.com/swig/swig/issues/1699
 */
%ignore audit_rule_data::buf;

%include "/usr/include/linux/audit.h"
#define __extension__ /*nothing*/
%include <stdint.i>
%include "../lib/audit-records.h"
%include "../lib/audit_logging.h"

/*
 * These are provided especially for setroubleshooter support
 */
int audit_elf_to_machine(unsigned int elf);
const char *audit_machine_to_name(int machine);
const char *audit_syscall_to_name(int sc, int machine);
int audit_detect_machine(void);
const char *audit_msg_type_to_name(int msg_type);
