/* auplugin.h --
 * Copyright 2025 Red Hat Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; see the file COPYING. If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA 02110-1335, USA.
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

#ifndef _AUPLUGIN_H_
#define _AUPLUGIN_H_

#include <stddef.h>

#ifndef __attr_access
# define __attr_access(x)
#endif
#ifndef __attr_dealloc
# define __attr_dealloc(x, y)
#endif
#ifndef __attribute_malloc__
# define __attribute_malloc__
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct auplugin_fgets_state auplugin_fgets_state_t;

enum auplugin_mem {
	MEM_MALLOC,
	MEM_MMAP,
	MEM_SELF_MANAGED
};

void auplugin_fgets_clear(void);
int auplugin_fgets_eof(void);
int auplugin_fgets_more(size_t blen);
int auplugin_fgets(char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 1, 2));
int auplugin_setvbuf(void *buf, size_t buff_size, enum auplugin_mem how)
	__attr_access ((__read_only__, 1, 2));

void auplugin_fgets_destroy(auplugin_fgets_state_t *st);
auplugin_fgets_state_t *auplugin_fgets_init(void)
	__attribute_malloc__ __attr_dealloc (auplugin_fgets_destroy, 1);
void auplugin_fgets_clear_r(auplugin_fgets_state_t *st);
int auplugin_fgets_eof_r(auplugin_fgets_state_t *st);
int auplugin_fgets_more_r(auplugin_fgets_state_t *st, size_t blen);
int auplugin_fgets_r(auplugin_fgets_state_t *st, char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 2, 3));
int auplugin_setvbuf_r(auplugin_fgets_state_t *st, void *buf, size_t buff_size,
			enum auplugin_mem how)
			__attr_access ((__read_only__, 2, 3));

#ifdef __cplusplus
}
#endif

#endif

