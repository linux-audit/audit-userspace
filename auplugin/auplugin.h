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
#include <libaudit.h>
#include <auparse.h>

#ifndef __attr_access
# define __attr_access(x)
#endif
#ifndef __attr_dealloc
# define __attr_dealloc(x, y)
#endif
#ifndef __attribute_malloc__
# define __attribute_malloc__
#endif
#ifndef __wur
# define __wur
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_AUDIT_EVENT_FRAME_SIZE (sizeof(struct audit_dispatcher_header) + MAX_AUDIT_MESSAGE_LENGTH)

typedef struct auplugin_fgets_state auplugin_fgets_state_t;

enum auplugin_mem {
	MEM_SELF_MANAGED,
	MEM_MALLOC,
	MEM_MMAP,
	MEM_MMAP_FILE
};

enum {
       AUPLUGIN_Q_IN_MEMORY = 1 << 0,
       AUPLUGIN_Q_IN_FILE   = 1 << 1,
       AUPLUGIN_Q_CREAT     = 1 << 2,
       AUPLUGIN_Q_EXCL      = 1 << 3,
       AUPLUGIN_Q_SYNC      = 1 << 4,
       AUPLUGIN_Q_RESIZE    = 1 << 5,
};

/* Callback prototypes */
typedef void (*auplugin_callback_ptr)(const char *record);
typedef void (*auplugin_timer_callback_ptr)(unsigned int interval);
typedef void (*auplugin_stats_callback_ptr)(unsigned int depth,
					    unsigned int max_depth,
					    int overflow);

/* fgets family of functions prototypes */
void auplugin_fgets_clear(void);
int auplugin_fgets_eof(void);
int auplugin_fgets_more(size_t blen);
int auplugin_fgets(char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 1, 2)) __wur;
int auplugin_setvbuf(void *buf, size_t buff_size, enum auplugin_mem how)
	__attr_access ((__read_only__, 1, 2));

void auplugin_fgets_destroy(auplugin_fgets_state_t *st);
auplugin_fgets_state_t *auplugin_fgets_init(void)
	__attribute_malloc__ __attr_dealloc (auplugin_fgets_destroy, 1);
void auplugin_fgets_clear_r(auplugin_fgets_state_t *st);
int auplugin_fgets_eof_r(auplugin_fgets_state_t *st);
int auplugin_fgets_more_r(auplugin_fgets_state_t *st, size_t blen);
int auplugin_fgets_r(auplugin_fgets_state_t *st, char *buf, size_t blen, int fd)
	__attr_access ((__write_only__, 2, 3)) __wur;
int auplugin_setvbuf_r(auplugin_fgets_state_t *st, void *buf, size_t buff_size,
			enum auplugin_mem how)
			__attr_access ((__read_only__, 2, 3));

/* auplugin family of functions prototypes */
int auplugin_init(int inbound_fd, unsigned queue_size, int q_flags,
		  const char *path) __wur;
void auplugin_stop(void);
void auplugin_event_loop(auplugin_callback_ptr callback);
int auplugin_event_feed(auparse_callback_ptr callback,
			unsigned int timer_interval,
			auplugin_timer_callback_ptr timer_cb);
void auplugin_register_stats_callback(auplugin_stats_callback_ptr cb);
void auplugin_report_stats(void);
unsigned int auplugin_queue_depth(void);
unsigned int auplugin_queue_max_depth(void);
int auplugin_queue_overflow(void);

#ifdef __cplusplus
}
#endif

#endif

