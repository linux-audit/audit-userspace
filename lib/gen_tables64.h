/* gen_tables64.h -- Declarations used for 64-bit lookup tables.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 *      Base on previous work by Miloslav Trmač
 */
#ifndef GEN_TABLES64_H__
#define GEN_TABLES64_H__

#include <stddef.h>
#include <stdint.h>

/* Assumes ASCII; verified in gen_tables.c. */
#define GT_ISUPPER(X) ((X) >= 'A' && (X) <= 'Z')
#define GT_ISLOWER(X) ((X) >= 'a' && (X) <= 'z')

/* 32-bit versions (original) */
inline static int s2i__(const char *strings, const unsigned *s_table,
                       const int *i_table, size_t n, const char *s, int *value);

inline static const char *i2s_direct__(const char *strings,
                                      const unsigned *table, int min, int max,
                                      int v);

inline static const char *i2s_bsearch__(const char *strings,
                                       const int *i_table,
                                       const unsigned *s_table, size_t n,
                                       int v);

/* 64-bit versions */
inline static int s2i_64__(const char *strings, const unsigned *s_table,
		const int64_t *i_table, size_t n, const char *s, int64_t *value)
{
    size_t lo = 0, hi = 0;
    ssize_t left = 0, right = n - 1;

    while (left <= right) {	   /* invariant: left <= x <= right */
        size_t mid, off, i;
        const char *t;
        int r;

        mid = (left + right) / 2;
        /* Skip previously matched prefix */
        off = lo < hi ? lo : hi;
        t = strings + s_table[mid];
        i = off;
        while (s[i] && t[i] && s[i] == t[i])
            i++;
        r = (unsigned char)s[i] - (unsigned char)t[i];
        if (r == 0) {
            *value = i_table[mid];
            return 1;
        }
        if (r < 0) {
            right = mid - 1;
            hi = i;
        } else {
            left = mid + 1;
            lo = i;
        }
    }
    return 0;
}

inline static const char *i2s_64_direct__(const char *strings,
	const unsigned *table, int64_t min, int64_t max, int64_t v)
{
    unsigned off;

    if (v < min || v > max)
        return NULL;
    // Cast to uint64_t to avoid potential overflow in 32-bit index calculation
    uint64_t index = (uint64_t)(v - min);
    if (index > SIZE_MAX) /* Check if the index would overflow size_t */
        return NULL;

    off = table[(size_t)index];
    if (off != -1u)
        return strings + off;
    return NULL;
}

inline static const char *i2s_64_bsearch__(const char *strings,
                                       const int64_t *i_table,
                                       const unsigned *s_table, size_t n,
                                       int64_t v)
{
    ssize_t left, right;

    left = 0;
    right = n - 1;
    while (left <= right) {    /* invariant: left <= x <= right */
        size_t mid;
        int64_t mid_val;

        mid = (left + right) / 2;
        mid_val = i_table[mid];
        if (v == mid_val)
            return strings + s_table[mid];
        if (v < mid_val)
            right = mid - 1;
        else
            left = mid + 1;
    }
    return NULL;
}

struct transtab64 {
    int64_t value;
    unsigned offset;
};

/* Include original 32-bit function implementations */
#include "gen_tables.h"

#endif /* GEN_TABLES64_H__ */
