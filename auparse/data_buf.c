/* data_buf.c --
 * Copyright 2007,2011 Red Hat Inc., Durham, North Carolina.
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
 *      John Dennis <jdennis@redhat.com>
 */

/*
 * gcc -DTEST -g data_buf.c -o data_buf
 * gcc -DTEST -g data_buf.c -o data_buf && valgrind --leak-check=yes ./data_buf
 */

/*****************************************************************************/
/******************************** Documentation ******************************/
/*****************************************************************************/

/*****************************************************************************/
/******************************* Include Files *******************************/
/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>
#include "data_buf.h"

/*****************************************************************************/
/****************************** Internal Defines *****************************/
/*****************************************************************************/

#ifndef MIN
#define MIN(a,b) (((a)<=(b))?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) (((a)>=(b))?(a):(b))
#endif

//#define DEBUG 1

#ifdef DEBUG
#define DATABUF_VALIDATE(db)                            \
{                                                       \
    if (db->alloc_ptr == NULL || db->alloc_size == 0) { \
        assert(db->alloc_ptr == NULL);                  \
        assert(db->alloc_size == 0);                    \
        assert(db->len == 0);                           \
    } else {                                            \
        assert(db->offset         <= db->alloc_size);   \
        assert(db->len            <= db->alloc_size);   \
        assert(db->offset+db->len <= db->alloc_size);   \
    }                                                   \
}
#else
#define DATABUF_VALIDATE(db)
#endif

/*****************************************************************************/
/************************** Internal Type Definitions ************************/
/*****************************************************************************/

/*****************************************************************************/
/**********************  External Function Declarations  *********************/
/*****************************************************************************/

/*****************************************************************************/
/**********************  Internal Function Declarations  *********************/
/*****************************************************************************/

static int databuf_shift_data_to_beginning(DataBuf *db);

/*****************************************************************************/
/*************************  External Global Variables  ***********************/
/*****************************************************************************/

/*****************************************************************************/
/*************************  Internal Global Variables  ***********************/
/*****************************************************************************/

static int debug = 0;

/*****************************************************************************/
/****************************  Inline Functions  *****************************/
/*****************************************************************************/

/*****************************************************************************/
/***************************  Internal Functions  ****************************/
/*****************************************************************************/

static int databuf_shift_data_to_beginning(DataBuf *db)
{
    DATABUF_VALIDATE(db);
    if (db->flags & DATABUF_FLAG_PRESERVE_HEAD) return -1;
    if (databuf_beg(db) == NULL) return 1;
    if (db->offset) {
        memmove(db->alloc_ptr, databuf_beg(db), db->len);
        db->offset = 0;
    }
    DATABUF_VALIDATE(db);
    return 1;
}

/*****************************************************************************/
/****************************  Exported Functions  ***************************/
/*****************************************************************************/

void databuf_print(DataBuf *db, int print_data, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (fmt) {
        vprintf(fmt, ap);
    }
    printf("%salloc_size=%zu alloc_ptr=%p offset=%zu beg=%p len=%zu max_len=%zu flags=[",
           fmt?" ":"", db->alloc_size, db->alloc_ptr, db->offset, databuf_beg(db), db->len, db->max_len);

    if (db->flags & DATABUF_FLAG_PRESERVE_HEAD) printf("PRESERVE_HEAD ");
    if (db->flags & DATABUF_FLAG_STRING)        printf("STRING ");
    printf("]");
    
    if (print_data) {
        printf(" [");
        fwrite(databuf_beg(db), 1, db->len, stdout);
        printf("]");
    }
    printf("\n");
    va_end(ap);
}

int databuf_init(DataBuf *db, size_t size, unsigned flags)
{
    db->alloc_ptr  = NULL;
    db->alloc_size = 0;
    db->offset     = 0;
    db->len        = 0;
    db->max_len    = 0;
    db->flags      = flags;

    if (size) {
        if ((db->alloc_ptr = malloc(size))) {
            db->alloc_size = size;
            return 1;
        } else {
            return -1;
        }
    }

    // For strings intialize with initial NULL terminator
    if (flags & DATABUF_FLAG_STRING) databuf_strcat(db, "");

    return 1;
}

void databuf_free(DataBuf *db)
{
    DATABUF_VALIDATE(db);

    if (db->alloc_ptr != NULL) {
        free(db->alloc_ptr);
    }

    db->alloc_ptr  = NULL;
    db->alloc_size = 0;
    db->offset     = 0;
    db->len        = 0;
    db->max_len    = 0;

    DATABUF_VALIDATE(db);
}

char *databuf_export(DataBuf *db)
{
    DATABUF_VALIDATE(db);
    databuf_shift_data_to_beginning(db);
    DATABUF_VALIDATE(db);
    return db->alloc_ptr;
}

int databuf_append(DataBuf *db, const char *src, size_t src_size)
{
    size_t new_size;

    DATABUF_VALIDATE(db);

    if (src == NULL || src_size == 0) return 0;

    new_size = db->len+src_size;

    if (debug) databuf_print(db, 1, "databuf_append() size=%d", src_size);
    if ((new_size > db->alloc_size) ||
        ((db->flags & DATABUF_FLAG_PRESERVE_HEAD) && !databuf_tail_available(db, src_size))) {
        /* not enough room, we must realloc */
        void *new_alloc;
        
        databuf_shift_data_to_beginning(db);
        if ((new_alloc = realloc(db->alloc_ptr, new_size))) {
            db->alloc_ptr  = new_alloc;
            db->alloc_size = new_size;
        } else {
            return -1;           /* realloc failed */
        }
    } else {
        /* we can fit within current allocation, but can we append? */
        if (!databuf_tail_available(db, src_size)) {
            /* we can't append in place, must create room at tail by shifting
               data forward to the beginning of the  allocation block */
            databuf_shift_data_to_beginning(db);
        }
    }
    if (debug) databuf_print(db, 1, "databuf_append() about to memmove()");
    /* pointers all set up and room availble, move the data and update */
    memmove(databuf_end(db), src, src_size);
    db->len = new_size;
    db->max_len = MAX(db->max_len, new_size);
    if (debug) databuf_print(db, 1, "databuf_append() conclusion");
    DATABUF_VALIDATE(db);
    return 1;
}

int databuf_strcat(DataBuf *db, const char *str)
{
    size_t str_len;

    DATABUF_VALIDATE(db);

    if (str == NULL) return 0;

    // +1 so the data append also copies the NULL terminator
    str_len = strlen(str) + 1;

    // If there is a NULL terminator exclude it so the subsequent
    // data append produces a proper string concatenation
    if (db->len > 0) {
        char *last_char = databuf_end(db) - 1;
        if (*last_char == 0) {
            db->len--;          // backup over NULL terminator
        }
    }

    // Copy string and NULL terminator
    databuf_append(db, str, str_len);

    DATABUF_VALIDATE(db);
    return 1;
}

int databuf_advance(DataBuf *db, size_t advance)
{
    size_t actual_advance;
    DATABUF_VALIDATE(db);

    if (debug) databuf_print(db, 1, "databuf_advance() enter, advance=%d", advance);
    actual_advance = MIN(advance, db->len);
    db->offset += actual_advance;
    db->len -= actual_advance;

    if (debug) databuf_print(db, 1, "databuf_advance() leave, actual_advance=%d", actual_advance);
    DATABUF_VALIDATE(db);
    if (advance == actual_advance) {
        return 1;
    } else {
        errno = ESPIPE; // Illegal seek
        return -1;
    }
}


int databuf_compress(DataBuf *db)
{
    void *new_alloc;

    DATABUF_VALIDATE(db);
    if (databuf_beg(db) == NULL || db->len == 0) return 0;
    databuf_shift_data_to_beginning(db);
    if ((new_alloc = realloc(db->alloc_ptr, db->len))) {
        db->alloc_ptr  = new_alloc;
        db->alloc_size = db->len;
    } else {
        return -1;           /* realloc failed */
    }
    
    DATABUF_VALIDATE(db);
    return 1;
}

int databuf_reset(DataBuf *db)
{
    if (debug) databuf_print(db, 1, "databuf_reset() entry");
    if (!(db->flags & DATABUF_FLAG_PRESERVE_HEAD)) return -1;
    db->offset = 0;
    db->len = MIN(db->alloc_size, db->max_len);
    if (debug) databuf_print(db, 1, "databuf_reset() exit");
    return 1;
}

/*****************************************************************************/
/*******************************  Test Program  ******************************/
/*****************************************************************************/

#ifdef TEST
static char *make_data(size_t size, const char *fill) {
    int n=0;
    char *data = malloc(size);

    if (data == NULL) {
        fprintf(stderr, "ERROR: make_data malloc failed\n");
        exit(1);
    }

    n += snprintf(data, size, "%d", size);
    while (n < size) {
        n += snprintf(data+n, size-n, "%s", fill);
    }
    return data;
}

int main(int argc, char **argv)
{
    size_t size = 0;
    DataBuf buf;
    char *data;

    assert(databuf_init(&buf, size, DATABUF_FLAG_STRING));
    databuf_print(&buf, 1, "after init size=%d", size);

#if 1
    data = "a";
    assert(databuf_strcat(&buf, data));
    databuf_print(&buf, 1, "after strcat(%s)", data);

    data = "bb";
    assert(databuf_strcat(&buf, data));
    databuf_print(&buf, 1, "after strcat(%s)", data);

    data = "ccc";
    assert(databuf_strcat(&buf, data));
    databuf_print(&buf, 1, "after strcat(%s)", data);

#endif

    data = databuf_export(&buf);
    printf("concatenation=\"%s\"\n", data);
    free(data);

#if 0
    assert(databuf_init(&buf, size, 0));
    databuf_print(&buf, 1, "after init size=%d", size);

    size = 8;
    data = make_data(size, "a");
    assert(databuf_append(&buf, data, size));
    databuf_print(&buf, 1, "after append size=%d", size);
    assert(databuf_append(&buf, data, size));
    free(data);
    databuf_print(&buf, 1, "after append size=%d", size);

    assert(databuf_advance(&buf, 4));
    databuf_print(&buf, 1, "after databuf_advance(%d", 4);
    assert(databuf_compress(&buf));
    databuf_print(&buf, 1, "after compress");

    size = 5;
    data = make_data(size, "b");
    assert(databuf_append(&buf, data, size));
    free(data);
    databuf_print(&buf, 1, "after append size=%d", size);
    size = 7;
    data = make_data(size, "c");
    assert(databuf_append(&buf, data, size));
    free(data);
    databuf_print(&buf, 1, "after append size=%d", size);

    databuf_free(&buf);
#endif
    exit(0);
}
#endif
