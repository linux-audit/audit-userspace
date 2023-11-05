/*
* ellist.c - Minimal linked list library
* Copyright (c) 2006-08,2014,2016-17,2023 Red Hat Inc.
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
*   Steve Grubb <sgrubb@redhat.com>
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "libaudit.h"
#include "ellist.h"
#include "interpret.h"
#include "common.h"

static const char key_sep[2] = { AUDIT_KEY_SEPARATOR, 0 };

void aup_list_create(event_list_t *l)
{
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	l->e.milli = 0L;       
	l->e.sec = 0L;         
	l->e.serial = 0L;
	l->e.host = NULL;
	l->cwd = NULL;
}

static void aup_list_last(event_list_t *l)
{
        register rnode* node;
	
	if (l->head == NULL)
		return;

        node = l->head;
	while (node->next)
		node = node->next;
	l->cur = node;
}

rnode *aup_list_next(event_list_t *l)
{
	if (l->cur)
		l->cur = l->cur->next;
	return l->cur;
}

/*
 *  * This function does encoding of "untrusted" names just like the kernel
 *   */
static char *_audit_c2x(char *final, const char *buf, unsigned int size)
{
	unsigned int i;
	char *ptr = final;
	const char *hex = "0123456789ABCDEF";

	for (i=0; i<size; i++) {
		*ptr++ = hex[(buf[i] & 0xF0)>>4]; /* Upper nibble */
		*ptr++ = hex[buf[i] & 0x0F];      /* Lower nibble */
	}
	*ptr = 0;
	return final;
}

static char *escape(const char *tmp)
{
	char *name;
	const unsigned char *p = (unsigned char *)tmp;
	while (*p) {
		if (*p == '"' || *p < 0x21 || *p > 0x7e) {
			int len = strlen(tmp);
			name = malloc((2*len)+1);
			return _audit_c2x(name, tmp, len);
		}
		p++;
	}
	if (asprintf(&name, "\"%s\"", tmp) < 0)
		name = NULL;
	return name;
}

/* This function does the heavy duty work of splitting a record into
 * its little tiny pieces */
static int parse_up_record(rnode* r)
{
	char *ptr, *buf, *saved=NULL;
	unsigned int offset = 0, len;

	// Potentially cut the record in two
	ptr = strchr(r->record, AUDIT_INTERP_SEPARATOR);
	if (ptr) {
		*ptr = 0;
		ptr++;
	}
	r->interp = ptr;
	// Rather than call strndup, we will do it ourselves to reduce
	// the number of interactions across the record.
	// len includes the string terminator.
	len = strlen(r->record) + 1;
	r->nv.record = buf = malloc(len);
	if (r->nv.record == NULL)
		return -1;
	memcpy(r->nv.record, r->record, len);
	r->nv.end = r->nv.record + len;
	ptr = audit_strsplit_r(buf, &saved);
	// If no fields we have fuzzer induced problems, leave
	if (ptr == NULL) {
		free(buf);
		r->nv.record = NULL;
		return -1;
	}

	do {	// If there's an '=' sign, its a keeper
		nvnode n;

		char *val = strchr(ptr, '=');
		if (val) {
			int vlen;

			// If name is 'msg=audit' throw it away
			if (*ptr == 'm' && strncmp(ptr, "msg=", 4) == 0) {
				if (ptr[4] == 'a')
					continue;

				// If name is 'msg='' chop off and see
				// if there is still a = in the string.
				else if (ptr[4] == '\'') {
					ptr += 5;
					val = strchr(ptr, '=');
					if (val == NULL)
						continue;
				}
			}

			// Split the string
			*val = 0;
			val++;

			// Remove beginning cruft of name
			if (*ptr == '(')
				ptr++;
			n.name = ptr;
			n.val = val;
			// Remove trailing punctuation
			vlen = strlen(n.val);
			// Check for invalid val
			if (!vlen)
				continue;
			if (n.val[vlen-1] == ':') {
				n.val[vlen-1] = 0;
				vlen--;
			}
			if (n.val[vlen-1] == ',') {
				n.val[vlen-1] = 0;
				vlen--;
			}
			if (n.val[vlen-1] == '\'') {
				n.val[vlen-1] = 0;
				vlen--;
			}
			if (n.val[vlen-1] == ')') {
				if (strcmp(n.val, "(none)") &&
					strcmp(n.val, "(null)")) {
					n.val[vlen-1] = 0;
					vlen--;
				}
			}
			// Make virtual keys or just store it
			if (strcmp(n.name, "key") == 0 && *n.val != '(') {
				if (*n.val == '"') {
					// This is a normal single key.
					n.name = strdup("key");
					char *t = strdup(n.val);
					n.val = t;
					if (nvlist_append(&r->nv, &n)) {
						free(n.name);
						free(n.val);
						continue;
					}
				} else {
					// Virtual keys
					char *key, *ptr2, *saved2;

					key = (char *)au_unescape(n.val);
					if (key == NULL) {
						n.name = strdup("key");
						n.val = NULL;
						// Malformed key - save as is
						if (nvlist_append(&r->nv, &n)) {
							free(n.name);
							free(n.val);
						}
						continue;
					}
					ptr2 = strtok_r(key, key_sep, &saved2);
					while (ptr2) {
						n.name = strdup("key");
						n.val = escape(ptr2);
						if (nvlist_append(&r->nv, &n)) {
							free(n.name);
							free(n.val);
						}
						ptr2 = strtok_r(NULL,
							key_sep, &saved2);
					}
					free(key);
				}
				continue;
			} else {
				if (strcmp(n.name, "key") == 0) {
					// This is a null key
					n.name = strdup("key");
					char *t = strdup(n.val);
					n.val = t;
					if (nvlist_append(&r->nv, &n)) {
						free(n.name);
						free(n.val);
						continue;
					}
				} else	// everything not a key
					nvlist_append(&r->nv, &n);
			}

			// Do some info gathering for use later
			if (r->nv.cnt == 1 && strcmp(n.name, "node") == 0)
				offset = 1; // if node, some positions changes
				// This has to account for seccomp records
			else if (r->nv.cnt == (1 + offset) &&
					strcmp(n.name, "type") == 0) {
				r->type = audit_name_to_msg_type(n.val);
				if (r->type == AUDIT_URINGOP)
					r->machine = MACH_IO_URING;
				// This has to account for seccomp records
			} else if ((r->nv.cnt == (2 + offset) ||
					r->nv.cnt == (11 + offset)) &&
					strcmp(n.name, "arch")== 0){
				unsigned int ival;
				errno = 0;
				ival = strtoul(n.val, NULL, 16);
				if (errno)
					r->machine = -2;
				else
					r->machine = audit_elf_to_machine(ival);
			} else if ((r->nv.cnt == (3 + offset) ||
					r->nv.cnt == (12 + offset)) &&
					strcmp(n.name, "syscall") == 0){
				errno = 0;
				r->syscall = strtoul(n.val, NULL, 10);
				if (errno)
					r->syscall = -1;
			} else if (r->nv.cnt == (2 + offset) &&
				   strcmp(n.name, "uring_op") == 0) {
				errno = 0;
				r->syscall = strtoul(n.val, NULL, 10);
				if (errno)
					r->syscall = -1;
			} else if (r->nv.cnt == (6 + offset) &&
					strcmp(n.name, "a0") == 0){
				errno = 0;
				r->a0 = strtoull(n.val, NULL, 16);
				if (errno)
					r->a0 = -1LL;
			} else if (r->nv.cnt == (7 + offset) &&
					strcmp(n.name, "a1") == 0){
				errno = 0;
				r->a1 = strtoull(n.val, NULL, 16);
				if (errno)
					r->a1 = -1LL;
			} else if (r->type == AUDIT_CWD) {
				// most common fuzzing hit: duplicate cwds
				if (strcmp(n.name, "cwd") == 0 && !r->cwd)
					r->cwd = strdup(n.val);
			}
		} else if (r->type == AUDIT_AVC || r->type == AUDIT_USER_AVC) {
			// We special case these 2 fields because selinux
			// avc messages do not label these fields.
			n.name = NULL;
			if (nvlist_get_cnt(&r->nv) == (1 + offset)) {
				// skip over 'avc:'
				if (strncmp(ptr, "avc", 3) == 0)
					continue;
				n.name = strdup("seresult");
			} else if (nvlist_get_cnt(&r->nv) == (2 + offset)) {
				// skip over open brace
				if (*ptr == '{') {
					int total = 0, clen;
					char tmpctx[256], *to;
					tmpctx[0] = 0;
					to = tmpctx;
					ptr = audit_strsplit_r(NULL, &saved);
					while (ptr && *ptr != '}') {
						clen = strlen(ptr);
						if ((clen+1) >= (256-total)) {
						   if (nvlist_get_cnt(&r->nv)
									 == 0)
								free(buf);
							return -1;
						}
						if (tmpctx[0]) {
							to = stpcpy(to, ",");
							total++;
						}
						to = stpcpy(to, ptr);
						total += clen;
						ptr = audit_strsplit_r(NULL,
								 &saved);
					}
					n.name = strdup("seperms");
					n.val = strdup(tmpctx);
					if (nvlist_append(&r->nv, &n)) {
						free(n.name);
						free(n.val);
					}
					continue;
				}
			} else
				continue;

			n.val = ptr;
			nvlist_append(&r->nv, &n);
		}
	} while((ptr = audit_strsplit_r(NULL, &saved)));

	// If for some reason it was useless, delete buf
	if (r->nv.cnt == 0) {
		free(buf);
		r->nv.record = NULL;
		r->nv.end = NULL;
		free((void *)r->cwd);
		r->cwd = NULL;
	}

	r->nv.cur = 0;	// reset to beginning
	return 0;
}

int aup_list_append(event_list_t *l, char *record, int list_idx,
	unsigned int line_number)
{
	int rc;
	rnode* r;

	if (record == NULL)
		return -1;

	// First step is build rnode
	r = malloc(sizeof(rnode));
	if (r == NULL)
		return -1;

	r->record = record;
	r->interp = NULL;
	r->cwd = NULL;
	r->type = 0;
	r->a0 = 0LL;
	r->a1 = 0LL;
	r->machine = -1;
	r->syscall = -1;
	r->item = l->cnt;
	r->list_idx = list_idx;
	r->line_number = line_number;
	r->next = NULL;
	nvlist_create(&r->nv);

	// if we are at top, fix this up
	if (l->head == NULL)
		l->head = r;
	else {	// Otherwise add pointer to newnode
		aup_list_last(l);
		l->cur->next = r;
	}

	// make newnode current
	l->cur = r;
	l->cnt++;

	// Then parse the record up into nvlist
	rc = parse_up_record(r);
	if (r->nv.cnt == 0) // This is fuzzer induced, return an error.
		rc = -1;

	if (r->cwd) {
		// Should never be 2 cwd records unless log is corrupted
		free((void *)l->cwd);
		l->cwd = r->cwd;
	}
	return rc;
}

void aup_list_clear(event_list_t* l)
{
	rnode* nextnode;
	register rnode* current;

	if (l == NULL)
		return;

	current = l->head;
	while (current) {
		nextnode=current->next;
		nvlist_clear(&current->nv, 1);
		free(current->record);
		free(current);
		current=nextnode;
	}
	l->head = NULL;
	l->cur = NULL;
	l->cnt = 0;
	l->e.milli = 0L;       
	l->e.sec = 0L;         
	l->e.serial = 0L;
	free((char *)l->e.host);
	l->e.host = NULL;
	free((void *)l->cwd);
}

/*int aup_list_get_event(event_list_t* l, au_event_t *e)
{
	if (l == NULL || e == NULL)
		return 0;

	e->sec = l->e.sec;
        e->milli = l->e.milli;
        e->serial = l->e.serial;
	if (l->e.host)
		e->host = strdup(l->e.host);
	else
	        e->host = NULL;
	return 1;
} */

int aup_list_set_event(event_list_t* l, au_event_t *e)
{
	if (l == NULL || e == NULL)
		return 0;

	l->e.sec = e->sec;
        l->e.milli = e->milli;
        l->e.serial = e->serial;
        l->e.host = e->host;	// Take custody of the memory
	e->host = NULL;
	return 1;
}

rnode *aup_list_goto_rec(event_list_t *l, int i)
{
        register rnode* node;

	node = l->head;	/* start at the beginning */
	while (node) {
		if (node->item == i) {
			l->cur = node;
			return node;
		} else
			node = node->next;
	}
	return NULL;
}

int aup_list_first_field(const event_list_t *l)
{
	if (l && l->cur) {
		nvlist_first(&l->cur->nv);
		return 1;
	} else
		return 0;
}

