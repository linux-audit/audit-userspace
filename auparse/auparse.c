/* auparse.c --
 * Copyright 2006-08,2012-15 Red Hat Inc., Durham, North Carolina.
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
 */

#include "config.h"
#include "expression.h"
#include "internal.h"
#include "auparse.h"
#include "interpret.h"
#include "auparse-idata.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio_ext.h>

static int debug = 0;

/* like strchr except string is delimited by length, not null byte */
static char *strnchr(const char *s, int c, size_t n)
{
    char *p_char;
    const char *p_end = s + n;

    for (p_char = (char *)s; p_char < p_end && *p_char != c; p_char++);
    if (p_char == p_end) return NULL;
    return p_char;
}

static int setup_log_file_array(auparse_state_t *au)
{
        struct daemon_conf config;
        char *filename, **tmp;
        int len, num = 0, i = 0;

        /* Load config so we know where logs are */
	set_aumessage_mode(MSG_STDERR, DBG_NO);
	load_config(&config, TEST_SEARCH);

	/* for each file */
	len = strlen(config.log_file) + 16;
	filename = malloc(len);
	if (!filename) {
		fprintf(stderr, "No memory\n");
		free_config(&config);
		return 1;
	}
	/* Find oldest log file */
	snprintf(filename, len, "%s", config.log_file);
	do {
		if (access(filename, R_OK) != 0)
			break;
		num++;
		snprintf(filename, len, "%s.%d", config.log_file, num);
	} while (1);

	if (num == 0) {
		fprintf(stderr, "No log file\n");
		free_config(&config);
		free(filename);
		return 1;
	}
	num--;
	tmp = malloc((num+2)*sizeof(char *));

        /* Got it, now process logs from last to first */
	if (num > 0)
		snprintf(filename, len, "%s.%d", config.log_file, num);
	else
		snprintf(filename, len, "%s", config.log_file);
	do {
		tmp[i++] = strdup(filename);

		/* Get next log file */
		num--;
		if (num > 0)
			snprintf(filename, len, "%s.%d", config.log_file, num);
		else if (num == 0)
			snprintf(filename, len, "%s", config.log_file);
		else
			break;
	} while (1);
	free_config(&config);
	free(filename);

	// Terminate the list
	tmp[i] = NULL; 
	au->source_list = tmp;
	return 0;
}

/* General functions that affect operation of the library */
auparse_state_t *auparse_init(ausource_t source, const void *b)
{
	char **tmp, **bb = (char **)b, *buf = (char *)b;
	int n, i;
	size_t size, len;

	auparse_state_t *au = malloc(sizeof(auparse_state_t));
	if (au == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	au->in = NULL;
	au->source_list = NULL;
	databuf_init(&au->databuf, 0, 0);
	au->callback = NULL;
	au->callback_user_data = NULL;
	au->callback_user_data_destroy = NULL;
	switch (source)
	{
		case AUSOURCE_LOGS:
			if (geteuid()) {
				errno = EPERM;
				goto bad_exit;
			}
			setup_log_file_array(au);
			break;
		case AUSOURCE_FILE:
			if (access(b, R_OK))
				goto bad_exit;
			tmp = malloc(2*sizeof(char *));
			tmp[0] = strdup(b);
			tmp[1] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_FILE_ARRAY:
			n = 0;
			while (bb[n]) {
				if (access(bb[n], R_OK))
					goto bad_exit;
				n++;
			}
			tmp = malloc((n+1)*sizeof(char *));
			for (i=0; i<n; i++)
				tmp[i] = strdup(bb[i]);
			tmp[n] = NULL;
			au->source_list = tmp;
			break;
		case AUSOURCE_BUFFER:
			buf = buf;
			len = strlen(buf);
			if (databuf_init(&au->databuf, len,
					 DATABUF_FLAG_PRESERVE_HEAD) < 0)
				goto bad_exit;
			if (databuf_append(&au->databuf, buf, len) < 0)
				goto bad_exit;
			break;
		case AUSOURCE_BUFFER_ARRAY:
			size = 0;
			for (n = 0; (buf = bb[n]); n++) {
				len = strlen(bb[n]);
				if (bb[n][len-1] != '\n') {
					size += len + 1;
				} else {
					size += len;
				}
			}
			if (databuf_init(&au->databuf, size,
					DATABUF_FLAG_PRESERVE_HEAD) < 0)
				goto bad_exit;
			for (n = 0; (buf = bb[n]); n++) {
				len = strlen(buf);
				if (databuf_append(&au->databuf, buf, len) < 0)
					goto bad_exit;
			}
			break;
		case AUSOURCE_DESCRIPTOR:
			n = (long)b;
			au->in = fdopen(n, "rm");
			break;
		case AUSOURCE_FILE_POINTER:
			au->in = (FILE *)b;
			break;
		case AUSOURCE_FEED:
                    if (databuf_init(&au->databuf, 0, 0) < 0) goto bad_exit;
			break;
		default:
			errno = EINVAL;
			goto bad_exit;
			break;
	}
	au->source = source;
	au->list_idx = 0;
        au->line_number = 0;
	au->next_buf = NULL;
	au->off = 0;
	au->cur_buf = NULL;
	au->line_pushed = 0;
	aup_list_create(&au->le);
	au->parse_state = EVENT_EMPTY;
	au->expr = NULL;
	au->find_field = NULL;
	au->search_where = AUSEARCH_STOP_EVENT;

	return au;
bad_exit:
	databuf_free(&au->databuf);
	free(au);
	return NULL;
}


void auparse_add_callback(auparse_state_t *au, auparse_callback_ptr callback,
			  void *user_data, user_destroy user_destroy_func)
{
	if (au == NULL) {
		errno = EINVAL;
		return;
	}

	if (au->callback_user_data_destroy) {
		(*au->callback_user_data_destroy)(au->callback_user_data);
		au->callback_user_data = NULL;
	}

	au->callback = callback;
	au->callback_user_data = user_data;
	au->callback_user_data_destroy = user_destroy_func;
}

static void consume_feed(auparse_state_t *au, int flush)
{
	while (auparse_next_event(au) > 0) {
		if (au->callback) {
			(*au->callback)(au, AUPARSE_CB_EVENT_READY,
					au->callback_user_data);
		}
	}
	if (flush) {
		// FIXME: might need a call here to force auparse_next_event()
		// to consume any partial data not fully consumed.
		if (au->parse_state == EVENT_ACCUMULATING) {
			// Emit the event, set event cursors to initial position
			aup_list_first(&au->le);
			aup_list_first_field(&au->le);
			au->parse_state = EVENT_EMITTED;
			if (au->callback) {
				 (*au->callback)(au, AUPARSE_CB_EVENT_READY,
						 au->callback_user_data);
			}
		}
	}
}

int auparse_feed(auparse_state_t *au, const char *data, size_t data_len)
{
	if (databuf_append(&au->databuf, data, data_len) < 0)
		return -1;
	consume_feed(au, 0);
	return 0;
}

int auparse_flush_feed(auparse_state_t *au)
{
	consume_feed(au, 1);
	return 0;
}

// If there is data in the state machine, return 1
// Otherwise return 0 to indicate its empty
int auparse_feed_has_data(const auparse_state_t *au)
{
	if (au->parse_state == EVENT_ACCUMULATING)
		return 1;
	return 0;
}

void auparse_set_escape_mode(auparse_esc_t mode)
{
	set_escape_mode(mode);
}

int auparse_reset(auparse_state_t *au)
{
	if (au == NULL) {
		errno = EINVAL;
		return -1;
	}

	aup_list_clear(&au->le);
	au->parse_state = EVENT_EMPTY;
	switch (au->source)
	{
		case AUSOURCE_LOGS:
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			if (au->in) {
				fclose(au->in);
				au->in = NULL;
			}
		/* Fall through */
		case AUSOURCE_DESCRIPTOR:
		case AUSOURCE_FILE_POINTER:
			if (au->in) 
				rewind(au->in);
		/* Fall through */
		case AUSOURCE_BUFFER:
		case AUSOURCE_BUFFER_ARRAY:
			au->list_idx = 0;
			au->line_number = 0;
			au->off = 0;
			databuf_reset(&au->databuf);
			break;
		default:
			return -1;
	}
	return 0;
}


/* Add EXPR to AU, using HOW to select the combining operator.
   On success, return 0.
   On error, free EXPR set errno and return -1.
   NOTE: EXPR is freed on error! */
static int add_expr(auparse_state_t *au, struct expr *expr, ausearch_rule_t how)
{
	if (au->expr == NULL)
		au->expr = expr;
	else if (how == AUSEARCH_RULE_CLEAR) {
		expr_free(au->expr);
		au->expr = expr;
	} else {
		struct expr *e;

		e = expr_create_binary(how == AUSEARCH_RULE_OR ? EO_OR : EO_AND,
				       au->expr, expr);
		if (e == NULL) {
			int err;

			err = errno;
			expr_free(expr);
			errno = err;
			return -1;
		}
		au->expr = e;
	}
	return 0;
}

static int ausearch_add_item_internal(auparse_state_t *au, const char *field,
	const char *op, const char *value, ausearch_rule_t how, unsigned op_eq,
	unsigned op_ne)
{
	struct expr *expr;

	// Make sure there's a field
	if (field == NULL)
		goto err_out;

	// Make sure how is within range
	if (how < AUSEARCH_RULE_CLEAR || how > AUSEARCH_RULE_AND)
		goto err_out;

	// All pre-checks are done, build a rule
	if (strcmp(op, "exists") == 0)
		expr = expr_create_field_exists(field);
	else {
		unsigned t_op;

		if (strcmp(op, "=") == 0)
			t_op = op_eq;
		else if (strcmp(op, "!=") == 0)
			t_op = op_ne;
		else
			goto err_out;
		if (value == NULL)
			goto err_out;
		expr = expr_create_comparison(field, t_op, value);
	}
	if (expr == NULL)
		return -1;
	if (add_expr(au, expr, how) != 0)
		return -1; /* expr is freed by add_expr() */
	return 0;

err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_add_item(auparse_state_t *au, const char *field, const char *op,
	const char *value, ausearch_rule_t how)
{
	return ausearch_add_item_internal(au, field, op, value, how, EO_RAW_EQ,
					  EO_RAW_NE);
}

int ausearch_add_interpreted_item(auparse_state_t *au, const char *field,
	const char *op, const char *value, ausearch_rule_t how)
{
	return ausearch_add_item_internal(au, field, op, value, how,
					  EO_INTERPRETED_EQ, EO_INTERPRETED_NE);
}

int ausearch_add_timestamp_item_ex(auparse_state_t *au, const char *op,
	time_t sec, unsigned milli, unsigned serial, ausearch_rule_t how)
{
	static const struct {
		unsigned value;
		const char name[3];
	} ts_tab[] = {
		{EO_VALUE_LT, "<"},
		{EO_VALUE_LE, "<="},
		{EO_VALUE_GE, ">="},
		{EO_VALUE_GT, ">"},
		{EO_VALUE_EQ, "="},
	};

	struct expr *expr;
        size_t i;
	unsigned t_op;

        for (i = 0; i < sizeof(ts_tab) / sizeof(*ts_tab); i++) {
                if (strcmp(ts_tab[i].name, op) == 0)
			goto found_op;
	}
	goto err_out;
found_op:
	t_op = ts_tab[i].value;

	if (milli >= 1000)
		goto err_out;

	// Make sure how is within range
	if (how < AUSEARCH_RULE_CLEAR || how > AUSEARCH_RULE_AND)
		goto err_out;

	// All pre-checks are done, build a rule
	expr = expr_create_timestamp_comparison_ex(t_op, sec, milli, serial);
	if (expr == NULL)
		return -1;
	if (add_expr(au, expr, how) != 0)
		return -1; /* expr is freed by add_expr() */
	return 0;

err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_add_timestamp_item(auparse_state_t *au, const char *op, time_t sec,
				unsigned milli, ausearch_rule_t how)
{
	return ausearch_add_timestamp_item_ex(au, op, sec, milli, 0, how);
}

int ausearch_add_expression(auparse_state_t *au, const char *expression,
			    char **error, ausearch_rule_t how)
{
	struct expr *expr;

	if (how < AUSEARCH_RULE_CLEAR || how > AUSEARCH_RULE_AND)
		goto err_einval;

	expr = expr_parse(expression, error);
	if (expr == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (add_expr(au, expr, how) != 0)
		goto err; /* expr is freed by add_expr() */
	return 0;

err_einval:
	errno = EINVAL;
err:
	*error = NULL;
	return -1;
}

int ausearch_add_regex(auparse_state_t *au, const char *regexp)
{
	struct expr *expr;

	// Make sure there's an expression
	if (regexp == NULL)
		goto err_out;

	expr = expr_create_regexp_expression(regexp);
	if (expr == NULL)
		return -1;
	if (add_expr(au, expr, AUSEARCH_RULE_AND) != 0)
		return -1; /* expr is freed by add_expr() */
	return 0;

err_out:
	errno = EINVAL;
	return -1;
}

int ausearch_set_stop(auparse_state_t *au, austop_t where)
{
	if (where < AUSEARCH_STOP_EVENT || where > AUSEARCH_STOP_FIELD) {
		errno = EINVAL;
		return -1;
	}

	au->search_where = where;
	return 0;
}

void ausearch_clear(auparse_state_t *au)
{
	if (au->expr != NULL) {
		expr_free(au->expr);
		au->expr = NULL;
	}
	au->search_where = AUSEARCH_STOP_EVENT;
}

void auparse_destroy(auparse_state_t *au)
{
	aulookup_destroy_uid_list();
	aulookup_destroy_gid_list();
	if (au == NULL)
		return;

	if (au->source_list) {
		int n = 0;
		while (au->source_list[n]) 
			free(au->source_list[n++]);
		free(au->source_list);
		au->source_list = NULL;
	}

	au->next_buf = NULL;
        free(au->cur_buf);
	au->cur_buf = NULL;
	aup_list_clear(&au->le);
	au->parse_state = EVENT_EMPTY;
        free(au->find_field);
	au->find_field = NULL;
	ausearch_clear(au);
	databuf_free(&au->databuf);
	if (au->callback_user_data_destroy) {
		(*au->callback_user_data_destroy)(au->callback_user_data);
		au->callback_user_data = NULL;
	}
	if (au->in) {
		fclose(au->in);
		au->in = NULL;
	}
	free(au);
}

/* alloc a new buffer, cur_buf which contains a null terminated line
 * without a newline (note, this implies the line may be empty (strlen == 0)) if
 * successfully read a blank line (e.g. containing only a single newline).
 * cur_buf will have been newly allocated with malloc.
 * 
 * Note: cur_buf will be freed the next time this routine is called if
 * cur_buf is not NULL, callers who retain a reference to the cur_buf
 * pointer will need to set cur_buf to NULL to cause the previous cur_buf
 * allocation to persist.
 *
 * Returns:
 *     1 if successful (errno == 0)
 *     0 if non-blocking input unavailable (errno == 0)
 *    -1 if error (errno contains non-zero error code)
 *    -2 if EOF  (errno == 0)
 */

static int readline_file(auparse_state_t *au)
{
	ssize_t rc;
	char *p_last_char;
	size_t n = 0;

	if (au->cur_buf != NULL) {
		free(au->cur_buf);
		au->cur_buf = NULL;
	}
	if (au->in == NULL) {
		errno = EBADF;
		return -1;
	}
	if ((rc = getline(&au->cur_buf, &n, au->in)) <= 0) {
		// Note: getline always malloc's if lineptr==NULL or n==0,
		// on failure malloc'ed memory is left uninitialized,
		// caller must free it.
		free(au->cur_buf);
		au->cur_buf = NULL;

		// Note: feof() does not set errno
		if (feof(au->in)) {
			// return EOF condition
			errno = 0;
			return -2;
		}
		// return error condition, error code in errno
		return -1;
	}
	p_last_char = au->cur_buf + (rc-1);
	if (*p_last_char == '\n') {	/* nuke newline */
		*p_last_char = 0;
	}
	// return success
	errno = 0;
	return 1;
}


/* malloc & copy a line into cur_buf from the internal buffer,
 * next_buf.  cur_buf will contain a null terminated line without a
 * newline (note, this implies the line may be empty (strlen == 0)) if
 * successfully read a blank line (e.g. containing only a single
 * newline).
 * 
 * Note: cur_buf will be freed the next time this routine is called if
 * cur_buf is not NULL, callers who retain a reference to the cur_buf
 * pointer will need to set cur_buf to NULL to cause the previous cur_buf
 * allocation to persist.
 *
 * Returns:
 *     1 if successful (errno == 0)
 *     0 if non-blocking input unavailable (errno == 0)
 *    -1 if error (errno contains non-zero error code)
 *    -2 if EOF  (errno == 0)
 */

static int readline_buf(auparse_state_t *au)
{
	char *p_newline=NULL;
	size_t line_len;

	if (au->cur_buf != NULL) {
		free(au->cur_buf);
		au->cur_buf = NULL;
	}

	//if (debug) databuf_print(&au->databuf, 1, "readline_buf");
	if (au->databuf.len == 0) {
		// return EOF condition
		errno = 0;
		return -2;
	}

	if ((p_newline = strnchr(databuf_beg(&au->databuf), '\n',
						au->databuf.len)) != NULL) {
		line_len = p_newline - databuf_beg(&au->databuf);
		
		/* dup the line */
		au->cur_buf = malloc(line_len+1);   // +1 for null terminator
		if (au->cur_buf == NULL)
			return -1; // return error condition, errno set
		strncpy(au->cur_buf, databuf_beg(&au->databuf), line_len);
		au->cur_buf[line_len] = 0;

		if (databuf_advance(&au->databuf, line_len+1) < 0)
			return -1;
		// return success
		errno = 0;
		return 1;
	
	} else {
		// return no data available
		errno = 0;
		return 0;
	}
}

static int str2event(char *s, au_event_t *e)
{
	char *ptr;

	errno = 0;
	ptr = strchr(s+10, ':');
	if (ptr) {
		e->serial = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->serial = 0;
	ptr = strchr(s, '.');
	if (ptr) {
		e->milli = strtoul(ptr+1, NULL, 10);
		*ptr = 0;
		if (errno)
			return -1;
	} else
		e->milli = 0;
	e->sec = strtoul(s, NULL, 10);
	if (errno)
		return -1;
	return 0;
}

/* Returns 0 on success and 1 on error */
static int extract_timestamp(const char *b, au_event_t *e)
{
	char *ptr, *tmp;
	int rc = 1;

        e->host = NULL;
	if (*b == 'n')
		tmp = strndupa(b, 340);
	else
		tmp = strndupa(b, 80);
	ptr = audit_strsplit(tmp);
	if (ptr) {
		// Optionally grab the node - may or may not be included
		if (*ptr == 'n') {
			e->host = strdup(ptr+5);
			(void)audit_strsplit(NULL); // Bump along to the next one
		}
		// at this point we have type=
		ptr = audit_strsplit(NULL);
		if (ptr) {
			if (*(ptr+9) == '(')
				ptr+=9;
			else
				ptr = strchr(ptr, '(');
			if (ptr) {
				// now we should be pointed at the timestamp
				char *eptr;
				ptr++;
				eptr = strchr(ptr, ')');
				if (eptr)
					*eptr = 0;

				if (str2event(ptr, e) == 0)
					rc = 0;
//				else {
//					audit_msg(LOG_ERROR,
//					  "Error extracting time stamp (%s)\n",
//						ptr);
//				}
			}
			// else we have a bad line
		}
		// else we have a bad line
	}
	// else we have a bad line
	return rc;
}

static int inline events_are_equal(au_event_t *e1, au_event_t *e2)
{
	// Check time & serial first since its most likely way
	// to spot 2 different events
	if (!(e1->serial == e2->serial && e1->milli == e2->milli &&
					e1->sec == e2->sec))
		return 0;
	// Hmm...same so far, check if both have a host, only a string
	// compare can tell if they are the same. Otherwise, if only one
	// of them have a host, they are definitely not the same. Its
	// a boundary on daemon config.
	if (e1->host && e2->host) {
		if (strcmp(e1->host, e2->host))
			return 0;
	} else if (e1->host || e2->host)
		return 0;
	return 1;
}

/* This function will figure out how to get the next line of input.
 * storing it cur_buf. cur_buf will be NULL terminated but will not
 * contain a trailing newline. This implies a successful read 
 * (result == 1) may result in a zero length cur_buf if a blank line
 * was read.
 *
 * cur_buf will have been allocated with malloc. The next time this
 * routine is called if cur_buf is non-NULL cur_buf will be freed,
 * thus if the caller wishes to retain a reference to malloc'ed
 * cur_buf data it should copy the cur_buf pointer and set cur_buf to
 * NULL.
 *
 * Returns:
 *     1 if successful (errno == 0)
 *     0 if non-blocking input unavailable (errno == 0)
 *    -1 if error (errno contains non-zero error code)
 *    -2 if EOF  (errno == 0)
 */

static int retrieve_next_line(auparse_state_t *au)
{
	int rc;

	// If line was pushed back for re-reading return that
	if (au->line_pushed) {
		// Starting new event, clear previous event data,
		// previous line is returned again for new parsing
		au->line_pushed = 0;
		au->line_number++;
		return 1;
	}

	switch (au->source)
	{
		case AUSOURCE_DESCRIPTOR:
		case AUSOURCE_FILE_POINTER:
			rc = readline_file(au);
			if (rc > 0) au->line_number++;
			return rc;
		case AUSOURCE_LOGS:
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			// if the first time through, open file
			if (au->list_idx == 0 && au->in == NULL &&
						au->source_list != NULL) {
				if (au->source_list[au->list_idx] == NULL) {
					errno = 0;
					return -2;
				}
				au->line_number = 0;
				au->in = fopen(au->source_list[au->list_idx],
									"rm");
				if (au->in == NULL)
					return -1;
				__fsetlocking(au->in, FSETLOCKING_BYCALLER);
			}

			// loop reading lines from a file
			while (au->in) {
				if ((rc = readline_file(au)) == -2) {
					// end of file, open next file,
					// try readline again
					fclose(au->in);
					au->in = NULL;
					au->list_idx++;
					au->line_number = 0;
					if (au->source_list[au->list_idx]) {
						au->in = fopen(
						  au->source_list[au->list_idx],
						  "rm");
						if (au->in == NULL)
							return -1;
						__fsetlocking(au->in,
							FSETLOCKING_BYCALLER);
					}
				} else {
					if (rc > 0)
						au->line_number++;
					return rc;
				}
			}
			return -2;	// return EOF
		case AUSOURCE_BUFFER:
		case AUSOURCE_BUFFER_ARRAY:
			rc = readline_buf(au);
			if (rc > 0)
				au->line_number++;
			return rc;
		case AUSOURCE_FEED:
			rc = readline_buf(au);
			// No such thing as EOF for feed, translate EOF
			// to data not available
			if (rc == -2)
				return 0;
			else
				if (rc > 0)
					au->line_number++;
				return rc;
		default:
			return -1;
	}
	return -1;		/* should never reach here */
}

static void push_line(auparse_state_t *au)
{
	au->line_number--;
	au->line_pushed = 1;
}

/*******
* Functions that traverse events.
********/
static int ausearch_reposition_cursors(auparse_state_t *au)
{
	int rc = 0;

	switch (au->search_where)
	{
		case AUSEARCH_STOP_EVENT:
			aup_list_first(&au->le);
			aup_list_first_field(&au->le);
			break;
		case AUSEARCH_STOP_RECORD:
			aup_list_first_field(&au->le);
			break;
		case AUSEARCH_STOP_FIELD:
			// do nothing - this is the normal stopping point
			break;
		default:
			rc = -1;
			break;
	}
	return rc;
}

/* This is called during search once per each record. It walks the list
 * of nvpairs and decides if a field matches. */
static int ausearch_compare(auparse_state_t *au)
{
	rnode *r;

	r = aup_list_get_cur(&au->le);
	if (r)
		return expr_eval(au, r, au->expr);

	return 0;
}

// Returns < 0 on error, 0 no data, > 0 success
int ausearch_next_event(auparse_state_t *au)
{
	int rc;

	if (au->expr == NULL) {
		errno = EINVAL;
		return -1;
	}
	if ((rc = auparse_first_record(au)) <= 0)
		return rc;
        do {
		do {
			if ((rc = ausearch_compare(au)) > 0) {
				ausearch_reposition_cursors(au);
				return 1;
			} else if (rc < 0)
				return rc;
               	} while ((rc = auparse_next_record(au)) > 0);
		if (rc < 0)
			return rc;
        } while ((rc = auparse_next_event(au)) > 0);
	if (rc < 0)
		return rc;
	
	return 0;
}

// Brute force go to next event. Returns < 0 on error, 0 no data, > 0 success
int auparse_next_event(auparse_state_t *au)
{
	int rc;
	au_event_t event;

	if (au->parse_state == EVENT_EMITTED) {
		// If the last call resulted in emitting event data then
		// clear previous event data in preparation to accumulate
		// new event data
		aup_list_clear(&au->le);
		au->parse_state = EVENT_EMPTY;
	}

	// accumulate new event data
	while (1) {
		rc = retrieve_next_line(au);
		if (debug) printf("next_line(%d) '%s'\n", rc, au->cur_buf);
		if (rc ==  0) return 0;	// No data now
		if (rc == -2) {
			// We're at EOF, did we read any data previously?
			// If so return data available, else return no data
			// available
			if (au->parse_state == EVENT_ACCUMULATING) {
				if (debug) printf("EOF, EVENT_EMITTED\n");
				au->parse_state = EVENT_EMITTED;
				return 1; // data is available
			}
			return 0;
		}
		if (rc > 0) {	        // Input available
			rnode *r;
			if (extract_timestamp(au->cur_buf, &event)) {
				if (debug)
					printf("Malformed line:%s\n",
							 au->cur_buf);
				continue;
			}
			if (au->parse_state == EVENT_EMPTY) {
				// First record in new event, initialize event
				if (debug)
					printf(
			"First record in new event, initialize event\n");
				aup_list_set_event(&au->le, &event);
				aup_list_append(&au->le, au->cur_buf,
						au->list_idx, au->line_number);
				au->parse_state = EVENT_ACCUMULATING;
				au->cur_buf = NULL; 
			} else if (events_are_equal(&au->le.e, &event)) {
				// Accumulate data into existing event
				if (debug)
					printf(
				    "Accumulate data into existing event\n");
				aup_list_append(&au->le, au->cur_buf,
						au->list_idx, au->line_number);
				au->parse_state = EVENT_ACCUMULATING;
				au->cur_buf = NULL; 
			} else {
				// New event, save input for next invocation
				if (debug)
					printf(
	"New event, save current input for next invocation, EVENT_EMITTED\n");
				push_line(au);
				// Emit the event, set event cursors to 
				// initial position
				aup_list_first(&au->le);
				aup_list_first_field(&au->le);
				au->parse_state = EVENT_EMITTED;
				free((char *)event.host);
				return 1; // data is available
			}
			free((char *)event.host);
			// Check to see if the event can be emitted due to EOE
			// or something we know is a single record event. At
			// this point, new record should be pointed at 'cur'
			if ((r = aup_list_get_cur(&au->le)) == NULL)
				continue;
			if (	r->type == AUDIT_EOE ||
				r->type < AUDIT_FIRST_EVENT ||
				r->type >= AUDIT_FIRST_ANOM_MSG) {
				// Emit the event, set event cursors to 
				// initial position
				aup_list_first(&au->le);
				aup_list_first_field(&au->le);
				au->parse_state = EVENT_EMITTED;
				return 1; // data is available
			}
		} else {		// Read error
			return -1;
		}
	}	
}

/* Accessors to event data */
const au_event_t *auparse_get_timestamp(auparse_state_t *au)
{
	if (au && au->le.e.sec != 0)
		return &au->le.e;
	else
		return NULL;
}


time_t auparse_get_time(auparse_state_t *au)
{
	if (au)
		return au->le.e.sec;
	else
		return 0;
}


unsigned int auparse_get_milli(auparse_state_t *au)
{
	if (au)
		return au->le.e.milli;
	else
		return 0;
}


unsigned long auparse_get_serial(auparse_state_t *au)
{
	if (au)
		return au->le.e.serial;
	else
		return 0;
}


// Gets the machine node name
const char *auparse_get_node(auparse_state_t *au)
{
	if (au && au->le.e.host != NULL)
		return strdup(au->le.e.host);
	else
		return NULL;
}


int auparse_node_compare(au_event_t *e1, au_event_t *e2)
{
	// If both have a host, only a string compare can tell if they
	// are the same. Otherwise, if only one of them have a host, they
	// are definitely not the same. Its a boundary on daemon config.
	if (e1->host && e2->host) 
		return strcmp(e1->host, e2->host);
	else if (e1->host)
		return 1;
	else if (e2->host)
		return -1;

	return 0;
}


int auparse_timestamp_compare(au_event_t *e1, au_event_t *e2)
{
	if (e1->sec > e2->sec)
		return 1;
	if (e1->sec < e2->sec)
		return -1;

	if (e1->milli > e2->milli)
		return 1;
	if (e1->milli < e2->milli)
		return -1;

	if (e1->serial > e2->serial)
		return 1;
	if (e1->serial < e2->serial)
		return -1;

	return 0;
}

unsigned int auparse_get_num_records(auparse_state_t *au)
{
	return aup_list_get_cnt(&au->le);
}


/* Functions that traverse records in the same event */
int auparse_first_record(auparse_state_t *au)
{
	int rc;

	if (aup_list_get_cnt(&au->le) == 0) {
		rc = auparse_next_event(au);
		if (rc <= 0)
			return rc;
	}
	aup_list_first(&au->le);
	aup_list_first_field(&au->le);
	
	return 1;
}


int auparse_next_record(auparse_state_t *au)
{
	if (aup_list_get_cnt(&au->le) == 0) { 
		int rc = auparse_first_record(au);
		if (rc <= 0)
			return rc;
	}
	if (aup_list_next(&au->le))
		return 1;
	else
		return 0;
}


int auparse_goto_record_num(auparse_state_t *au, unsigned int num)
{
	/* Check if a request is out of range */
	if (num >= aup_list_get_cnt(&au->le))
		return 0;

	if (aup_list_goto_rec(&au->le, num) != NULL)
		return 1;
	else
		return 0;
}


/* Accessors to record data */
int auparse_get_type(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r) 
		return r->type;
	else
		return 0;
}


const char *auparse_get_type_name(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r)
		return audit_msg_type_to_name(r->type);
	else
		return NULL;
}


unsigned int auparse_get_line_number(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r) 
		return r->line_number;
	else
		return 0;
}


const char *auparse_get_filename(auparse_state_t *au)
{
	switch (au->source)
	{
		case AUSOURCE_FILE:
		case AUSOURCE_FILE_ARRAY:
			break;
		default:
			return NULL;
	}

	rnode *r = aup_list_get_cur(&au->le);
	if (r) {
		if (r->list_idx < 0) return NULL;
		return au->source_list[r->list_idx];
	} else {
		return NULL;
	}
}


int auparse_first_field(auparse_state_t *au)
{
	return aup_list_first_field(&au->le);
}


int auparse_next_field(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r) {
		if (nvlist_next(&r->nv))
			return 1;
		else
			return 0;
	}
	return 0;
}


unsigned int auparse_get_num_fields(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r)
		return nvlist_get_cnt(&r->nv);
	else
		return 0;
}

const char *auparse_get_record_text(auparse_state_t *au)
{
	rnode *r = aup_list_get_cur(&au->le);
	if (r) 
		return r->record;
	else
		return NULL;
}


/* scan from current location to end of event */
const char *auparse_find_field(auparse_state_t *au, const char *name)
{
	free(au->find_field);
	au->find_field = strdup(name);

	if (au->le.e.sec) {
		const char *cur_name;
		rnode *r;

		// look at current record before moving
		r = aup_list_get_cur(&au->le);
		if (r == NULL)
			return NULL;
		cur_name = nvlist_get_cur_name(&r->nv);
		if (cur_name && strcmp(cur_name, name) == 0)
			return nvlist_get_cur_val(&r->nv);

		return auparse_find_field_next(au);
	}
	return NULL;
}

/* Increment 1 location and then scan for next field */
const char *auparse_find_field_next(auparse_state_t *au)
{
	if (au->find_field == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (au->le.e.sec) {
		int moved = 0;

		rnode *r = aup_list_get_cur(&au->le);
		while (r) {	// For each record in the event...
			if (!moved) {
				nvlist_next(&r->nv);
				moved=1;
			}
			if (nvlist_find_name(&r->nv, au->find_field))
				return nvlist_get_cur_val(&r->nv);
			r = aup_list_next(&au->le);
			if (r)
				aup_list_first_field(&au->le);
		}
	}
	return NULL;
}


/* Accessors to field data */
const char *auparse_get_field_name(auparse_state_t *au)
{
	if (au->le.e.sec) {
		rnode *r = aup_list_get_cur(&au->le);
		if (r) 
			return nvlist_get_cur_name(&r->nv);
	}
	return NULL;
}


const char *auparse_get_field_str(auparse_state_t *au)
{
	if (au->le.e.sec) {
		rnode *r = aup_list_get_cur(&au->le);
		if (r) 
			return nvlist_get_cur_val(&r->nv);
	}
	return NULL;
}

int auparse_get_field_type(auparse_state_t *au)
{
        if (au->le.e.sec) {
                rnode *r = aup_list_get_cur(&au->le);
                if (r)
                        return nvlist_get_cur_type(r);
        }
	return AUPARSE_TYPE_UNCLASSIFIED;
}

int auparse_get_field_int(auparse_state_t *au)
{
	const char *v = auparse_get_field_str(au);
	if (v) {
		int val;

		errno = 0;
		val = strtol(v, NULL, 10);
		if (errno == 0)
			return val;
	} else
		errno = ENODATA;
	return -1;
}

const char *auparse_interpret_field(auparse_state_t *au)
{
        if (au->le.e.sec) {
                rnode *r = aup_list_get_cur(&au->le);
                if (r)
                        return nvlist_interp_cur_val(r);
        }
	return NULL;
}

