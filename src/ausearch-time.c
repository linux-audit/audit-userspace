/* ausearch-time.c - time handling utility functions
 * Copyright 2006-08,2011 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *     Steve Grubb <sgrubb@redhat.com>
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include "ausearch-time.h"


#define SECONDS_IN_DAY 24*60*60
static void clear_tm(struct tm *t);
static void replace_time(struct tm *t1, struct tm *t2);
static void replace_date(struct tm *t1, struct tm *t2);


time_t start_time = 0, end_time = 0;

struct nv_pair {
    int        value;
    const char *name;
};

static struct nv_pair timetab[] = {
        { T_NOW, "now" },
        { T_RECENT, "recent" },
        { T_TODAY, "today" },
        { T_YESTERDAY, "yesterday" },
        { T_THIS_WEEK, "this-week" },
        { T_WEEK_AGO, "week-ago" },
        { T_THIS_MONTH, "this-month" },
        { T_THIS_YEAR, "this-year" },
};
#define TIME_NAMES (sizeof(timetab)/sizeof(timetab[0]))

int lookup_time(const char *name)
{
        int i;

        for (i = 0; i < TIME_NAMES; i++) {
                if (strcmp(timetab[i].name, name) == 0) {
                        return timetab[i].value;
		}
	}
        return -1;

}

static void clear_tm(struct tm *t)
{
        t->tm_sec = 0;         /* seconds */
        t->tm_min = 0;         /* minutes */
        t->tm_hour = 0;        /* hours */
        t->tm_mday = 0;        /* day of the month */
        t->tm_mon = 0;         /* month */
        t->tm_year = 0;        /* year */
        t->tm_isdst = 0;       /* DST flag */
}

static void set_tm_now(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
	replace_time(d, tv);
	replace_date(d, tv);
}

static void set_tm_today(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
}

static void set_tm_yesterday(struct tm *d)
{
        time_t t = time(NULL) - (time_t)(SECONDS_IN_DAY);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
}

static void set_tm_recent(struct tm *d)
{
        time_t t = time(NULL) - (time_t)(10*60); /* 10 minutes ago */
        struct tm *tv = localtime(&t);
	replace_time(d, tv);
	replace_date(d, tv);
}

static void set_tm_this_week(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	t -= (time_t)(tv->tm_wday*SECONDS_IN_DAY);
        tv = localtime(&t);
	replace_date(d, tv);
}

static void set_tm_week_ago(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv;
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	t -= (time_t)(7*SECONDS_IN_DAY);
        tv = localtime(&t);
	replace_date(d, tv);
}

static void set_tm_this_month(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
        d->tm_mday = 1;         /* override day of month */
}

static void set_tm_this_year(struct tm *d)
{
        time_t t = time(NULL);
        struct tm *tv = localtime(&t);
        d->tm_sec = 0;          /* seconds */
        d->tm_min = 0;          /* minutes */
        d->tm_hour = 0;         /* hours */
	replace_date(d, tv);
        d->tm_mday = 1;         /* override day of month */
        d->tm_mon = 0;          /* override month */
}

/* Combine date & time into 1 struct. Results in date. */
static void add_tm(struct tm *d, struct tm *t)
{
        time_t dst;
        struct tm *lt;

	replace_time(d, t);

        /* Now we need to figure out if DST is in effect */
        dst = time(NULL);
        lt = localtime(&dst);
        d->tm_isdst = lt->tm_isdst;
}

/* The time in t1 is replaced by t2 */
static void replace_time(struct tm *t1, struct tm *t2)
{
        t1->tm_sec = t2->tm_sec;	/* seconds */
        t1->tm_min = t2->tm_min;	/* minutes */
        t1->tm_hour = t2->tm_hour;	/* hours */
}

/* The date in t1 is replaced by t2 */
static void replace_date(struct tm *t1, struct tm *t2)
{
        t1->tm_mday = t2->tm_mday;	/* day */
        t1->tm_mon = t2->tm_mon;	/* month */
        t1->tm_year = t2->tm_year;	/* year */
        t1->tm_isdst = t2->tm_isdst;	/* daylight savings time */
}

/* Given 2 char strings, create a time struct *
void set_time(struct tm *t, int num, const char *t1, const char *t2)
{
	switch (num)
	{
		case 1:
			// if keyword, init time
			// elif time use today and replace time
			// elif date, set to 00:00:01 and replace date
			// else error
			break;
		case 2:
			// if keyword
			//	init time with it
			//	get other time str and replace
			// otherwise, figure out which is time
			//	and set time adding them
			break;
		default:
			break;
	}
} */

static int lookup_and_set_time(const char *da, struct tm *d)
{
	int retval = lookup_time(da);
	if (retval >= 0) {
		switch (retval)
		{
			case T_NOW:
				set_tm_now(d);
				break;
			case T_RECENT:
				set_tm_recent(d);
				break;
			case T_TODAY:
				set_tm_today(d);
				break;
			case T_YESTERDAY:
				set_tm_yesterday(d);
				break;
			case T_THIS_WEEK:
				set_tm_this_week(d);
				break;
			case T_WEEK_AGO:
				set_tm_week_ago(d);
				break;
			case T_THIS_MONTH:
				set_tm_this_month(d);
				break;
			case T_THIS_YEAR:
				set_tm_this_year(d);
				break;
		}
		return 0;
	} else
		return -1;
}

/* static void print_time(struct tm *d)
{
	char outstr[200];
	strftime(outstr, sizeof(outstr), "%c", d);
	printf("%s\n", outstr);
} */

int ausearch_time_start(const char *da, const char *ti)
{
/* If da == NULL, use current date */
/* If ti == NULL, then use midnight 00:00:00 */
	int rc = 0;
	struct tm d, t;
	char *ret;

	if (da == NULL)
		set_tm_now(&d);
	else {
		if (lookup_and_set_time(da, &d) < 0) {
			ret = strptime(da, "%x", &d);
			if (ret == NULL) {
				fprintf(stderr,
		"Invalid start date (%s). Month, Day, and Year are required.\n",
					da);
				return 1;
			}
			if (*ret != 0) {
				fprintf(stderr,
					"Error parsing start date (%s)\n", da);
				return 1;
			}
		} else {
			int keyword=lookup_time(da);
			if (keyword == T_RECENT || keyword == T_NOW) {
				if (ti == NULL || strcmp(ti, "00:00:00") == 0)
					goto set_it;
			}
		}
	}

	if (ti != NULL) {
		char tmp_t[36];

		if (strlen(ti) <= 5) {
			snprintf(tmp_t, sizeof(tmp_t), "%s:00", ti);
		} else {
			tmp_t[0]=0;
			strncat(tmp_t, ti, sizeof(tmp_t)-1);
		}
		ret = strptime(tmp_t, "%X", &t);
		if (ret == NULL) {
			fprintf(stderr,
	"Invalid start time (%s). Hour, Minute, and Second are required.\n",
				ti);
			return 1;
		}
		if (*ret != 0) {
			fprintf(stderr, "Error parsing start time (%s)\n", ti);
			return 1;
		}
	} else
		clear_tm(&t);

	add_tm(&d, &t);
	if (d.tm_year < 104) {
		fprintf(stderr, "Error - year is %d\n", d.tm_year+1900);
		return -1;
	}
set_it:
	// printf("start is: %s\n", ctime(&start_time));
	start_time = mktime(&d);
	if (start_time == -1) {
		fprintf(stderr, "Error converting start time\n");
		rc = -1;
	}
	return rc;
}

int ausearch_time_end(const char *da, const char *ti)
{
/* If date == NULL, use current date */
/* If ti == NULL, use current time */
	int rc = 0;
	struct tm d, t;
	char *ret;

	if (da == NULL)
		set_tm_now(&d);
	else {
		if (lookup_and_set_time(da, &d) < 0) {
			ret = strptime(da, "%x", &d);
			if (ret == NULL) {
				fprintf(stderr,
		 "Invalid end date (%s). Month, Day, and Year are required.\n",
					da);
				return 1;
			}
			if (*ret != 0) {
				fprintf(stderr,
					"Error parsing end date (%s)\n", da);
				return 1;
			}
		} else {
			int keyword=lookup_time(da);
			if (keyword == T_RECENT || keyword == T_NOW) {
				if (ti == NULL || strcmp(ti, "00:00:00") == 0)
					goto set_it;
			}
			// Special case today
			if (keyword == T_TODAY) {
				set_tm_now(&d);
				if (ti == NULL || strcmp(ti, "00:00:00") == 0)
					goto set_it;
			}
		}
	}

	if (ti != NULL) {
		char tmp_t[36];

		if (strlen(ti) <= 5) {
			snprintf(tmp_t, sizeof(tmp_t), "%s:00", ti);
		} else {
			tmp_t[0]=0;
			strncat(tmp_t, ti, sizeof(tmp_t)-1);
		}
		ret = strptime(tmp_t, "%X", &t);
		if (ret == NULL) {
			fprintf(stderr,
	     "Invalid end time (%s). Hour, Minute, and Second are required.\n",
				ti);
			return 1;
		}
		if (*ret != 0) {
			fprintf(stderr, "Error parsing end time (%s)\n", ti);
			return 1;
		}
	} else {
		time_t tt = time(NULL);
		struct tm *tv = localtime(&tt);
		clear_tm(&t);
		t.tm_hour = tv->tm_hour;
		t.tm_min = tv->tm_min;
		t.tm_sec = tv->tm_sec;
		t.tm_isdst = tv->tm_isdst;

	}
	add_tm(&d, &t);
	if (d.tm_year < 104) {
		fprintf(stderr, "Error - year is %d\n", d.tm_year+1900);
		return -1;
	}
set_it:
	// printf("end is: %s\n", ctime(&end_time));
	end_time = mktime(&d);
	if (end_time == -1) {
		fprintf(stderr, "Error converting end time\n");
		rc = -1;
	}
	return rc;
}

