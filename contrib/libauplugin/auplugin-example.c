/* auplugin-example.c --
 * Copyright 2025 Red Hat Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 * This is a sample program showing how to write an audisp plugin using
 * the libauplugin helper library.  It is functionally equivalent to the
 * contrib/plugin/audisp-example.c program but avoids manual queue and
 * event management by delegating that work to libauplugin.
 *
 * To test with a file of raw audit records, generate the file with:
 *   ausearch --start today --raw > test.log
 * and then run:
 *   cat test.log | ./auplugin-example
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <auplugin.h>

/* Global Data */
static volatile sig_atomic_t stop = 0;
static volatile sig_atomic_t hup = 0;

/* Local declarations */
static void handle_event(auparse_state_t *au,
                        auparse_cb_event_t cb_event_type,
			void *user_data __attribute__((unused)));

/*
 * SIGTERM handler
 *
 * Only honor the signal if it comes from the parent process so that other
 * tasks (for example systemctl) cannot make the plugin exit without the
 * dispatcher in agreement.  The handler also stops the libauplugin worker
 * thread so that auplugin_event_feed returns.
 */
static void term_handler(int sig __attribute__((unused)), siginfo_t *info,
			 void *ucontext __attribute__((unused)))
{
        if (info && info->si_pid != getppid())
                return;
        stop = 1;
        auplugin_stop();
}

/*
 * SIGHUP handler: request configuration reload.
 */
static void hup_handler(int sig __attribute__((unused)))
{
        hup = 1;
}

static void reload_config(void)
{
        hup = 0;
        /*
         * Add your code here that re-reads the config file and changes
         * how your plugin works.
         */
}

int main(int argc, char *argv[])
{
        struct sigaction sa;

        /* Register signal handlers expected by auditd plugins */
        sa.sa_flags = 0;
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = hup_handler;
        sigaction(SIGHUP, &sa, NULL);
        sa.sa_sigaction = term_handler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGTERM, &sa, NULL);

        /*
         * Initialize libauplugin.
         *  - inbound_fd: 0 (read events from stdin)
         *  - queue_size: 128 events kept in memory
         *  - q_flags:    AUPLUGIN_Q_IN_MEMORY for an in-memory queue
         *  - path:       unused here
         */
        if (auplugin_init(0, 128, AUPLUGIN_Q_IN_MEMORY, NULL)) {
                fprintf(stderr, "failed to init auplugin\n");
                return 1;
        }

        /*
         * Feed events to libauparse.  The callback will be invoked for each
         * complete event.  The timer flushes aged events every second.
         */
        if (auplugin_event_feed(handle_event, 1, NULL)) {
                fprintf(stderr, "failed to start event feed\n");
                return 1;
        }

        if (stop)
                printf("audisp-example-auplugin is exiting on stop request\n");
        else
                printf("audisp-example-auplugin is exiting on stdin EOF\n");

        return 0;
}

/* Helper: dump a whole event by iterating over records */
static void dump_whole_event(auparse_state_t *au)
{
        auparse_first_record(au);
        do {
                printf("%s\n", auparse_get_record_text(au));
        } while (auparse_next_record(au) > 0);
        printf("\n");
}

/* Helper: dump a single record's text */
static void dump_whole_record(auparse_state_t *au)
{
        printf("%s: %s\n", audit_msg_type_to_name(auparse_get_type(au)),
               auparse_get_record_text(au));
        printf("\n");
}

/* Helper: iterate through the fields of a record and print details */
static void dump_fields_of_record(auparse_state_t *au)
{
        printf("record type %d(%s) has %d fields\n", auparse_get_type(au),
               audit_msg_type_to_name(auparse_get_type(au)),
               auparse_get_num_fields(au));

        printf("line=%d file=%s\n", auparse_get_line_number(au),
               auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");

        const au_event_t *e = auparse_get_timestamp(au);
        if (e == NULL) {
                printf("Error getting timestamp - aborting\n");
                return;
        }
        /* e->sec may be treated as time_t for human readable output */
        printf("event time: %u.%u:%lu, host=%s\n", (unsigned)e->sec,
               e->milli, e->serial, e->host ? e->host : "?");
        auparse_first_field(au);

        do {
                printf("field: %s=%s (%s)\n",
                       auparse_get_field_name(au),
                       auparse_get_field_str(au),
                       auparse_interpret_field(au));
        } while (auparse_next_field(au) > 0);
        printf("\n");
}

/*
 * Callback from auplugin_event_feed.  We receive a completed event and can
 * inspect it using libauparse APIs.  This is where plugin specific logic
 * would normally be implemented.
 */
static void handle_event(auparse_state_t *au,
                        auparse_cb_event_t cb_event_type, void *user_data)
{
        int type, num = 0;

        /* Process any pending signal requests */
        if (hup)
                reload_config();

        /* Iterate over records in the event looking for ones to process */
        while (auparse_goto_record_num(au, num) > 0) {
                type = auparse_get_type(au);
                switch (type) {
                case AUDIT_AVC:
                        dump_fields_of_record(au);
                        break;
                case AUDIT_SYSCALL:
                        dump_whole_record(au);
                        break;
                case AUDIT_MAC_STATUS:
                        dump_whole_event(au);
                        break;
                default:
                        break;
                }
                num++;
        }
}

