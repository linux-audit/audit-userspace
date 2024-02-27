/* audisp-filter.c --
 * Copyright 2024 Red Hat Inc.
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
 *   Attila Lakatos <alakatos@redhat.com>
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>

#include "config.h"
#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif
#include "auparse.h"
#include "common.h"
#include "libaudit.h"

struct filter_rule {
	char* expr;
	int lineno;
	struct filter_rule* next;
};

struct filter_list {
	struct filter_rule* head;
	struct filter_rule* tail;
};

enum {
	ALLOWLIST,
	BLOCKLIST
};

struct filter_conf {
	int mode; /* allowlist or blocklist */
	const char* binary; /* external program that will receive filter audit events */
	char** binary_args; /* arguments for external program */
	const char* config_file; /* file containing audit expressions */
	int only_check; /* just verify the syntax of the config_file and exit */
};

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static int pipefd[2];
static int errors = 0;
static struct filter_list list;
pid_t cpid = -1;

static struct filter_conf config = {
	.mode = -1,
	.binary = NULL,
	.binary_args = NULL,
	.config_file = NULL,
	.only_check = 0
};

static void handle_event(auparse_state_t* au, auparse_cb_event_t cb_event_type,
	void* user_data) {
	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	int rc, forward_event;

	// Determine whether to forward or drop the event
	rc = ausearch_cur_event(au);
	if (rc > 0) { /* matched */
		forward_event = (config.mode == ALLOWLIST) ? 0 : 1;
	} else if (rc == 0) { /* not matched */
		forward_event = (config.mode == ALLOWLIST) ? 1 : 0;
	} else {
		syslog(LOG_ERR, "The ausearch_next_event returned %d", rc);
		return;
	}

	if (forward_event) {
		const int records = auparse_get_num_records(au);
		for (int i = 0; i < records; i++) {
			const char* txt = auparse_get_record_text(au);

			// Need to add new line character to signal end of the current record
			if (write(pipefd[1], txt, strlen(txt)) == -1 || write(pipefd[1], "\n", 1) == -1) {
				syslog(LOG_ERR, "Failed to write to pipe");
				return;
			}
		}
	}
}

static void free_args() {
	if (config.binary_args) {
		for (int i = 0; config.binary_args[i] != NULL; i++) {
			free(config.binary_args[i]);
		}
		free(config.binary_args);
	}
}

static int parse_args(int argc, const char* argv[]) {
	if (argc == 3 && (strcmp("--check", argv[1]) == 0)) {
		config.config_file = argv[2];
		config.only_check = 1;
		return 0;
	}

	if (argc <= 3) {
		syslog(LOG_ERR, "Not enough command line arguments");
		return 1;
	}

	if (strcasecmp(argv[1], "allowlist") == 0)
		config.mode = ALLOWLIST;
	else if (strcasecmp(argv[1], "blocklist") == 0)
		config.mode = BLOCKLIST;
	else {
		syslog(LOG_ERR,
			"Invalid mode '%s' specified, possible values are: allowlist, "
			"blocklist.",
			argv[1]);
		return 1;
	}

	config.config_file = argv[2];
	config.binary = argv[3];

	argc -= 3;
	argv += 3;

	config.binary_args = malloc(sizeof(char*) * (argc + 1)); /* +1 is for the last NULL */
	if (!config.binary_args)
		return 1;

	for (int i = 0; i < argc; i++) {
		config.binary_args[i] = strdup(argv[i]);
		if (!config.binary_args[i]) {
			while (i > 0) {
				free(config.binary_args[--i]);
			}
			free(config.binary_args);
			return 1;
		}
	}
	config.binary_args[argc] = NULL;

	return 0;
}

static char* get_line(FILE* f, char* buf, unsigned size, int* lineno,
	const char* file) {
	int too_long = 0;

	while (fgets_unlocked(buf, size, f)) {
		/* remove newline */
		char* ptr = strchr(buf, 0x0a);
		if (ptr) {
			if (!too_long) {
				*ptr = 0;
				return buf;
			}
			// Reset and start with the next line
			too_long = 0;
			*lineno = *lineno + 1;
		} else {
			// If a line is too long skip it.
			// Only output 1 warning
			if (!too_long)
				syslog(LOG_WARNING, "Skipping line %d in %s: too long", *lineno, file);
			too_long = 1;
		}
	}
	return NULL;
}

// static void print_rules(struct filter_list* list) {
// 	struct filter_rule* rule;
// 	int count = 0;
//
// 	for (rule = list->head; rule != NULL; rule = rule->next, count++) {
// 		printf("Rule %d on line %d: %s\n", count, rule->lineno, rule->expr);
// 	}
// }

static void reset_rules(struct filter_list* list) {
	list->head = list->tail = NULL;
}

static void free_rule(struct filter_rule* rule) { free(rule->expr); }

static void free_rules(struct filter_list* list) {
	struct filter_rule* current = list->head, * to_delete;
	while (current != NULL) {
		to_delete = current;
		current = current->next;
		free_rule(to_delete);
		free(to_delete);
	}
}

static void append_rule(struct filter_list* list, struct filter_rule* rule) {
	if (list->head == NULL) {
		list->head = list->tail = rule;
	} else {
		list->tail->next = rule;
		list->tail = rule;
	}
}

static struct filter_rule* parse_line(char* line, int lineno) {
	struct filter_rule* rule;
	auparse_state_t* au;
	const char* buf[] = { NULL };
	char* error = NULL;

	/* dummy instance of the audit parsing library, we use it to
	validate search expressions that will be added to the filter engine */
	if ((au = auparse_init(AUSOURCE_BUFFER_ARRAY, buf)) == NULL) {
		syslog(LOG_ERR, "The auparse_init failed");
		return NULL;
	}

	// Skip whitespace
	while (*line == ' ')
		line++;

	// Empty line or it's a comment
	if (!*line || *line == '#') {
		auparse_destroy(au);
		return NULL;
	}

	if ((rule = malloc(sizeof(struct filter_rule))) == NULL) {
		auparse_destroy(au);
		return NULL;
	}
	rule->lineno = lineno;
	rule->next = NULL;

	if ((rule->expr = strdup(line)) == NULL) {
		auparse_destroy(au);
		free(rule);
		return NULL;
	}

	if (ausearch_add_expression(au, rule->expr, &error, AUSEARCH_RULE_OR) != 0) {
		syslog(LOG_ERR, "Invalid expression: %s (%s)", rule->expr, error);
		free_rule(rule);
		free(rule);
		rule = NULL;
		errors++;
	}

	auparse_destroy(au);
	return rule;
}

/*
 * Load rules from config into our linked list
 */
static int load_rules(struct filter_list* list) {
	int fd, lineno = 0;
	struct stat st;
	char buf[1024];
	FILE* f;

	reset_rules(list);
	errors = 0;

	/* open the file */
	if ((fd = open(config.config_file, O_RDONLY)) < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "Error opening config file (%s)", strerror(errno));
			return 1;
		}
		syslog(LOG_ERR, "Config file %s doesn't exist, skipping",
			config.config_file);
		return 1;
	}

	if (fstat(fd, &st) < 0) {
		syslog(LOG_ERR, "Error fstat'ing config file (%s)", strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		syslog(LOG_ERR, "Error - %s isn't owned by root", config.config_file);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		syslog(LOG_ERR, "Error - %s is world writable", config.config_file);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		syslog(LOG_ERR, "Error - %s is not a regular file", config.config_file);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		syslog(LOG_ERR, "Error - fdopen failed (%s)", strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf, sizeof(buf), &lineno, config.config_file)) {
		lineno++;
		struct filter_rule* rule;
		if ((rule = parse_line(buf, lineno)) == NULL)
			continue;

		append_rule(list, rule);
	}
	fclose(f);

	return errors;
}

/*
 * SIGCHLD handler: reap exiting processes
 */
static void child_handler(int sig) {
	while (waitpid(-1, NULL, WNOHANG) > 0)
		; /* empty */
	stop = 1;
}

/*
 * SIGTERM handler
 */
static void term_handler(int sig) {
	kill(cpid, sig);
	stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig) {
	kill(cpid, sig);
	hup = 1;
}

static void reload_config(void) {
	hup = 0;
	struct filter_list new_list;

	/* load new rules */
	if (load_rules(&new_list)) {
		syslog(LOG_INFO, "The rules were not reloaded because of a syntax error");
		free_rules(&new_list);
		return;
	}

	/* remove unused previous rules */
	free_rules(&list);
	list = new_list;
	syslog(LOG_INFO, "Successfully reloaded rules");
}

int main(int argc, const char* argv[]) {
	auparse_state_t* au = NULL;
	struct sigaction sa;
	char buffer[MAX_AUDIT_MESSAGE_LENGTH];

	/* validate args */
	if (parse_args(argc, argv))
		return 1;

	/* create a list of rules from config file */
	if (load_rules(&list)) {
		free_rules(&list);
		free_args();
		return 1;
	}

	/* validate the ruleset and exit */
	if (config.only_check) {
		free_rules(&list);
		free_args();
		return 0;
	}

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);

#ifdef HAVE_LIBCAP_NG
	// Drop capabilities
	capng_clear(CAPNG_SELECT_BOTH);
	if (capng_apply(CAPNG_SELECT_BOTH))
		syslog(LOG_WARNING,
			"%s: unable to drop capabilities, continuing with "
			"elevated privileges",
			argv[0]);
#endif

	if (pipe(pipefd) == -1) {
		syslog(LOG_ERR, "%s: unable to open a pipe (%s)",
			argv[0], strerror(errno));
		return -1;
	}

	cpid = fork();
	if (cpid == -1) {
		syslog(LOG_ERR, "%s: unable to create fork (%s)", argv[0], strerror(errno));
		return -1;
	}

	if (cpid == 0) {
		/* Child reads filtered input*/

		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);

		execve(config.binary, config.binary_args, NULL);
		syslog(LOG_ERR, "%s: execve failed (%s)", argv[0], strerror(errno));
		exit(1);
	} else {
		/* Parent reads input and forwards data after filters have been applied
		 */
		close(pipefd[0]);

		au = auparse_init(AUSOURCE_FEED, 0);
		if (au == NULL) {
			syslog(LOG_ERR, "%s: failed to initialize auparse data feed", argv[0]);
			kill(cpid, SIGTERM);
			return -1;
		}

		auparse_set_eoe_timeout(2);
		auparse_add_callback(au, handle_event, NULL, NULL);
		ausearch_set_stop(au, AUSEARCH_STOP_EVENT);

		// add rules(expressions) to the ausearch engine
		for (struct filter_rule* rule = list.head; rule != NULL; rule = rule->next) {
			char* error = NULL;
			int rc = ausearch_add_expression(au, rule->expr, &error, AUSEARCH_RULE_OR);
			if (rc != 0) {
				/* this should not happen because rules were pre-tested in parse_line() */
				syslog(LOG_ERR, "Failed to add expression '%s' to ausearch (%s)",
					rule->expr, error);
			}
			free(error);
		}

		do {
			fd_set read_mask;
			int retval;
			int read_size = 1; /* Set to 1 so it's not EOF */

			/* Load configuration */
			if (hup) {
				reload_config();
			}
			do {
				FD_ZERO(&read_mask);
				FD_SET(0, &read_mask);

				if (auparse_feed_has_data(au)) {
					struct timeval tv;
					tv.tv_sec = 1;
					tv.tv_usec = 0;
					retval = select(1, &read_mask, NULL, NULL, &tv);
				} else
					retval = select(1, &read_mask, NULL, NULL, NULL);

				/* If we timed out & have events, shake them loose */
				if (retval == 0 && auparse_feed_has_data(au))
					auparse_feed_age_events(au);
			} while (retval == -1 && errno == EINTR && !hup && !stop);

			/* Now the event loop */
			if (!stop && !hup && retval > 0) {
				while ((read_size = read(0, buffer, MAX_AUDIT_MESSAGE_LENGTH)) > 0) {
					auparse_feed(au, buffer, read_size);
				}
			}
			if (read_size == 0) /* EOF */
				break;
		} while (stop == 0);

		auparse_flush_feed(au);
		ausearch_clear(au);
		auparse_destroy(au);
	}

	free_rules(&list);
	free_args();
	return 0;
}
