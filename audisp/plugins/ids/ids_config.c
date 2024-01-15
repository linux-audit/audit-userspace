/* model_bad_event.c --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>      /* O_NOFOLLOW needs gnu defined */
#include <limits.h>     /* INT_MAX */
#include <ctype.h>
#include <stdlib.h>
#include "ids_config.h"

#define CONFIG_FILE "/etc/audit/ids.conf"
extern char *audit_strsplit(char *s);


/* Local prototypes */
struct nv_pair
{
        const char *name;
        const char *value;
};

struct kw_pair
{
        const char *name;
        int (*parser)(struct nv_pair *, int, struct ids_conf *);
};

struct kw_value
{
        const char *name;
        int value;
};

struct nv_list
{
        const char *name;
        int option;
};


static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
                const char *file) __attr_access ((__write_only__, 2, 3));
static int nv_split(char *buf, struct nv_pair *nv);
static const struct kw_pair *kw_lookup(const char *val);
static int option_origin_failed_logins_threshold_parser(struct nv_pair *nv,
		int line, struct ids_conf *config);
static int option_origin_failed_logins_reaction_parser(struct nv_pair *nv,
		int line, struct ids_conf *config);
static int option_session_badness1_threshold_parser(struct nv_pair *nv,
		int line, struct ids_conf *config);
static int option_session_badness1_reaction_parser(struct nv_pair *nv,
		int line, struct ids_conf *config);
static int option_service_login_allowed_parser(struct nv_pair *nv, int line,
		struct ids_conf *config);
static int option_service_login_weight_parser(struct nv_pair *nv, int line,
		struct ids_conf *config);
static int option_root_login_allowed_parser(struct nv_pair *nv, int line,
		struct ids_conf *config);
static int option_root_login_weight_parser(struct nv_pair *nv, int line,
		struct ids_conf *config);
static int option_bad_login_weight_parser(struct nv_pair *nv, int line,
		struct ids_conf *config);

static const struct kw_value reactions[] =
{
  { "ignore", REACTION_IGNORE },
  { "log", REACTION_LOG },
  { "email", REACTION_EMAIL },
  { "term_process", REACTION_TERMINATE_PROCESS },
  { "term_session", REACTION_TERMINATE_SESSION },
  { "restrict_role", REACTION_RESTRICT_ROLE },
  { "password_reset", REACTION_PASSWORD_RESET },
  { "lock_account_timed", REACTION_LOCK_ACCOUNT_TIMED },
  { "lock_account", REACTION_LOCK_ACCOUNT },
  { "block_address_timed", REACTION_BLOCK_ADDRESS_TIMED },
  { "block_address", REACTION_BLOCK_ADDRESS },
  { "system_reboot", REACTION_SYSTEM_REBOOT },
  { "system_single_user", REACTION_SYSTEM_SINGLE_USER },
  { "system_halt", REACTION_SYSTEM_HALT },
};
#define REACTION_NAMES (sizeof(reactions)/sizeof(reactions[0]))

static const struct kw_pair keywords[] =
{
  {"option_origin_failed_logins_threshold",
				option_origin_failed_logins_threshold_parser },
  {"option_origin_failed_logins_reaction",
				option_origin_failed_logins_reaction_parser },
  {"option_session_badness1_threshold",
				option_session_badness1_threshold_parser },
  {"option_session_badness1_reaction",
				option_session_badness1_reaction_parser },
  {"option_service_login_allowed",	option_service_login_allowed_parser },
  {"option_service_login_weight",	option_service_login_weight_parser },
  {"option_root_login_allowed",		option_root_login_allowed_parser },
  {"option_root_login_weight",		option_root_login_weight_parser },
  {"option_bad_login_weight",		option_bad_login_weight_parser },
};

void reset_config(struct ids_conf *config)
{
	config->option_origin_failed_logins_threshold = 8;
	config->option_origin_failed_logins_reaction = REACTION_BLOCK_ADDRESS;
	config->option_session_badness1_threshold = 8;
	config->option_session_badness1_reaction = REACTION_TERMINATE_SESSION;
	config->option_service_login_allowed = 0;
	config->option_service_login_weight = 5;
	config->option_root_login_allowed = 0;
	config->option_root_login_weight = 5;
	config->option_bad_login_weight = 1;
}

void free_config(struct ids_conf *config __attribute__((unused)))
{
}

void dump_config(struct ids_conf *config, FILE *f)
{
	fprintf(f, "\nInternal Configuration\n");
	fprintf(f, "======================\n");
	fprintf(f, "option_origin_failed_logins_threshold: %u\n",
			config->option_origin_failed_logins_threshold);
	fprintf(f, "option_session_badness1_threshold: %u\n",
			config->option_session_badness1_threshold);
	fprintf(f, "option_service_login_allowed: %u\n",
			config->option_service_login_allowed);
	fprintf(f, "option_service_login_weight: %u\n",
			config->option_service_login_weight);
	fprintf(f, "option_root_login_allowed: %u\n",
			config->option_root_login_allowed);
	fprintf(f, "option_root_login_weight: %u\n",
			config->option_root_login_weight);
	fprintf(f, "option_bad_login_weight: %u\n",
			config->option_bad_login_weight);
}

int load_config(struct ids_conf *config)
{
	int fd, rc, mode, lineno = 1;
	struct stat st;
	FILE *f;
	char buf[160];

	reset_config(config);

	/* open the file */
	mode = O_RDONLY;
	rc = open(CONFIG_FILE, mode);
	if (rc < 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "Error opening config file (%s)",
				strerror(errno));
			return 1;
		}
		syslog(LOG_WARNING,
			"Config file %s doesn't exist, skipping", CONFIG_FILE);
		return 0;
	}
	fd = rc;

	if (fstat(fd, &st) < 0) {
		syslog(LOG_ERR, "Error fstat'ing config file (%s)",
			strerror(errno));
		close(fd);
		return 1;
	}
	if (st.st_uid != 0) {
		syslog(LOG_ERR, "Error - %s isn't owned by root",
			CONFIG_FILE);
		close(fd);
		return 1;
	}
	if ((st.st_mode & S_IWOTH) == S_IWOTH) {
		syslog(LOG_ERR, "Error - %s is world writable",
			CONFIG_FILE);
		close(fd);
		return 1;
	}
	if (!S_ISREG(st.st_mode)) {
		syslog(LOG_ERR, "Error - %s is not a regular file",
			CONFIG_FILE);
		close(fd);
		return 1;
	}

	/* it's ok, read line by line */
	f = fdopen(fd, "rm");
	if (f == NULL) {
		syslog(LOG_ERR, "Error - fdopen failed (%s)",
			strerror(errno));
		close(fd);
		return 1;
	}

	while (get_line(f, buf, sizeof(buf), &lineno, CONFIG_FILE)) {
		// convert line into name-value pair
		const struct kw_pair *kw;
		struct nv_pair nv;
		rc = nv_split(buf, &nv);
		switch (rc) {
			case 0: // fine
				break;
			case 1: // not the right number of tokens.
				syslog(LOG_ERR,
				"Wrong number of arguments for line %d in %s",
					lineno, CONFIG_FILE);
				break;
			case 2: // no '=' sign
				syslog(LOG_ERR,
					"Missing equal sign for line %d in %s",
					lineno, CONFIG_FILE);
				break;
			default: // something else went wrong...
				syslog(LOG_ERR,
					"Unknown error for line %d in %s",
					lineno, CONFIG_FILE);
				break;
		}
		if (nv.name == NULL) {
			lineno++;
			continue;
		}
		if (nv.value == NULL) {
			fclose(f);
			syslog(LOG_ERR,
				"Not processing any more lines in %s",
				CONFIG_FILE);
			return 1;
		}

		/* identify keyword or error */
		kw = kw_lookup(nv.name);
		if (kw->name == NULL) {
			syslog(LOG_ERR,
				"Unknown keyword \"%s\" in line %d of %s",
				nv.name, lineno, CONFIG_FILE);
			fclose(f);
			return 1;
		}

		/* dispatch to keyword's local parser */
		rc = kw->parser(&nv, lineno, config);
		if (rc != 0) {
			fclose(f);
			return 1; // local parser puts message out
		}
		lineno++;
	}

	fclose(f);
//	if (lineno > 1)
//		return sanity_check(config);
	return 0;
}

static char *get_line(FILE *f, char *buf, unsigned size, int *lineno,
	const char *file)
{
	int too_long = 0;

	while (fgets_unlocked(buf, size, f)) {
		 /* remove newline */
		char *ptr = strchr(buf, 0x0a);
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
				syslog(LOG_ERR,
					"Skipping line %d in %s: too long",
					*lineno, file);
			too_long = 1;
		}
	}
	return NULL;
}

static int nv_split(char *buf, struct nv_pair *nv)
{
	/* Get the name part */
	char *ptr;

	nv->name = NULL;
	nv->value = NULL;
	ptr = audit_strsplit(buf);
	if (ptr == NULL)
		return 0; /* If there's nothing, go to next line */
	if (ptr[0] == '#')
		return 0; /* If there's a comment, go to next line */
	nv->name = ptr;

	/* Check for a '=' */
	ptr = audit_strsplit(NULL);
	if (ptr == NULL)
		return 1;
	if (strcmp(ptr, "=") != 0)
		return 2;

	/* get the value */
	ptr = audit_strsplit(NULL);
	if (ptr == NULL)
		return 1;
	nv->value = ptr;

	/* See if there's more */
	ptr = audit_strsplit(NULL);
	if (ptr)
		return 1;

	/* Everything is OK */
	return 0;
}

static const struct kw_pair *kw_lookup(const char *val)
{
	int i = 0;
	while (keywords[i].name != NULL) {
		if (strcasecmp(keywords[i].name, val) == 0)
			break;
		i++;
	}
	return &keywords[i];
}

static int unsigned_int_parser(struct nv_pair *nv, int line, unsigned int *val)
{
	const char *ptr = nv->value;
	unsigned long i;

	/* check that all chars are numbers */
	for (i=0; ptr[i]; i++) {
		if (!isdigit((unsigned char)ptr[i])) {
			syslog(LOG_ERR,
				"Value %s should only be numbers - line %d",
				nv->value, line);
			return 1;
		}
	}

	/* convert to unsigned int */
	errno = 0;
	i = strtoul(nv->value, NULL, 10);
	if (errno) {
		syslog(LOG_ERR,
			"Error converting string to a number (%s) - line %d",
			strerror(errno), line);
		return 1;
	}

	/* Check its range */
	if (i > INT_MAX) {
		syslog(LOG_ERR,
			"Error - converted number (%s) is too large - line %d",
			nv->value, line);
		return 1;
	}

	*val = (unsigned int)i;
	return 0;
}

static int reaction_parser(struct nv_pair *nv, int line, unsigned int *val)
{
	unsigned int i, found = 0;
	char *ptr, *tmp = strdup(nv->value), *saved;
	if (tmp == NULL)
		return 1;

	*val = 0;
	ptr = strtok_r(tmp, ",", &saved);
	while (ptr) {
		for (i = 0; i < REACTION_NAMES; i++) {
			if (strcasecmp(reactions[i].name, ptr) == 0) {
				*val |= (unsigned int)reactions[i].value;
				found = 1;
			}
		}
		ptr = strtok_r(NULL, ",", &saved);
	}
	free(tmp);
	if (found)
		return 0;

	syslog(LOG_ERR, "Option %s not found - line %d", nv->value, line);
	return 1;
}

static int option_origin_failed_logins_threshold_parser(struct nv_pair *nv,
	int line, struct ids_conf *config)
{
	return unsigned_int_parser(nv, line,
		&config->option_origin_failed_logins_threshold);
}

static int option_origin_failed_logins_reaction_parser(struct nv_pair *nv,
	int line, struct ids_conf *config)
{
	return reaction_parser(nv, line,
		&config->option_origin_failed_logins_reaction);
}

static int option_session_badness1_threshold_parser(struct nv_pair *nv,
		int line, struct ids_conf *config)
{
	return unsigned_int_parser(nv, line,
		&config->option_session_badness1_threshold);
}

static int option_session_badness1_reaction_parser(struct nv_pair *nv,
		int line, struct ids_conf *config)
{
	return reaction_parser(nv, line,
		&config->option_session_badness1_reaction);
}

static int option_service_login_allowed_parser(struct nv_pair *nv, int line,
                struct ids_conf *config)
{
	return unsigned_int_parser(nv, line,
		&config->option_service_login_allowed);
}

static int option_service_login_weight_parser(struct nv_pair *nv, int line,
                struct ids_conf *config)
{
	return unsigned_int_parser(nv, line,
		&config->option_service_login_weight);
}

static int option_root_login_allowed_parser(struct nv_pair *nv, int line,
                struct ids_conf *config)
{
	return unsigned_int_parser(nv, line,
		&config->option_root_login_allowed);
}

static int option_root_login_weight_parser(struct nv_pair *nv, int line,
                struct ids_conf *config)
{
	return unsigned_int_parser(nv, line,
		&config->option_root_login_weight);
}

static int option_bad_login_weight_parser(struct nv_pair *nv, int line,
                struct ids_conf *config)
{
	return unsigned_int_parser(nv, line,
		&config->option_bad_login_weight);
}

