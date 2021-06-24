/* model_behavior.c --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <libaudit.h>
#include <string.h>
#include "ids.h"
#include "session.h"
#include "origin.h"
#include "model_behavior.h"
#include "reactions.h"

/* Local Data */


static void process_plain_syscalls(auparse_state_t *au)
{
	if (auparse_normalize_key(au) == 1) {
		uint32_t s = -2;
		const char *key = auparse_interpret_field(au);
		// If its a key we don't care about, skip it.
		if (strncmp(key, "ids-", 4))
			return;
		if (auparse_normalize_session(au) == 1) {
			const char *ses = auparse_get_field_str(au);
			if (ses && strcmp(ses, DAEMON_SESSION))
				s = auparse_get_field_int(au);
		}

		// For now, do not process daemon events
		if ((int32_t)s < 0)
			return;

		session_data_t *sess = find_session(s);
		if (sess) {
			if (strcmp(key, "ids-recon") == 0) {
				add_to_score_session(sess, 2);
			} else if (strcmp(key, "ids-archive") == 0) {
				add_to_score_session(sess, 5);
			} else if (strcmp(key, "ids-mkexec") == 0) {
				add_to_score_session(sess, 4);
			} else if (strcmp(key, "ids-connections") == 0) {
				add_to_score_session(sess, 6);
			}
		}
	}
}

static void process_anomalies(auparse_state_t *au)
{
	if (auparse_normalize_session(au) == 1) {
		const char *ses = auparse_get_field_str(au);
		if (ses && strcmp(ses, DAEMON_SESSION)) {
			unsigned int s = auparse_get_field_int(au);

			session_data_t *sess = find_session(s);
			if (sess) {
				auparse_first_record(au);
				int type = auparse_get_type(au);
				if (type == AUDIT_FANOTIFY)
					add_to_score_session(sess, 12);
				else
					add_to_score_session(sess, 2);
			}
		}
	}
}

/* This function receives a single complete event from the auparse library. */
void process_behavior_model(auparse_state_t *au, struct ids_conf *config)
{
	unsigned int answer = 0;
	auparse_first_record(au);
	int type = auparse_get_type(au);

	/* Now we can branch based on what the first record type we find. */
	switch (type) {
		case AUDIT_SYSCALL:
			process_plain_syscalls(au);
			break;
		//case SECCOMP:
		case AUDIT_FANOTIFY:
		case AUDIT_AVC:
		case AUDIT_ANOM_PROMISCUOUS:
		case AUDIT_ANOM_ABEND:
		case AUDIT_ANOM_LINK:
			// Handle these by looking for session. If
			// not in a session handle by process
			process_anomalies(au);
			break;
		case AUDIT_USER_MGMT:
		case AUDIT_ADD_USER:
		case AUDIT_DEL_USER:
		case AUDIT_ADD_GROUP:
		case AUDIT_DEL_GROUP:
		case AUDIT_GRP_MGMT:
			break;
		case AUDIT_USER_AUTH:
		case AUDIT_USER_ACCT:
		case AUDIT_GRP_AUTH:
			// watch for failures in auth
			break;
		default:
			break;
	}

	origin_data_t *o = current_origin();
	session_data_t *s = current_session();

	if (o && s) {
		if (s->score >= config->option_session_badness1_threshold &&
							s->killed == 0) {
			//AUDIT_ANOM_SESSION
			answer |= config->option_session_badness1_reaction;
			do_reaction(answer, "session_bad");
			if (s->killed >= 1)
				add_to_score_origin(o, 5);
			else
				add_to_score_origin(o, 2);
		}
	}

	if (o && o->karma >= config->option_origin_failed_logins_threshold &&
							!o->blocked) {
		//AUDIT_ANOM_ORIGIN_FAILURES
		answer |= config->option_origin_failed_logins_reaction;
			do_reaction(answer, "failed_login");
	}
}

