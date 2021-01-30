/* model_bad_event.c --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include "config.h"
#include <arpa/inet.h> // inet_pton
#include <libaudit.h>
#include <string.h>
#include "ids.h"
#include "session.h"
#include "origin.h"
#include "model_bad_event.h"


/* Local Data */


static void terminate_sessions(void)
{
	if (get_num_sessions() == 0)
		return;

	if (debug)
		my_printf("terminating all sessions");
	// Might want to do more than this like update persistent scores
	destroy_sessions();
}

static void start_session(auparse_state_t *au, struct ids_conf *config)
{
	unsigned int a;
	const char *addr = auparse_find_field(au, "addr");
	if (addr && *addr != '?')
		inet_pton(AF_INET, addr, &a);
	else
		a = -1;

	if (auparse_normalize_get_results(au) == 1) {
		// Handle a bad login
		const char *res = auparse_interpret_field(au);
		if (res && strcmp(res, "failed") == 0) {
			int service_acct = 0;
			const char *acct = NULL;
			const char *atype = auparse_normalize_subject_kind(au);
			if (atype && strncmp(atype, "service", 7) == 0)
				service_acct = 1;
			if (auparse_normalize_subject_primary(au) == 1)
				acct = auparse_interpret_field(au);

			origin_data_t *o = find_origin(a);
			if (o == NULL)
				o = new_origin(a);
			if(service_acct &&
					!config->option_service_login_allowed)
				bad_service_login_origin(o, config, acct);
			else if (!config->option_root_login_allowed && acct && 
						strcmp(acct, "root") == 0)
				watched_login_origin(o, config, acct);
			else
				bad_login_origin(o, config);
			return;
		}
	}
	if (auparse_normalize_session(au) == 1) {
		const char *ses = auparse_get_field_str(au);
		if (ses) {
			if (strcmp(ses, DAEMON_SESSION)) {
				unsigned int s = auparse_get_field_int(au);
				if (auparse_normalize_subject_primary(au) == 1){
					new_session(s, a, strdup(
						auparse_interpret_field(au)));
				}
			} // else we have a strange daemon login
		} else if (debug)
		     my_printf("start_session: can't find session in serial %lu",
				auparse_get_serial(au));
	}
}

static void end_session(auparse_state_t *au)
{
	if (auparse_normalize_session(au) == 1) {
		const char *ses = auparse_get_field_str(au);
		if (ses && strcmp(ses, DAEMON_SESSION)) {
			unsigned int s = auparse_get_field_int(au);
			del_session(s);
		}
	}
}

/* This function receives a single complete event from the auparse library. */
unsigned int process_bad_event_model(auparse_state_t *au,
	struct ids_conf *config)
{
	unsigned int answer = 0;
	auparse_first_record(au);
	int type = auparse_get_type(au);

	/* Now we can branch based on what the first record type we find. */
	switch (type) {
		case AUDIT_SYSTEM_BOOT:
		case AUDIT_SYSTEM_SHUTDOWN:
			// Reset everything
			terminate_sessions();
			break;
		// FIXME: update this list as events are added
		case AUDIT_ANOM_LOGIN_SERVICE:
		case AUDIT_ANOM_LOGIN_ACCT:
			// Do not process our own events
			break;
		case AUDIT_ANOM_LOGIN_FAILURES:
		{
			// Do not process our own events
			const char *exe = auparse_normalize_how(au);
			if (exe && strcmp(exe, "ids") == 0)
				break;
		}
			// fallthrough if pam related
		case AUDIT_ANOM_LOGIN_TIME:
		case AUDIT_ANOM_LOGIN_SESSIONS:
		case AUDIT_ANOM_LOGIN_LOCATION:
			// watch for pam discovered problems
			break;
		case AUDIT_USER_LOGIN:
			start_session(au, config);
			break;
//		case AUDIT_USER_END: user_end can be for su
		case AUDIT_USER_LOGOUT:
			end_session(au);
			break;
		default:
			break;
	}

	// We only mess with origins because it could be a bad login
	origin_data_t *o = current_origin();
	if (o) {
		if (o->karma >= config->option_origin_failed_logins_threshold &&
							!o->blocked)
			answer |= config->option_origin_failed_logins_reaction;
	}
	return answer;
}

