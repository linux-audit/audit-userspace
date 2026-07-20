/* reactions.h --
 *
 * Authors:
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#ifndef REACTIONS_HEADER
#define REACTIONS_HEADER

#include "address.h"

struct session_data;

int kill_process(pid_t pid);
int kill_session(int session);
int restricted_role(const char *acct);
int force_password_reset(const char *acct);
int lock_account(const char *acct);
int unlock_account(const char *acct);
int lock_account_timed(const char *acct, unsigned long length);
int block_ip_address(const ids_address_t *address);
int block_ip_address_timed(const ids_address_t *address,
	unsigned long length);
int unblock_ip_address(const char *addr);
int system_reboot(void);
int system_single_user(void);
int system_halt(void);
void do_reaction(unsigned int answer, const char *reason,
	const struct session_data *session);

#endif
