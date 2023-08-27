/* audit-records.h --
 * Copyright 2023 Red Hat Inc.
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

#ifndef _AUDIT_RECORDS_H
#define _AUDIT_RECORDS_H

#include <linux/audit.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Audit message types as of 5.0 kernel:
 * 1000 - 1099 are for commanding the audit system
 * 1100 - 1199 user space trusted application messages
 * 1200 - 1299 messages internal to the audit daemon
 * 1300 - 1399 audit event messages
 * 1400 - 1499 kernel SE Linux use
 * 1500 - 1599 AppArmor events
 * 1600 - 1699 kernel crypto events
 * 1700 - 1799 kernel anomaly records
 * 1800 - 1899 kernel integrity labels and related events
 * 1800 - 1999 future kernel use
 * 2001 - 2099 unused (kernel)
 * 2100 - 2199 user space anomaly records
 * 2200 - 2299 user space actions taken in response to anomalies
 * 2300 - 2399 user space generated LSPP events
 * 2400 - 2499 user space crypto events
 * 2500 - 2599 user space virtualization management events
 * 2600 - 2999 future user space (maybe integrity labels and related events)
 */

#define AUDIT_FIRST_USER_MSG    1100    /* First user space message */
#define AUDIT_LAST_USER_MSG     1199    /* Last user space message */
#define AUDIT_USER_AUTH         1100    /* User system access authentication */
#define AUDIT_USER_ACCT         1101    /* User system access authorization */
#define AUDIT_USER_MGMT         1102    /* User acct attribute change */
#define AUDIT_CRED_ACQ          1103    /* User credential acquired */
#define AUDIT_CRED_DISP         1104    /* User credential disposed */
#define AUDIT_USER_START        1105    /* User session start */
#define AUDIT_USER_END          1106    /* User session end */
#define AUDIT_USER_AVC          1107    /* User space avc message */
#define AUDIT_USER_CHAUTHTOK    1108    /* User acct password or pin changed */
#define AUDIT_USER_ERR          1109    /* User acct state error */
#define AUDIT_CRED_REFR         1110    /* User credential refreshed */
#define AUDIT_USYS_CONFIG       1111    /* User space system config change */
#define AUDIT_USER_LOGIN        1112    /* User has logged in */
#define AUDIT_USER_LOGOUT       1113    /* User has logged out */
#define AUDIT_ADD_USER          1114    /* User account added */
#define AUDIT_DEL_USER          1115    /* User account deleted */
#define AUDIT_ADD_GROUP         1116    /* Group account added */
#define AUDIT_DEL_GROUP         1117    /* Group account deleted */
#define AUDIT_DAC_CHECK         1118    /* User space DAC check results */
#define AUDIT_CHGRP_ID          1119    /* User space group ID changed */
#define AUDIT_TEST              1120    /* Used for test success messages */
#define AUDIT_TRUSTED_APP       1121    /* Trusted app msg - freestyle text */
#define AUDIT_USER_SELINUX_ERR  1122    /* SE Linux user space error */
#define AUDIT_USER_CMD          1123    /* User shell command and args */
#define AUDIT_USER_TTY          1124    /* Non-ICANON TTY input meaning */
#define AUDIT_CHUSER_ID         1125    /* Changed user ID supplemental data */
#define AUDIT_GRP_AUTH          1126    /* Authentication for group password */
#define AUDIT_SYSTEM_BOOT       1127    /* System boot */
#define AUDIT_SYSTEM_SHUTDOWN   1128    /* System shutdown */
#define AUDIT_SYSTEM_RUNLEVEL   1129    /* System runlevel change */
#define AUDIT_SERVICE_START     1130    /* Service (daemon) start */
#define AUDIT_SERVICE_STOP      1131    /* Service (daemon) stop */
#define AUDIT_GRP_MGMT          1132    /* Group account attr was modified */
#define AUDIT_GRP_CHAUTHTOK     1133    /* Group acct password or pin changed */
#define AUDIT_MAC_CHECK         1134    /* User space MAC decision results */
#define AUDIT_ACCT_LOCK         1135    /* User's account locked by admin */
#define AUDIT_ACCT_UNLOCK       1136    /* User's account unlocked by admin */
#define AUDIT_USER_DEVICE       1137    /* User space hotplug device changes */
#define AUDIT_SOFTWARE_UPDATE   1138    /* Software update event */

#define AUDIT_FIRST_DAEMON      1200
#define AUDIT_LAST_DAEMON       1299
#define AUDIT_DAEMON_RECONFIG   1204    /* Auditd should reconfigure */
#define AUDIT_DAEMON_ROTATE     1205    /* Auditd should rotate logs */
#define AUDIT_DAEMON_RESUME     1206    /* Auditd should resume logging */
#define AUDIT_DAEMON_ACCEPT     1207    /* Auditd accepted remote connection */
#define AUDIT_DAEMON_CLOSE      1208    /* Auditd closed remote connection */
#define AUDIT_DAEMON_ERR        1209    /* Auditd internal error */

#define AUDIT_FIRST_EVENT       1300
#define AUDIT_LAST_EVENT        1399

#define AUDIT_FIRST_SELINUX     1400
#define AUDIT_LAST_SELINUX      1499

#define AUDIT_FIRST_APPARMOR            1500
#define AUDIT_LAST_APPARMOR             1599
#ifndef AUDIT_AA
#define AUDIT_AA                        1500    /* Not upstream yet */
#define AUDIT_APPARMOR_AUDIT            1501
#define AUDIT_APPARMOR_ALLOWED          1502
#define AUDIT_APPARMOR_DENIED           1503
#define AUDIT_APPARMOR_HINT             1504
#define AUDIT_APPARMOR_STATUS           1505
#define AUDIT_APPARMOR_ERROR            1506
#define AUDIT_APPARMOR_KILL             1507
#endif

#define AUDIT_FIRST_KERN_CRYPTO_MSG     1600
#define AUDIT_LAST_KERN_CRYPTO_MSG      1699

#define AUDIT_FIRST_KERN_ANOM_MSG       1700
#define AUDIT_LAST_KERN_ANOM_MSG        1799

#define AUDIT_INTEGRITY_FIRST_MSG       1800
#define AUDIT_INTEGRITY_LAST_MSG        1899
#ifndef AUDIT_INTEGRITY_DATA
#define AUDIT_INTEGRITY_DATA            1800 /* Data integrity verification */
#define AUDIT_INTEGRITY_METADATA        1801 // Metadata integrity verification
#define AUDIT_INTEGRITY_STATUS          1802 /* Integrity enable status */
#define AUDIT_INTEGRITY_HASH            1803 /* Integrity HASH type */
#define AUDIT_INTEGRITY_PCR             1804 /* PCR invalidation msgs */
#define AUDIT_INTEGRITY_RULE            1805 /* Policy rule */
#endif
#ifndef AUDIT_INTEGRITY_EVM_XATTR
#define AUDIT_INTEGRITY_EVM_XATTR       1806 /* New EVM-covered xattr */
#endif
#ifndef AUDIT_INTEGRITY_POLICY_RULE
#define AUDIT_INTEGRITY_POLICY_RULE     1807 /* Integrity Policy rule */
#endif
#define AUDIT_FIRST_ANOM_MSG            2100
#define AUDIT_LAST_ANOM_MSG             2199
#define AUDIT_ANOM_LOGIN_FAILURES       2100 // Failed login limit reached
#define AUDIT_ANOM_LOGIN_TIME           2101 // Login attempted at bad time
#define AUDIT_ANOM_LOGIN_SESSIONS       2102 // Max concurrent sessions reached
#define AUDIT_ANOM_LOGIN_ACCT           2103 // Login attempted to watched acct
#define AUDIT_ANOM_LOGIN_LOCATION       2104 // Login from forbidden location
#define AUDIT_ANOM_MAX_DAC              2105 // Max DAC failures reached
#define AUDIT_ANOM_MAX_MAC              2106 // Max MAC failures reached
#define AUDIT_ANOM_AMTU_FAIL            2107 // AMTU failure
#define AUDIT_ANOM_RBAC_FAIL            2108 // RBAC self test failure
#define AUDIT_ANOM_RBAC_INTEGRITY_FAIL  2109 // RBAC file integrity failure
#define AUDIT_ANOM_CRYPTO_FAIL          2110 // Crypto system test failure
#define AUDIT_ANOM_ACCESS_FS            2111 // Access of file or dir
#define AUDIT_ANOM_EXEC                 2112 // Execution of file
#define AUDIT_ANOM_MK_EXEC              2113 // Make an executable
#define AUDIT_ANOM_ADD_ACCT             2114 // Adding an acct
#define AUDIT_ANOM_DEL_ACCT             2115 // Deleting an acct
#define AUDIT_ANOM_MOD_ACCT             2116 // Changing an acct
#define AUDIT_ANOM_ROOT_TRANS           2117 // User became root
#define AUDIT_ANOM_LOGIN_SERVICE        2118 // Service acct attempted login
#define AUDIT_ANOM_LOGIN_ROOT           2119 // Root login attempted
#define AUDIT_ANOM_ORIGIN_FAILURES      2120 // Origin has too many failed login
#define AUDIT_ANOM_SESSION              2121 // The user session is bad

#define AUDIT_FIRST_ANOM_RESP           2200
#define AUDIT_LAST_ANOM_RESP            2299
#define AUDIT_RESP_ANOMALY              2200 /* Anomaly not reacted to */
#define AUDIT_RESP_ALERT                2201 /* Alert email was sent */
#define AUDIT_RESP_KILL_PROC            2202 /* Kill program */
#define AUDIT_RESP_TERM_ACCESS          2203 /* Terminate session */
#define AUDIT_RESP_ACCT_REMOTE          2204 /* Acct locked from remote access*/
#define AUDIT_RESP_ACCT_LOCK_TIMED      2205 /* User acct locked for time */
#define AUDIT_RESP_ACCT_UNLOCK_TIMED    2206 /* User acct unlocked from time */
#define AUDIT_RESP_ACCT_LOCK            2207 /* User acct was locked */
#define AUDIT_RESP_TERM_LOCK            2208 /* Terminal was locked */
#define AUDIT_RESP_SEBOOL               2209 /* Set an SE Linux boolean */
#define AUDIT_RESP_EXEC                 2210 /* Execute a script */
#define AUDIT_RESP_SINGLE               2211 /* Go to single user mode */
#define AUDIT_RESP_HALT                 2212 /* take the system down */
#define AUDIT_RESP_ORIGIN_BLOCK         2213 /* Address blocked by iptables */
#define AUDIT_RESP_ORIGIN_BLOCK_TIMED   2214 /* Address blocked for time */
#define AUDIT_RESP_ORIGIN_UNBLOCK_TIMED 2215 /* Address unblocked from timed */

#define AUDIT_FIRST_USER_LSPP_MSG       2300
#define AUDIT_LAST_USER_LSPP_MSG        2399
#define AUDIT_USER_ROLE_CHANGE          2300 /* User changed to a new role */
#define AUDIT_ROLE_ASSIGN               2301 /* Admin assigned user to role */
#define AUDIT_ROLE_REMOVE               2302 /* Admin removed user from role */
#define AUDIT_LABEL_OVERRIDE            2303 /* Admin is overriding a label */
#define AUDIT_LABEL_LEVEL_CHANGE        2304 /* Object's level was changed */
#define AUDIT_USER_LABELED_EXPORT       2305 /* Object exported with label */
#define AUDIT_USER_UNLABELED_EXPORT     2306 /* Object exported without label */
#define AUDIT_DEV_ALLOC                 2307 /* Device was allocated */
#define AUDIT_DEV_DEALLOC               2308 /* Device was deallocated */
#define AUDIT_FS_RELABEL                2309 /* Filesystem relabeled */
#define AUDIT_USER_MAC_POLICY_LOAD      2310 /* Userspc daemon loaded policy */
#define AUDIT_ROLE_MODIFY               2311 /* Admin modified a role */
#define AUDIT_USER_MAC_CONFIG_CHANGE    2312 /* Change made to MAC policy */
#define AUDIT_USER_MAC_STATUS           2313 /* Userspc daemon enforcing change */

#define AUDIT_FIRST_CRYPTO_MSG          2400
#define AUDIT_CRYPTO_TEST_USER          2400 /* Crypto test results */
#define AUDIT_CRYPTO_PARAM_CHANGE_USER  2401 /* Crypto attribute change */
#define AUDIT_CRYPTO_LOGIN              2402 /* Logged in as crypto officer */
#define AUDIT_CRYPTO_LOGOUT             2403 /* Logged out from crypto */
#define AUDIT_CRYPTO_KEY_USER           2404 /* Create,delete,negotiate */
#define AUDIT_CRYPTO_FAILURE_USER       2405 /* Fail decrypt,encrypt,randomiz */
#define AUDIT_CRYPTO_REPLAY_USER        2406 /* Crypto replay detected */
#define AUDIT_CRYPTO_SESSION            2407 /* Record parameters set during
                                                TLS session establishment */
#define AUDIT_CRYPTO_IKE_SA             2408 /* Record parameters related to
                                                IKE SA */
#define AUDIT_CRYPTO_IPSEC_SA           2409 /* Record parameters related to
                                                IPSEC SA */

#define AUDIT_LAST_CRYPTO_MSG           2499

/* Events for both VMs and container orchestration software */
#define AUDIT_FIRST_VIRT_MSG            2500
#define AUDIT_VIRT_CONTROL              2500 /* Start,Pause,Stop VM/container */
#define AUDIT_VIRT_RESOURCE             2501 /* Resource assignment */
#define AUDIT_VIRT_MACHINE_ID           2502 /* Binding of label to VM/cont */
#define AUDIT_VIRT_INTEGRITY_CHECK      2503 /* Guest integrity results */
#define AUDIT_VIRT_CREATE               2504 /* Creation of guest image */
#define AUDIT_VIRT_DESTROY              2505 /* Destruction of guest image */
#define AUDIT_VIRT_MIGRATE_IN           2506 /* Inbound guest migration info */
#define AUDIT_VIRT_MIGRATE_OUT          2507 /* Outbound guest migration info */

#define AUDIT_LAST_VIRT_MSG             2599

#ifndef AUDIT_FIRST_USER_MSG2
#define AUDIT_FIRST_USER_MSG2  2100    /* More userspace messages */
#define AUDIT_LAST_USER_MSG2   2999
#endif
/* New kernel event definitions since 5.0 */
#ifndef AUDIT_BPF
#define AUDIT_BPF               1334 /* BPF load/unload */
#endif

#ifndef AUDIT_EVENT_LISTENER
#define AUDIT_EVENT_LISTENER    1335 /* audit mcast sock join/part */
#endif

#ifndef AUDIT_URINGOP
#define AUDIT_URINGOP           1336 /* io_uring operations */
#endif

#ifndef AUDIT_OPENAT2
#define AUDIT_OPENAT2           1337 /* openat2 open_how flags */
#endif

#ifndef AUDIT_DM_CTRL
#define AUDIT_DM_CTRL           1338 /* Device Mapper target control */
#endif

#ifndef AUDIT_DM_EVENT
#define AUDIT_DM_EVENT          1339 /* Device Mapper events */
#endif

#ifndef AUDIT_ANOM_CREAT
#define AUDIT_ANOM_CREAT            1703 /* Suspicious file creation */
#endif

#ifdef __cplusplus
}
#endif

#endif

