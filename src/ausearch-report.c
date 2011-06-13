/*
* ausearch-report.c - Format and output events
* Copyright (c) 2005-09,2011 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved. 
*
* This software may be freely redistributed and/or modified under the
* terms of the GNU General Public License as published by the Free
* Software Foundation; either version 2, or (at your option) any
* later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING. If not, write to the
* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/un.h>
#include <linux/ax25.h>
#include <linux/atm.h>
#include <linux/x25.h>
#include <linux/if.h>	// FIXME: remove when ipx.h is fixed
#include <linux/ipx.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/icmp.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#include "libaudit.h"
#include "ausearch-options.h"
#include "ausearch-parse.h"
#include "ausearch-lookup.h"

/* This is the name/value pair used by search tables */
struct nv_pair {
	int        value;
	const char *name;
};

/* This is the list of field types that we can interpret */
enum { T_UID, T_GID, T_SYSCALL, T_ARCH, T_EXIT, T_ESCAPED, T_PERM, T_MODE, 
T_SOCKADDR, T_FLAGS, T_PROMISC, T_CAPABILITY, T_SIGNAL, T_KEY, T_LIST,
T_TTY_DATA, T_SESSION, T_CAP_BITMAP, T_NFPROTO, T_ICMPTYPE, T_PROTOCOL,
T_ADDR };

/* Function in ausearch-parse for unescaping filenames */
extern char *unescape(char *buf);

/* Local functions */
static void output_raw(llist *l);
static void output_default(llist *l);
static void output_interpreted(llist *l);
static void output_interpreted_node(const lnode *n);
static void interpret(char *name, char *val, int comma, int rtype);

/* The machine based on elf type */
static int machine = -1;

/* The first syscall argument */
static unsigned long long a0;

/* This function branches to the correct output format */
void output_record(llist *l)
{
	switch (report_format) {
		case RPT_RAW:
			output_raw(l);
			break;
		case RPT_DEFAULT:
			output_default(l);
			break;
		case RPT_INTERP:
			output_interpreted(l);
			break;
		case RPT_PRETTY:
			break;
		default:
			fprintf(stderr, "Report format error");
			exit(1);
	}
}

/* This function will output the record as is */
static void output_raw(llist *l)
{
	const lnode *n;

	list_first(l);
	n = list_get_cur(l);
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	do {
		printf("%s\n", n->message);
	} while ((n=list_next(l)));
}

/*
 * This function will take the linked list and format it for output. No
 * interpretation is performed. The output order is lifo for everything.
 */
static void output_default(llist *l)
{
	const lnode *n;

	list_last(l);
	n = list_get_cur(l);
	printf("----\ntime->%s", ctime(&l->e.sec));
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	if (n->type >= AUDIT_DAEMON_START && n->type < AUDIT_SYSCALL) 
		printf("%s\n", n->message);
	else {
		do {
			printf("%s\n", n->message);
		} while ((n=list_prev(l)));
	}
}

/*
 * This function will take the linked list and format it for output. 
 * Interpretation is performed to aid understanding of records. The output
 * order is lifo for everything.
 */
static void output_interpreted(llist *l)
{
	const lnode *n;

	list_last(l);
	n = list_get_cur(l);
	printf("----\n");
	if (!n) {
		fprintf(stderr, "Error - no elements in record.");
		return;
	}
	if (n->type >= AUDIT_DAEMON_START && n->type < AUDIT_SYSCALL) 
		output_interpreted_node(n);
	else {
		do {
			output_interpreted_node(n);
		} while ((n=list_prev(l)));
	}
}

/*
 * This function will cycle through a message and lookup each type that 
 * it finds. 
 */
static void output_interpreted_node(const lnode *n)
{
	char *ptr, *str = n->message, *node = NULL;
	int found;

	/* Check and see if we start with a node */
	if (str[0] == 'n') {
		ptr=strchr(str, ' ');
		if (ptr) {
			*ptr = 0;
			node = str;
			str = ptr+1;
		}
	}

	// First locate time stamp.
	ptr = strchr(str, '(');
	if (ptr == NULL) {
		fprintf(stderr, "can't find time stamp\n");
		return;
	} else {
		time_t t;
		int milli,num = n->type;
		unsigned long serial;
		struct tm *btm;
		char tmp[32];
		const char *bptr;

		*ptr++ = 0;
		if (num == -1) {
			// see if we are older and wiser now.
			bptr = strchr(str, '[');
			if (bptr && bptr < ptr) {
				char *eptr;
				bptr++;
				eptr = strchr(bptr, ']');
				if (eptr) {
					*eptr = 0;
					errno = 0;
					num = strtoul(bptr, NULL, 10);
					*eptr = ']';
					if (errno) 
						num = -1;
				}
			}
		}

		// print everything up to it.
		if (num >= 0) {
			bptr = audit_msg_type_to_name(num);
			if (bptr) {
				if (node)
					printf("%s ", node);
				printf("type=%s msg=audit(", bptr);
				goto no_print;
			}
		} 
		if (node)
			printf("%s ", node);
		printf("%s(", str);
no_print:

		// output formatted time.
		str = strchr(ptr, '.');
		if (str == NULL)
			return;
		*str++ = 0;
		errno = 0;
		t = strtoul(ptr, NULL, 10);
		if (errno)
			return;
		ptr = strchr(str, ':');
		if (ptr == NULL)
			return;
		*ptr++ = 0;
		milli = strtoul(str, NULL, 10);
		if (errno)
			return;
		str = strchr(ptr, ')');
		if(str == NULL)
			return;
		*str++ = 0;
		serial = strtoul(ptr, NULL, 10);
		if (errno)
			return;
		btm = localtime(&t);
		strftime(tmp, sizeof(tmp), "%x %T", btm);
		printf("%s", tmp);
		printf(".%03d:%lu) ", milli, serial);
	}

	if (n->type == AUDIT_SYSCALL) 
		a0 = n->a0;

	// for each item.
	found = 0;
	while (str && *str && (ptr = strchr(str, '='))) {
		char *name, *val;
		int comma = 0;
		found = 1;

		// look back to last space - this is name
		name = ptr;
		while (*name != ' ' && name > str)
			--name;
		*ptr++ = 0;

		// print everything up to the '='
		printf("%s=", str);

		// Some user messages have msg='uid=500   in this case
		// skip the msg= piece since the real stuff is the uid=
		if (strcmp(name, "msg") == 0) {
			str = ptr;
			continue;
		}

		// In the above case, after msg= we need to trim the ' from uid
		if (*name == '\'')
			name++;

		// get string after = to the next space or end - this is value
		if (*ptr == '\'' || *ptr == '"') {
			str = strchr(ptr+1, *ptr);
			if (str) {
				str++;
				if (*str)
					*str++ = 0;
			}
		} else {
			str = strchr(ptr, ',');
			val = strchr(ptr, ' ');
			if (str && val && (str < val)) {
				*str++ = 0;
				comma = 1;
			} else if (str && (val == NULL)) {
				*str++ = 0;
				comma = 1;
			} else if (val) {
				str = val;
				*str++ = 0;
			}
		}
		// val points to begin & str 1 past end
		val = ptr;
		
		// print interpreted string
		interpret(name, val, comma, n->type);
	}
	// If nothing found, just print out as is
	if (!found && ptr == NULL && str)
		printf("%s", str);
	printf("\n");
}

/*
 * This table translates field names into a type that identifies the
 * interpreter to use on it.
 */
static struct nv_pair typetab[] = {
	{T_UID, "auid"},
	{T_UID, "uid"},
	{T_UID, "euid"},
	{T_UID, "suid"},
	{T_UID, "fsuid"},
	{T_UID, "ouid"},
	{T_UID, "oauid"},
	{T_UID, "iuid"},
	{T_UID, "id"},
	{T_UID, "inode_uid"},
	{T_UID, "sauid"},
	{T_GID, "gid"},
	{T_GID, "egid"},
	{T_GID, "sgid"},
	{T_GID, "fsgid"},
	{T_GID, "ogid"},
	{T_GID, "igid"},
	{T_GID, "inode_gid"},
	{T_GID, "new_gid"},
	{T_SYSCALL, "syscall"},
	{T_ARCH, "arch"},
	{T_EXIT, "exit"},
	{T_ESCAPED, "path"},
	{T_ESCAPED, "comm"},
	{T_ESCAPED, "exe"},
	{T_ESCAPED, "file"},
	{T_ESCAPED, "name"},
	{T_ESCAPED, "watch"},
	{T_ESCAPED, "cwd"},
	{T_ESCAPED, "cmd"},
	{T_ESCAPED, "dir"},
	{T_TTY_DATA, "data"},
	{T_KEY, "key"},
	{T_PERM, "perm"},
	{T_PERM, "perm_mask"},
	{T_MODE, "mode"},
	{T_SOCKADDR, "saddr"},
	{T_FLAGS, "flags"},
	{T_PROMISC, "prom"},
	{T_PROMISC, "old_prom"},
	{T_CAPABILITY, "capability"},
	{T_SIGNAL, "sig"},
	{T_LIST, "list"},
	{T_SESSION, "ses"},
	{T_CAP_BITMAP, "cap_pi"},
	{T_CAP_BITMAP, "cap_pe"},
	{T_CAP_BITMAP, "cap_pp"},
	{T_CAP_BITMAP, "cap_fi"},
	{T_CAP_BITMAP, "cap_fp"},
	{T_ESCAPED, "vm"},
	{T_ESCAPED, "old-disk"},
	{T_ESCAPED, "new-disk"},
	{T_ESCAPED, "device"},
	{T_ESCAPED, "cgroup"},
	{T_NFPROTO, "family"},
	{T_ICMPTYPE, "icmptype"},
	{T_PROTOCOL, "proto"},
};
#define TYPE_NAMES (sizeof(typetab)/sizeof(typetab[0]))


static int audit_lookup_type(const char *name)
{
        int i;

        for (i = 0; i < TYPE_NAMES; i++)
                if (!strcmp(typetab[i].name, name)) {
                        return typetab[i].value;
		}
        return -1;
}

static void print_uid(const char *val)
{
	int uid;
	char name[64];

	errno = 0;
	uid = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

	printf("%s ", aulookup_uid(uid, name, sizeof(name)));
}

static void print_gid(const char *val)
{
	int gid;
	char name[64];

	errno = 0;
	gid = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

	printf("%s ", aulookup_gid(gid, name, sizeof(name)));
}

static void print_arch(const char *val)
{
	unsigned int ival;
	const char *ptr;

	errno = 0;
	ival = strtoul(val, NULL, 16);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}
	machine = audit_elf_to_machine(ival);
	if (machine < 0) {
		printf("unknown elf type(%s) ", val);
		return;
	}
	ptr = audit_machine_to_name(machine);
	printf("%s ", ptr);
}

static void print_syscall(const char *val)
{
	const char *sys;
	int ival;

	if (machine < 0) 
		machine = audit_detect_machine();
	if (machine < 0) {
		printf("%s ", val);
		return;
	}
	errno = 0;
	ival = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}
	
	sys = audit_syscall_to_name(ival, machine);
	if (sys) {
		const char *func = NULL;
		if (strcmp(sys, "socketcall") == 0)
			func = aulookup_socketcall((long)a0);
		else if (strcmp(sys, "ipc") == 0)
			func = aulookup_ipccall((long)a0);
		if (func)
			printf("%s(%s) ", sys, func);
		else
			printf("%s ", sys);
	}
	else
		printf("unknown syscall(%s) ", val);
}

static void print_exit(const char *val)
{
	int ival;

	errno = 0;
	ival = strtol(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

	if (ival < 0)
		printf("%d(%s) ", ival, strerror(-ival));
	else
		printf("%s ", val);
}

static void print_escaped(char *val)
{
	char *str;

	if (*val == '"') {
		char *term;
		val++;
		term = strchr(val, '"');
		if (term == NULL)
			return;
		*term = 0;
		printf("%s ", val);
// FIXME: working here...was trying to detect (null) and handle that differently
// The other 2 should have " around the file names.
/*	} else if (*val == '(') {
		char *term;
		val++;
		term = strchr(val, ' ');
		if (term == NULL)
			return;
		*term = 0;
		printf("%s ", val); */
	} else {
		if (val[0] == '0' && val[1] == '0')
			str = unescape(&val[2]); // Abstract name
		else
			str = unescape(val);
		printf("%s ", str ? str: "(null)");
		free(str);
	}
}

static void print_perm(const char *val)
{
	int ival, printed=0;

	errno = 0;
	ival = strtol(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

	/* The kernel treats nothing as everything */
	if (ival == 0)
		ival = 0x0F;

	if (ival & AUDIT_PERM_READ) {
		printf("read");
		printed = 1;
	}
	if (ival & AUDIT_PERM_WRITE) {
		if (printed)
			printf(",write");
		else
			printf("write");
		printed = 1;
	}
	if (ival & AUDIT_PERM_EXEC) {
		if (printed)
			printf(",exec");
		else
			printf("exec");
		printed = 1;
	}
	if (ival & AUDIT_PERM_ATTR) {
		if (printed)
			printf(",attr");
		else
			printf("attr");
	}
	printf(" ");
}

static void print_mode(const char *val)
{
	const char *name;
	unsigned int ival;

	errno = 0;
	ival = strtoul(val, NULL, 8);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

	// print the file type
	name = audit_ftype_to_name(ival & S_IFMT);
	if (name != NULL)
		printf("%s,", name);
	else {
		unsigned first_ifmt_bit;

		// The lowest-valued "1" bit in S_IFMT
		first_ifmt_bit = S_IFMT & ~(S_IFMT - 1);
		printf("%03o,", (ival & S_IFMT) / first_ifmt_bit);
	}

	// check on special bits
	if (S_ISUID & ival)
		printf("suid,");
	if (S_ISGID & ival)
		printf("sgid,");
	if (S_ISVTX & ival)
		printf("sticky,");

	// and the read, write, execute flags in octal
	printf("%03o ",  (S_IRWXU|S_IRWXG|S_IRWXO) & ival);
}

/*
 * This table maps socket families to their text name
 */
static struct nv_pair famtab[] = {
        {AF_LOCAL, "local"},
        {AF_INET, "inet"},
        {AF_AX25, "ax25"},
        {AF_IPX, "ipx"},
        {AF_APPLETALK, "appletalk"},
        {AF_NETROM, "netrom"},
        {AF_BRIDGE, "bridge"},
        {AF_ATMPVC, "atmpvc"},
        {AF_X25, "x25"},
        {AF_INET6, "inet6"},
        {AF_ROSE, "rose"},
        {AF_DECnet, "decnet"},
        {AF_NETBEUI, "netbeui"},
        {AF_SECURITY, "security"},
        {AF_KEY, "key"},
        {AF_NETLINK, "netlink"},
        {AF_PACKET, "packet"},
        {AF_ASH, "ash"},
        {AF_ECONET, "econet"},
        {AF_ATMSVC, "atmsvc"},
        {AF_SNA, "sna"},
        {AF_IRDA, "irda"},
        {AF_PPPOX, "pppox"},
        {AF_WANPIPE, "wanpipe"},
        {AF_BLUETOOTH, "bluetooth"}
};
#define FAM_NAMES (sizeof(famtab)/sizeof(famtab[0]))

static const char *audit_lookup_fam(int fam)
{
        int i;

        for (i = 0; i < FAM_NAMES; i++)
                if (famtab[i].value == fam)
                        return famtab[i].name;

        return NULL;
}

static void print_sockaddr(char *val)
{
	int len;
	struct sockaddr *saddr;
	char name[NI_MAXHOST], serv[NI_MAXSERV];
	char *host;
	const char *str;

	len = strlen(val)/2;
	host = unescape(val);
	saddr = (struct sockaddr *)host;

	
	str = audit_lookup_fam(saddr->sa_family);
	if (str)
		printf("%s ", str);
	else
		printf("unknown family(%d) ", saddr->sa_family);

	// Now print address for some families
	switch (saddr->sa_family) {
		case AF_LOCAL:
			{
				struct sockaddr_un *un = 
					(struct sockaddr_un *)saddr;
				if (un->sun_path[0])
					printf("%s ", un->sun_path);
				else // abstract name
					printf("%.108s", &un->sun_path[1]);
			}
			break;
                case AF_INET:
			if (len < sizeof(struct sockaddr_in)) {
				printf("sockaddr len too short ");
				free(host);
				return;
			}
			len = sizeof(struct sockaddr_in);
			if (getnameinfo(saddr, len, name, NI_MAXHOST, serv, 
				NI_MAXSERV, NI_NUMERICHOST | 
					NI_NUMERICSERV) == 0 ) {
				printf("host:%s serv:%s ", name, serv);
			} else
				printf("(error resolving addr) ");
			break;
		case AF_AX25:
			{
				struct sockaddr_ax25 *x = 
						(struct sockaddr_ax25 *)saddr;
				printf("call:%c%c%c%c%c%c%c ", 
					x->sax25_call.ax25_call[0],
					x->sax25_call.ax25_call[1],
					x->sax25_call.ax25_call[2],
					x->sax25_call.ax25_call[3],
					x->sax25_call.ax25_call[4],
					x->sax25_call.ax25_call[5],
					x->sax25_call.ax25_call[6]
				);
			}
			break;
                case AF_IPX:
			{
				struct sockaddr_ipx *ip = 
						(struct sockaddr_ipx *)saddr;
				printf("port:%d net:%u ", 
					ip->sipx_port, ip->sipx_network);
			}
			break;
		case AF_ATMPVC:
			{
				struct sockaddr_atmpvc* at = 
					(struct sockaddr_atmpvc *)saddr;
				printf("int:%d ", at->sap_addr.itf);
			}
			break;
		case AF_X25:
			{
				struct sockaddr_x25* x = 
					(struct sockaddr_x25 *)saddr;
				printf("addr:%.15s ", x->sx25_addr.x25_addr);
			}
			break;
                case AF_INET6:
			if (len < sizeof(struct sockaddr_in6)) {
				printf("sockaddr6 len too short ");
				free(host);
				return;
			}
			len = sizeof(struct sockaddr_in6);
			if (getnameinfo(saddr, len, name, NI_MAXHOST, serv,
				NI_MAXSERV, NI_NUMERICHOST | 
					NI_NUMERICSERV) == 0 ) {
				printf("host:%s serv:%s ", name, serv);
			} else
				printf("(error resolving addr) ");
			break;
                case AF_NETLINK:
			{
				struct sockaddr_nl *n = 
						(struct sockaddr_nl *)saddr;
				printf("pid:%u ", n->nl_pid);
			}
			break;
	}
	free(host);
}

static void print_addr(char *val)
{
	printf("%s ", val);
}

/*
 * This table maps file system flags to their text name
 */
static struct nv_pair flagtab[] = {
        {0x0001, "follow"},
        {0x0002, "directory"},
        {0x0004, "continue"},
        {0x0010, "parent"},
        {0x0020, "noalt"},
        {0x0040, "atomic"},
        {0x0100, "open"},
        {0x0200, "create"},
        {0x0400, "access"},
};
#define FLAG_NAMES (sizeof(flagtab)/sizeof(flagtab[0]))

static void print_flags(char *val)
{
	int flags, i,cnt = 0;

	errno = 0;
	flags = strtoul(val, NULL, 16);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}
	if (flags == 0) {
		printf("none");
		return;
	}
	for (i=0; i<FLAG_NAMES; i++) {
		if (flagtab[i].value & flags) {
			if (!cnt) {
				printf("%s", flagtab[i].name);
				cnt++;
			} else
				printf(",%s", flagtab[i].name);
		}
	}
}

static void print_promiscuous(const char *val)
{
	int ival;

	errno = 0;
	ival = strtol(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

	if (ival == 0)
		printf("no ");
	else
		printf("yes ");
}

/*
 * This table maps posix capability defines to their text name
 */
static struct nv_pair captab[] = {
        {0, "chown"},
        {1, "dac_override"},
        {2, "dac_read_search"},
        {3, "fowner"},
        {4, "fsetid"},
        {5, "kill"},
        {6, "setgid"},
        {7, "setuid"},
        {8, "setpcap"},
        {9, "linux_immutable"},
        {10, "net_bind_service"},
        {11, "net_broadcast"},
        {12, "net_admin"},
        {13, "net_raw"},
        {14, "ipc_lock"},
        {15, "ipc_owner"},
        {16, "sys_module"},
        {17, "sys_rawio"},
        {18, "sys_chroot"},
        {19, "sys_ptrace"},
        {20, "sys_pacct"},
        {21, "sys_admin"},
        {22, "sys_boot"},
        {23, "sys_nice"},
        {24, "sys_resource"},
        {25, "sys_time"},
        {26, "sys_tty_config"},
        {27, "mknod"},
        {28, "lease"},
        {29, "audit_write"},
        {30, "audit_control"},
        {31, "setfcap"},
        {32, "mac_overide"},
        {33, "mac_admin"},
        {34, "syslog"},
};
#define CAP_NAMES (sizeof(captab)/sizeof(captab[0]))

static void print_capabilities(char *val)
{
	int cap, i;

	errno = 0;
	cap = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

        for (i = 0; i < CAP_NAMES; i++) {
                if (captab[i].value == cap) {
                        printf("%s ", captab[i].name);
			return;
		}
	}
}

static void print_cap_bitmap(char *val)
{
#define MASK(x) (1U << (x))
	unsigned long long temp;
	__u32 caps[2];
	int i, found=0;

	errno = 0;
	temp = strtoull(val, NULL, 16);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

	caps[0] = temp & 0xFFFFFFFF;
	caps[1] = (temp & 0xFFFFFFFF) >> 32;
	for (i=0; i< CAP_NAMES; i++) {
		if (MASK(i%32) & caps[i/32]) {
			if (found)
				printf(",");
       			printf("%s", captab[i].name);
			found = 1;
		}
	}
	if (found == 0)
		printf("none");
	printf(" ");
}

/*
 * This table maps netfilter protocol defines to their text name
 */
static struct nv_pair nfprototab[] = {
        {NFPROTO_UNSPEC, "unspecified"},
        {NFPROTO_IPV4, "ipv4"},
        {NFPROTO_ARP, "arp"},
        {NFPROTO_BRIDGE, "bridge"},
        {NFPROTO_IPV6, "ipv6"},
        {NFPROTO_DECNET, "decnet"},
};
#define NFPROTO_NAMES (sizeof(nfprototab)/sizeof(nfprototab[0]))

static void print_nfproto(char *val)
{
	int proto, i;

	errno = 0;
	proto = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

        for (i = 0; i < NFPROTO_NAMES; i++) {
                if (nfprototab[i].value == proto) {
                        printf("%s ", nfprototab[i].name);
			return;
		}
	}
}

/*
 * This table maps icmp type defines to their text name
 */
static struct nv_pair icmptypetab[] = {
        {ICMP_ECHOREPLY, "echo-reply"},
        {ICMP_DEST_UNREACH, "destination-unreachable"},
        {ICMP_SOURCE_QUENCH, "source-quench"},
        {ICMP_REDIRECT, "redirect"},
        {ICMP_ECHO, "echo"},
        {ICMP_TIME_EXCEEDED, "time-exceeded"},
        {ICMP_PARAMETERPROB, "parameter-problem"},
        {ICMP_TIMESTAMP, "timestamp-request"},
        {ICMP_TIMESTAMPREPLY, "timestamp-reply"},
        {ICMP_INFO_REQUEST, "info-request"},
        {ICMP_INFO_REPLY, "info-reply"},
        {ICMP_ADDRESS, "address-mask-request"},
        {ICMP_ADDRESSREPLY, "address-mask-reply"},
};
#define ICMPTYPE_NAMES (sizeof(icmptypetab)/sizeof(icmptypetab[0]))

static void print_icmptype(char *val)
{
	int icmptype, i;

	errno = 0;
	icmptype = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}

        for (i = 0; i < ICMPTYPE_NAMES; i++) {
                if (icmptypetab[i].value == icmptype) {
                        printf("%s ", icmptypetab[i].name);
			return;
		}
	}
}

static void print_signals(char *val)
{
	int i;

	errno = 0;
	i = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}
	printf("%s ", strsignal(i));
}

static void print_protocol(char *val)
{
	int i;
	struct protoent *p;

	errno = 0;
	i = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}
	p = getprotobynumber(i);
	if (p)
		printf("%s ", p->p_name);
	else
		printf("unknown protocol ");
}

static const char key_sep[2] = { AUDIT_KEY_SEPARATOR, 0 };
static void print_key(char *val)
{
	int count=0;
	char *saved=NULL;
	if (*val == '"') {
		char *term;
		val++;
		term = strchr(val, '"');
		if (term == NULL)
			return;
		*term = 0;
		printf("%s ", val);
	} else {
		char *keyptr = unescape(val);
		char *kptr = strtok_r(keyptr, key_sep, &saved);
		if (kptr == NULL) {
			printf("%s", keyptr);
		}
		while (kptr) {
			if (count == 0) {
				printf("%s", kptr);
				count++;
			} else
				printf(" key=%s", kptr);
			kptr = strtok_r(NULL, key_sep, &saved);
		}
		printf(" ");
		free(keyptr);
	}
}

static void print_list(char *val)
{
	int i;

	errno = 0;
	i = strtoul(val, NULL, 10);
	if (errno) {
		printf("conversion error(%s) ", val);
		return;
	}
	printf("%s ", audit_flag_to_name(i));
}

static void print_session(char *val)
{
	if (strcmp(val, "4294967295") == 0)
		printf("unset ");
	else
		printf("%s ", val);
}

static void interpret(char *name, char *val, int comma, int rtype)
{
	int type;

	while (*name == ' '||*name == '(')
		name++;


	/* Do some fixups */
	if (rtype == AUDIT_EXECVE && name[0] == 'a' && strcmp(name, "argc"))
		type = T_ESCAPED;
	else if (rtype == AUDIT_AVC && strcmp(name, "saddr") == 0)
		type = -1;
	else if (rtype == AUDIT_NETFILTER_PKT && strcmp(name, "saddr") == 0)
		type = T_ADDR;
	else if (strcmp(name, "acct") == 0) {
		// Remove trailing punctuation
		int len = strlen(val);
		if (val[len-1] == ':')
			val[len-1] = 0;

		if (val[0] == '"')
			type = T_ESCAPED;
		else if (is_hex_string(val))
			type = T_ESCAPED;
		else
			type = -1;
	} else
		type = audit_lookup_type(name);

	switch(type) {
		case T_UID:
			print_uid(val);
			break;
		case T_GID:
			print_gid(val);
			break;
		case T_SYSCALL:
			print_syscall(val);
			break;
		case T_ARCH:
			print_arch(val);
			break;
		case T_EXIT:
			print_exit(val);
			break;
		case T_ESCAPED:
			print_escaped(val);
			break;
		case T_PERM:
			print_perm(val);
			break;
		case T_MODE:
			print_mode(val);
			break;
		case T_SOCKADDR:
			print_sockaddr(val);
			break;
		case T_ADDR:
			print_addr(val);
			break;
		case T_FLAGS:
			print_flags(val);
			break;
		case T_PROMISC:
			print_promiscuous(val);
			break;
		case T_CAPABILITY:
			print_capabilities(val);
			break;
		case T_SIGNAL:
			print_signals(val);
			break;
		case T_KEY:
			print_key(val);
			break;
		case T_LIST:
			print_list(val);
			break;
		case T_TTY_DATA:
			print_tty_data(val);
			break;
		case T_SESSION:
			print_session(val);
			break;
		case T_CAP_BITMAP:
			print_cap_bitmap(val);
			break;
		case T_NFPROTO:
			print_nfproto(val);
			break;
		case T_ICMPTYPE:
			print_icmptype(val);
			break;
		case T_PROTOCOL:
			print_protocol(val);
			break;
		default:
			printf("%s%c", val, comma ? ',' : ' ');
	}
}

