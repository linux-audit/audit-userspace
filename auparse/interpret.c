/*
* interpret.c - Lookup values to something more readable
* Copyright (c) 2007-09,2011-12 Red Hat Inc., Durham, North Carolina.
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
#include "nvlist.h"
#include "nvpair.h"
#include "libaudit.h"
#include "internal.h"
#include "interpret.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <linux/net.h>
#include <netdb.h>
#include <sys/un.h>
#include <linux/ax25.h>
#include <linux/atm.h>
#include <linux/x25.h>
#include <linux/if.h>   // FIXME: remove when ipx.h is fixed
#include <linux/ipx.h>
#include <linux/capability.h>
#include <sys/personality.h>
#include "auparse-defs.h"
#include "gen_tables.h"

/* This is from asm/ipc.h. Copying it for now as some platforms
 * have broken headers. */
#define SEMOP            1
#define SEMGET           2
#define SEMCTL           3
#define SEMTIMEDOP	 4
#define MSGSND          11
#define MSGRCV          12
#define MSGGET          13
#define MSGCTL          14
#define SHMAT           21
#define SHMDT           22
#define SHMGET          23
#define SHMCTL          24

#include "captabs.h"
#include "clone-flagtabs.h"
#include "epoll_ctls.h"
#include "famtabs.h"
#include "fcntl-cmdtabs.h"
#include "flagtabs.h"
#include "ipctabs.h"
#include "mmaptabs.h"
#include "mounttabs.h"
#include "open-flagtabs.h"
#include "persontabs.h"
#include "prottabs.h"
#include "ptracetabs.h"
#include "recvtabs.h"
#include "rlimittabs.h"
#include "socktabs.h"
#include "socktypetabs.h"
#include "signaltabs.h"
#include "clocktabs.h"
#include "typetabs.h"
#include "nfprototabs.h"
#include "icmptypetabs.h"
#include "seccomptabs.h"

typedef enum { AVC_UNSET, AVC_DENIED, AVC_GRANTED } avc_t;
typedef enum { S_UNSET=-1, S_FAILED, S_SUCCESS } success_t;

static const char *print_signals(const char *val, unsigned int base);


/*
 * This function will take a pointer to a 2 byte Ascii character buffer and
 * return the actual hex value.
 */
static unsigned char x2c(const unsigned char *buf)
{
        static const char AsciiArray[17] = "0123456789ABCDEF";
        char *ptr;
        unsigned char total=0;

        ptr = strchr(AsciiArray, (char)toupper(buf[0]));
        if (ptr)
                total = (unsigned char)(((ptr-AsciiArray) & 0x0F)<<4);
        ptr = strchr(AsciiArray, (char)toupper(buf[1]));
        if (ptr)
                total += (unsigned char)((ptr-AsciiArray) & 0x0F);

        return total;
}

static int is_hex_string(const char *str)
{
	while (*str) {
		if (!isxdigit(*str))
			return 0;
		str++;
	}
	return 1;
}

/* returns a freshly malloc'ed and converted buffer */
char *au_unescape(char *buf)
{
        int len, i;
        char saved, *str, *ptr = buf;

        /* Find the end of the name */
        if (*ptr == '(') {
                ptr = strchr(ptr, ')');
                if (ptr == NULL)
                        return NULL;
                else
                        ptr++;
        } else {
                while (isxdigit(*ptr))
                        ptr++;
        }
        saved = *ptr;
        *ptr = 0;
        str = strdup(buf);
        *ptr = saved;

	/* See if its '(null)' from the kernel */
        if (*buf == '(')
                return str;

        /* We can get away with this since the buffer is 2 times
         * bigger than what we are putting there.
         */
        len = strlen(str);
        if (len < 2) {
                free(str);
                return NULL;
        }
        ptr = str;
        for (i=0; i<len; i+=2) {
                *ptr = x2c((unsigned char *)&str[i]);
                ptr++;
        }
        *ptr = 0;
        return str;
}

static const char *success[3]= { "unset", "no", "yes" };
static const char *aulookup_success(int s)
{
	switch (s)
	{
		default:
			return success[0];
			break;
		case S_FAILED:
			return success[1];
			break;
		case S_SUCCESS:
			return success[2];
			break;
	}
}

static nvpair uid_nvl;
static int uid_list_created=0;
static const char *aulookup_uid(uid_t uid, char *buf, size_t size)
{
	char *name = NULL;
	int rc;

	if (uid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	}

	// Check the cache first
	if (uid_list_created == 0) {
		nvpair_create(&uid_nvl);
		nvpair_clear(&uid_nvl);
		uid_list_created = 1;
	}
	rc = nvpair_find_val(&uid_nvl, uid);
	if (rc) {
		name = uid_nvl.cur->name;
	} else {
		// Add it to cache
		struct passwd *pw;
		pw = getpwuid(uid);
		if (pw) {
			nvpnode nv;
			nv.name = strdup(pw->pw_name);
			nv.val = uid;
			nvpair_append(&uid_nvl, &nv);
			name = uid_nvl.cur->name;
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", uid);
	return buf;
}

void aulookup_destroy_uid_list(void)
{
	if (uid_list_created == 0)
		return;

	nvpair_clear(&uid_nvl); 
	uid_list_created = 0;
}

static nvpair gid_nvl;
static int gid_list_created=0;
static const char *aulookup_gid(gid_t gid, char *buf, size_t size)
{
	char *name = NULL;
	int rc;

	if (gid == -1) {
		snprintf(buf, size, "unset");
		return buf;
	}

	// Check the cache first
	if (gid_list_created == 0) {
		nvpair_create(&gid_nvl);
		nvpair_clear(&gid_nvl);
		gid_list_created = 1;
	}
	rc = nvpair_find_val(&gid_nvl, gid);
	if (rc) {
		name = gid_nvl.cur->name;
	} else {
		// Add it to cache
		struct group *gr;
		gr = getgrgid(gid);
		if (gr) {
			nvpnode nv;
			nv.name = strdup(gr->gr_name);
			nv.val = gid;
			nvpair_append(&gid_nvl, &nv);
			name = gid_nvl.cur->name;
		}
	}
	if (name != NULL)
		snprintf(buf, size, "%s", name);
	else
		snprintf(buf, size, "unknown(%d)", gid);
	return buf;
}

void aulookup_destroy_gid_list(void)
{
	if (gid_list_created == 0)
		return;

	nvpair_clear(&gid_nvl); 
	gid_list_created = 0;
}

static const char *print_uid(const char *val, unsigned int base)
{
        int uid;
        char name[64];

        errno = 0;
        uid = strtoul(val, NULL, base);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        return strdup(aulookup_uid(uid, name, sizeof(name)));
}

static const char *print_gid(const char *val, unsigned int base)
{
        int gid;
        char name[64];

        errno = 0;
        gid = strtoul(val, NULL, base);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        return strdup(aulookup_gid(gid, name, sizeof(name)));
}

static const char *print_arch(const char *val, int machine)
{
        const char *ptr;
	char *out;

        if (machine < 0) {
                asprintf(&out, "unknown elf type(%s)", val);
                return out;
        }
        ptr = audit_machine_to_name(machine);
	if (ptr)
	        return strdup(ptr);
	else {
                asprintf(&out, "unknown machine type(%d)", machine);
                return out;
	}
}

static const char *print_syscall(const char *val, const rnode *r)
{
        const char *sys;
	char *out;
	int machine = r->machine, syscall = r->syscall;
	unsigned long long a0 = r->a0;

        if (machine < 0)
                machine = audit_detect_machine();
        if (machine < 0) {
                out = strdup(val);
                return out;
        }
        sys = audit_syscall_to_name(syscall, machine);
        if (sys) {
                const char *func = NULL;
                if (strcmp(sys, "socketcall") == 0) {
			if ((int)a0 == a0)
				func = sock_i2s(a0);
                } else if (strcmp(sys, "ipc") == 0)
			if ((int)a0 == a0)
				func = ipc_i2s(a0);
                if (func)
                        asprintf(&out, "%s(%s)", sys, func);
                else
                        return strdup(sys);
        }
        else
                asprintf(&out, "unknown syscall(%d)", syscall);

	return out;
}

static const char *print_exit(const char *val)
{
        int ival;
	char *out;

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        if (ival < 0) {
                asprintf(&out, "%d(%s)", ival, strerror(-ival));
		return out;
        }
        return strdup(val);

}

static const char *print_escaped(const char *val)
{
	const char *out;

        if (*val == '"') {
                char *term;
                val++;
                term = strchr(val, '"');
                if (term == NULL)
                        return strdup(" ");
                *term = 0;
                out = strdup(val);
		*term = '"';
		return out;
// FIXME: working here...was trying to detect (null) and handle that
// differently. The other 2 should have " around the file names.
/*      } else if (*val == '(') {
                char *term;
                val++;
                term = strchr(val, ' ');
                if (term == NULL)
                        return;
                *term = 0;
                printf("%s ", val); */
        } else if (val[0] == '0' && val[1] == '0')
                out = au_unescape((char *)&val[2]); // Abstract name
	else
                out = au_unescape((char *)val);
	if (out)
		return out;
	return strdup(val); // Something is wrong with string, just send as is
}

static const char *print_perm(const char *val)
{
        int ival, printed=0;
	char buf[32];

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	buf[0] = 0;

        /* The kernel treats nothing (0x00) as everything (0x0F) */
        if (ival == 0)
                ival = 0x0F;
        if (ival & AUDIT_PERM_READ) {
                strcat(buf, "read");
                printed = 1;
        }
        if (ival & AUDIT_PERM_WRITE) {
                if (printed)
                        strcat(buf, ",write");
                else
                        strcat(buf, "write");
                printed = 1;
        }
        if (ival & AUDIT_PERM_EXEC) {
                if (printed)
                        strcat(buf, ",exec");
                else
                        strcat(buf, "exec");
                printed = 1;
        }
        if (ival & AUDIT_PERM_ATTR) {
                if (printed)
                        strcat(buf, ",attr");
                else
                        strcat(buf, "attr");
        }
	return strdup(buf);
}

static const char *print_mode(const char *val, unsigned int base)
{
        unsigned int ival;
	char *out, buf[48];
	const char *name;

        errno = 0;
        ival = strtoul(val, NULL, base);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        // detect the file type
	name = audit_ftype_to_name(ival & S_IFMT);
	if (name != NULL)
		strcpy(buf, name);
	else {
		unsigned first_ifmt_bit;

		// The lowest-valued "1" bit in S_IFMT
		first_ifmt_bit = S_IFMT & ~(S_IFMT - 1);
		sprintf(buf, "%03o", (ival & S_IFMT) / first_ifmt_bit);
	}

        // check on special bits
        if (S_ISUID & ival)
                strcat(buf, ",suid");
        if (S_ISGID & ival)
                strcat(buf, ",sgid");
        if (S_ISVTX & ival)
                strcat(buf, ",sticky");

	// and the read, write, execute flags in octal
        asprintf(&out, "%s,%03o",  buf, (S_IRWXU|S_IRWXG|S_IRWXO) & ival);
	return out;
}

static const char *print_mode_short(const char *val)
{
        unsigned int ival;
	char *out, buf[48];

        errno = 0;
        ival = strtoul(val, NULL, 16);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        // check on special bits
        buf[0] = 0;
        if (S_ISUID & ival)
                strcat(buf, ",suid");
        if (S_ISGID & ival)
                strcat(buf, ",sgid");
        if (S_ISVTX & ival)
                strcat(buf, ",sticky");

	// and the read, write, execute flags in octal
	if (buf[0] == 0)
	        asprintf(&out, "0%03o", (S_IRWXU|S_IRWXG|S_IRWXO) & ival);
	else
	        asprintf(&out, "%s,%03o", buf, (S_IRWXU|S_IRWXG|S_IRWXO)&ival);
	return out;
}

static const char *print_socket_domain(const char *val)
{
	int i;
	char *out;
        const char *str;

	errno = 0;
        i = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
        str = fam_i2s(i);
        if (str == NULL) {
                asprintf(&out, "unknown family(%s)", val);
		return out;
	} else
		return strdup(str);
}

static const char *print_socket_type(const char *val)
{
	unsigned int type;
	char *out;
        const char *str;

	errno = 0;
        type = 0xFF & strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
        str = sock_type_i2s(type);
        if (str == NULL) {
                asprintf(&out, "unknown type(%s)", val);
		return out;
	} else
		return strdup(str);
}

static const char *print_socket_proto(const char *val)
{
	unsigned int proto;
	char *out;
        struct protoent *p;

	errno = 0;
        proto = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
        p = getprotobynumber(proto);
        if (p == NULL) {
                asprintf(&out, "unknown proto(%s)", val);
		return out;
	} else
		return strdup(p->p_name);
}

static const char *print_sockaddr(const char *val)
{
        int slen;
        const struct sockaddr *saddr;
        char name[NI_MAXHOST], serv[NI_MAXSERV];
        const char *host;
        char *out = NULL;
        const char *str;

        slen = strlen(val)/2;
        host = au_unescape((char *)val);
	if (host == NULL) {
                asprintf(&out, "malformed host(%s)", val);
		return out;
	}
        saddr = (struct sockaddr *)host;


        str = fam_i2s(saddr->sa_family);
        if (str == NULL) {
                asprintf(&out, "unknown family(%d)", saddr->sa_family);
		return out;
	}

	// Now print address for some families
        switch (saddr->sa_family) {
                case AF_LOCAL:
                        {
                                const struct sockaddr_un *un =
                                        (struct sockaddr_un *)saddr;
                                if (un->sun_path[0])
                                        asprintf(&out, "%s %s", str,
							un->sun_path);
                                else // abstract name
                                        asprintf(&out, "%s %.108s", str,
							&un->sun_path[1]);
                        }
                        break;
                case AF_INET:
                        if (slen < sizeof(struct sockaddr_in)) {
                                asprintf(&out, "%s sockaddr len too short",
						 str);
                                free((char *)host);
                                return out;
                        }
                        slen = sizeof(struct sockaddr_in);
                        if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
                                NI_MAXSERV, NI_NUMERICHOST |
                                        NI_NUMERICSERV) == 0 ) {
                                asprintf(&out, "%s host:%s serv:%s", str,
						name, serv);
                        } else
                                asprintf(&out, "%s (error resolving addr)",
						 str);
                        break;
                case AF_AX25:
                        {
                                const struct sockaddr_ax25 *x =
                                                (struct sockaddr_ax25 *)saddr;
                                asprintf(&out, "%s call:%c%c%c%c%c%c%c", str,
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
                                const struct sockaddr_ipx *ip =
                                                (struct sockaddr_ipx *)saddr;
                                asprintf(&out, "%s port:%d net:%u", str,
                                        ip->sipx_port, ip->sipx_network);
                        }
                        break;
                case AF_ATMPVC:
                        {
                                const struct sockaddr_atmpvc* at =
                                        (struct sockaddr_atmpvc *)saddr;
                                asprintf(&out, "%s int:%d", str, 
						at->sap_addr.itf);
                        }
                        break;
                case AF_X25:
                        {
                                const struct sockaddr_x25* x =
                                        (struct sockaddr_x25 *)saddr;
                                asprintf(&out, "%s addr:%.15s", str,
						x->sx25_addr.x25_addr);
                        }
                        break;
                case AF_INET6:
                        if (slen < sizeof(struct sockaddr_in6)) {
                                asprintf(&out, "%s sockaddr6 len too short", 
						str);
                                free((char *)host);
                                return out;
                        }
                        slen = sizeof(struct sockaddr_in6);
                        if (getnameinfo(saddr, slen, name, NI_MAXHOST, serv,
                                NI_MAXSERV, NI_NUMERICHOST |
                                        NI_NUMERICSERV) == 0 ) {
                                asprintf(&out, "%s host:%s serv:%s", str,
						name, serv);
                        } else
                                asprintf(&out, "%s (error resolving addr)",
						str);
                        break;
                case AF_NETLINK:
                        {
                                const struct sockaddr_nl *n =
                                                (struct sockaddr_nl *)saddr;
                                asprintf(&out, "%s pid:%u", str, n->nl_pid);
                        }
                        break;
        }
        free((char *)host);
	return out;
}

static const char *print_flags(const char *val)
{
        int flags, cnt = 0;
	size_t i;
	char *out, buf[80];

        errno = 0;
        flags = strtoul(val, NULL, 16);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }
        if (flags == 0) {
                asprintf(&out, "none");
                return out;
        }
	buf[0] = 0;
        for (i=0; i<FLAG_NUM_ENTRIES; i++) {
                if (flag_table[i].value & flags) {
                        if (!cnt) {
                                strcat(buf,
				       flag_strings + flag_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, ",");
                                strcat(buf,
				       flag_strings + flag_table[i].offset);
			}
                }
        }
	return strdup(buf);
}

static const char *print_promiscuous(const char *val)
{
        int ival;

        errno = 0;
        ival = strtol(val, NULL, 10);
        if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

        if (ival == 0)
                return strdup("no");
        else
                return strdup("yes");
}

static const char *print_capabilities(const char *val)
{
        int cap;
	char *out;
	const char *s;

        errno = 0;
        cap = strtoul(val, NULL, 10);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	s = cap_i2s(cap);
	if (s != NULL)
		return strdup(s);
	asprintf(&out, "unknown capability(%s)", val);
	return out;
}

static const char *print_cap_bitmap(const char *val)
{
#define MASK(x) (1U << (x))
	unsigned long long temp;
	__u32 caps[2];
	int i, found=0;
	char *p, buf[600]; // 17 per cap * 33

	errno = 0;
	temp = strtoull(val, NULL, 16);
	if (errno) {
		char *out;
                asprintf(&out, "conversion error(%s)", val);
                return out;
	}

        caps[0] =  temp & 0x00000000FFFFFFFFLL;
        caps[1] = (temp & 0xFFFFFFFF00000000LL) >> 32;
	p = buf;
	for (i=0; i <= CAP_LAST_CAP; i++) {
		if (MASK(i%32) & caps[i/32]) {
			const char *s;
			if (found)
				p = stpcpy(p, ",");
			s = cap_i2s(i);
			if (s != NULL)
				p = stpcpy(p, s);
			found = 1;
		}
	}
	if (found == 0)
		return strdup("none");
	return strdup(buf);
}

static const char *print_success(const char *val)
{
        int res;

	if (isdigit(*val)) {
	        errno = 0;
        	res = strtoul(val, NULL, 10);
	        if (errno) {
			char *out;
                	asprintf(&out, "conversion error(%s)", val);
	                return out;
        	}

	        return strdup(aulookup_success(res));
	} else
		return strdup(val);
}

static const char *print_open_flags(const char *val)
{
	size_t i;
	unsigned int flags;
	int cnt = 0;
	char *out, buf[160];

	errno = 0;
	flags = strtoul(val, NULL, 16);
        if (errno) {
		asprintf(&out, "conversion error(%s)", val);
               	return out;
       	}

	buf[0] = 0;
        if ((flags & O_ACCMODE) == 0) {
		// Handle O_RDONLY specially
                strcat(buf, "O_RDONLY");
                cnt++;
        }
        for (i=0; i<OPEN_FLAG_NUM_ENTRIES; i++) {
                if (open_flag_table[i].value & flags) {
                        if (!cnt) {
                                strcat(buf,
				open_flag_strings + open_flag_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				open_flag_strings + open_flag_table[i].offset);
			}
                }
        }
	return strdup(buf);
}

static const char *print_clone_flags(const char *val)
{
	unsigned int flags, i;
	int cnt = 0;
	char *out, buf[352];

	errno = 0;
	flags = strtoul(val, NULL, 16);
        if (errno) {
		asprintf(&out, "conversion error(%s)", val);
               	return out;
       	}

	buf[0] = 0;
        for (i=0; i<CLONE_FLAG_NUM_ENTRIES; i++) {
                if (clone_flag_table[i].value & flags) {
                        if (!cnt) {
                                strcat(buf,
			clone_flag_strings + clone_flag_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
			clone_flag_strings + clone_flag_table[i].offset);
			}
                }
        }
	if (buf[0] == 0)
		snprintf(buf, sizeof(buf), "%d", flags);
	return strdup(buf);
}

static const char *print_fcntl_cmd(const char *val)
{
	char *out;
	const char *s;
	int cmd;

	errno = 0;
	cmd = strtoul(val, NULL, 16);
        if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
       	}

	s = fcntl_i2s(cmd);
	if (s != NULL)
		return strdup(s);
	asprintf(&out, "unknown fcntl command(%d)", cmd);
	return out;
}

static const char *print_epoll_ctl(const char *val)
{
	char *out;
	const char *s;
	int cmd;

	errno = 0;
	cmd = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}

	s = epoll_ctl_i2s(cmd);
	if (s != NULL)
		return strdup(s);
	asprintf(&out, "unknown epoll_ctl operation (%d)", cmd);
	return out;
}

static const char *print_clock_id(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	else if (i < 7) {
		const char *s = clock_i2s(i);
		if (s != NULL)
			return strdup(s);
	}
	asprintf(&out, "unknown clk_id (%s)", val);
	return out;
}

static const char *print_prot(const char *val, unsigned int is_mmap)
{
	unsigned int prot, i;
	int cnt = 0, limit;
	char buf[144];
	char *out;

	errno = 0;
        prot = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	buf[0] = 0;
        if ((prot & 0x07) == 0) {
		// Handle PROT_NONE specially
                strcat(buf, "PROT_NONE");
		return strdup(buf);
        }
	if (is_mmap)
		limit = 4;
	else
		limit = 3;
        for (i=0; i<limit; i++) {
                if (prot_table[i].value & prot) {
                        if (!cnt) {
                                strcat(buf,
				prot_strings + prot_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				prot_strings + prot_table[i].offset);
			}
                }
        }
	return strdup(buf);
}

static const char *print_mmap(const char *val)
{
	unsigned int maps, i;
	int cnt = 0;
	char buf[144];
	char *out;

	errno = 0;
        maps = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	buf[0] = 0;
        if ((maps & 0x0F) == 0) {
		// Handle MAP_FILE specially
                strcat(buf, "MAP_FILE");
		cnt++;
        }
        for (i=0; i<MMAP_NUM_ENTRIES; i++) {
                if (mmap_table[i].value & maps) {
                        if (!cnt) {
                                strcat(buf,
				mmap_strings + mmap_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				mmap_strings + mmap_table[i].offset);
			}
                }
        }
	return strdup(buf);
}

static const char *print_personality(const char *val)
{
        int pers, pers2;
	char *out;
	const char *s;

        errno = 0;
        pers = strtoul(val, NULL, 16);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	pers2 = pers & ~ADDR_NO_RANDOMIZE;
	s = person_i2s(pers2);
	if (s != NULL) {
		if (pers & ADDR_NO_RANDOMIZE) {
			asprintf(&out, "%s|~ADDR_NO_RANDOMIZE", s);
			return out;
		} else
			return strdup(s);
	}
	asprintf(&out, "unknown personality (%s)", val);
	return out;
}

static const char *print_ptrace(const char *val)
{
        int trace;
	char *out;
	const char *s;

        errno = 0;
        trace = strtoul(val, NULL, 16);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	s = ptrace_i2s(trace);
	if (s != NULL)
		return strdup(s);
	asprintf(&out, "unknown ptrace (%s)", val);
	return out;
}

static const char *print_mount(const char *val)
{
	unsigned int mounts, i;
	int cnt = 0;
	char buf[144];
	char *out;

	errno = 0;
        mounts = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	buf[0] = 0;
        for (i=0; i<MOUNT_NUM_ENTRIES; i++) {
                if (mount_table[i].value & mounts) {
                        if (!cnt) {
                                strcat(buf,
				mount_strings + mount_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				mount_strings + mount_table[i].offset);
			}
                }
        }
	return strdup(buf);
}

static const char *print_rlimit(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	else if (i < 17) {
		const char *s = rlimit_i2s(i);
		if (s != NULL)
			return strdup(s);
	}
	asprintf(&out, "unknown rlimit (%s)", val);
	return out;
}

static const char *print_recv(const char *val)
{
	unsigned int rec, i;
	int cnt = 0;
	char buf[144];
	char *out;

	errno = 0;
        rec = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	buf[0] = 0;
        for (i=0; i<RECV_NUM_ENTRIES; i++) {
                if (recv_table[i].value & rec) {
                        if (!cnt) {
                                strcat(buf,
				recv_strings + recv_table[i].offset);
                                cnt++;
                        } else {
                                strcat(buf, "|");
                                strcat(buf,
				recv_strings + recv_table[i].offset);
			}
                }
        }
	return strdup(buf);
}

static const char *print_a0(const char *val, const rnode *r)
{
	int machine = r->machine, syscall = r->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (strcmp(sys, "rt_sigaction") == 0)
                        return print_signals(val, 16);
                else if (strcmp(sys, "setuid") == 0)
			return print_uid(val, 16);
                else if (strcmp(sys, "setreuid") == 0)
			return print_uid(val, 16);
                else if (strcmp(sys, "setresuid") == 0)
			return print_uid(val, 16);
                else if (strcmp(sys, "setfsuid") == 0)
			return print_uid(val, 16);
                else if (strcmp(sys, "setgid") == 0)
			return print_gid(val, 16);
                else if (strcmp(sys, "setregid") == 0)
			return print_gid(val, 16);
                else if (strcmp(sys, "setresgid") == 0)
			return print_gid(val, 16);
                else if (strcmp(sys, "setfsgid") == 0)
			return print_gid(val, 16);
                else if (strcmp(sys, "clock_settime") == 0)
			return print_clock_id(val);
                else if (strcmp(sys, "personality") == 0)
			return print_personality(val);
                else if (strcmp(sys, "ptrace") == 0)
			return print_ptrace(val);
                else if (strstr(sys, "etrlimit"))
			return print_rlimit(val);
                else if (strcmp(sys, "socket") == 0)
			return print_socket_domain(val);
	}
	return strdup(val);
}

static const char *print_a1(const char *val, const rnode *r)
{
	int machine = r->machine, syscall = r->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (strcmp(sys, "open") == 0)
			return print_open_flags(val);
		else if (strcmp(sys, "epoll_ctl") == 0)
			return print_epoll_ctl(val);
		else if (strcmp(sys, "chmod") == 0)
			return print_mode_short(val);
		else if (strcmp(sys, "fchmod") == 0)
			return print_mode_short(val);
		else if (strstr(sys, "chown"))
			return print_uid(val, 16);
                else if (strcmp(sys, "setreuid") == 0)
			return print_uid(val, 16);
                else if (strcmp(sys, "setresuid") == 0)
			return print_uid(val, 16);
                else if (strcmp(sys, "setregid") == 0)
			return print_gid(val, 16);
                else if (strcmp(sys, "setresgid") == 0)
			return print_gid(val, 16);
		else if (strcmp(sys, "kill") == 0)
			return print_signals(val, 16);
		else if (strcmp(sys, "tkill") == 0)
			return print_signals(val, 16);
		else if (strcmp(sys, "mkdir") == 0)
			return print_mode_short(val);
		else if (strcmp(sys, "creat") == 0)
			return print_mode_short(val);
		else if (strncmp(sys, "fcntl", 5) == 0)
			return print_fcntl_cmd(val);
		else if (strcmp(sys, "mknod") == 0)
			return print_mode(val, 16);
                else if (strcmp(sys, "socket") == 0)
			return print_socket_type(val);
	}
	return strdup(val);
}

static const char *print_a2(const char *val, const rnode *r)
{
	int machine = r->machine, syscall = r->syscall;
	char *out;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (strncmp(sys, "fcntl", 5) == 0) {
			int ival;

			errno = 0;
			ival = strtoul(val, NULL, 16);
		        if (errno) {
                		asprintf(&out, "conversion error(%s)", val);
	                	return out;
	        	}
			switch (r->a1)
			{
				case F_SETOWN:
					return print_uid(val, 16);
				case F_SETFD:
					if (ival == FD_CLOEXEC)
						return strdup("FD_CLOEXEC");
					/* Fall thru okay. */
				case F_SETFL:
				case F_SETLEASE:
				case F_GETLEASE:
				case F_NOTIFY:
					break;
			}
		} else if (strcmp(sys, "openat") == 0)
			return print_open_flags(val);
		else if (strcmp(sys, "fchmodat") == 0)
			return print_mode_short(val);
		else if (strstr(sys, "chown"))
			return print_gid(val, 16);
                else if (strcmp(sys, "setresuid") == 0)
			return print_uid(val, 16);
                else if (strcmp(sys, "setresgid") == 0)
			return print_gid(val, 16);
		else if (strcmp(sys, "tgkill") == 0)
			return print_signals(val, 16);
		else if (strcmp(sys, "mkdirat") == 0)
			return print_mode_short(val);
		else if (strcmp(sys, "mmap") == 0)
			return print_prot(val, 1);
		else if (strcmp(sys, "mprotect") == 0)
			return print_prot(val, 0);
                else if (strcmp(sys, "socket") == 0)
			return print_socket_proto(val);
		else if (strcmp(sys, "clone") == 0)
			return print_clone_flags(val);
                else if (strcmp(sys, "recvmsg") == 0)
			return print_recv(val);
	}
	return strdup(val);
}

static const char *print_a3(const char *val, const rnode *r)
{
	int machine = r->machine, syscall = r->syscall;
	const char *sys = audit_syscall_to_name(syscall, machine);
	if (sys) {
		if (strcmp(sys, "mmap") == 0)
			return print_mmap(val);
		else if (strcmp(sys, "mount") == 0)
			return print_mount(val);
                else if (strcmp(sys, "recv") == 0)
			return print_recv(val);
                else if (strcmp(sys, "recvfrom") == 0)
			return print_recv(val);
                else if (strcmp(sys, "recvmmsg") == 0)
			return print_recv(val);
	}
	return strdup(val);
}

static const char *print_signals(const char *val, unsigned int base)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, base);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	else if (i < 32) {
		const char *s = signal_i2s(i);
		if (s != NULL)
			return strdup(s);
	}
	asprintf(&out, "unknown signal (%s)", val);
	return out;
}

static const char *print_nfproto(const char *val)
{
        int proto;
	char *out;
	const char *s;

        errno = 0;
        proto = strtoul(val, NULL, 10);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	s = nfproto_i2s(proto);
	if (s != NULL)
		return strdup(s);
	asprintf(&out, "unknown netfilter protocol (%s)", val);
	return out;
}

static const char *print_icmptype(const char *val)
{
        int icmptype;
	char *out;
	const char *s;

        errno = 0;
        icmptype = strtoul(val, NULL, 10);
        if (errno) {
                asprintf(&out, "conversion error(%s)", val);
                return out;
        }

	s = icmptype_i2s(icmptype);
	if (s != NULL)
		return strdup(s);
	asprintf(&out, "unknown icmp type (%s)", val);
	return out;
}

static const char *print_protocol(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 10);
	if (errno) 
		asprintf(&out, "conversion error(%s)", val);
	else {
		struct protoent *p = getprotobynumber(i);
		if (p)
			out = strdup(p->p_name);
		else
			out = strdup("undefined protocol");
	}
	return out;
}

static const char *print_addr(const char *val)
{
	char *out = strdup(val);
	return out;
}

static const char *print_list(const char *val)
{
	int i;
	char *out;

	errno = 0;
        i = strtoul(val, NULL, 10);
	if (errno) 
		asprintf(&out, "conversion error(%s)", val);
	else
		out = strdup(audit_flag_to_name(i));
	return out;
}

struct string_buf {
	char *buf; /* NULL if was ever out of memory */
	size_t allocated;
	size_t pos;
};

/* Append c to buf. */
static void append_char(struct string_buf *buf, char c)
{
	if (buf->buf == NULL)
		return;
	if (buf->pos == buf->allocated) {
		char *p;

		buf->allocated *= 2;
		p = realloc(buf->buf, buf->allocated);
		if (p == NULL) {
			free(buf->buf);
			buf->buf = NULL;
			return;
		}
		buf->buf = p;
	}
	buf->buf[buf->pos] = c;
	buf->pos++;
}

/* Represent c as a character within a quoted string, and append it to buf. */
static void tty_append_printable_char(struct string_buf *buf, unsigned char c)
{
	if (c < 0x20 || c > 0x7E) {
		append_char(buf, '\\');
		append_char(buf, '0' + ((c >> 6) & 07));
		append_char(buf, '0' + ((c >> 3) & 07));
		append_char(buf, '0' + (c & 07));
	} else {
		if (c == '\\' || c ==  '"')
			append_char(buf, '\\');
		append_char(buf, c);
	}
}

/* Search for a name of a sequence of TTY bytes.
   If found, return the name and advance *INPUT.  Return NULL otherwise. */
static const char *tty_find_named_key(unsigned char **input, size_t input_len)
{
	/* NUL-terminated list of (sequence, NUL, name, NUL) entries.
	   First match wins, even if a longer match were possible later */
	static const unsigned char named_keys[] =
#define E(SEQ, NAME) SEQ "\0" NAME "\0"
#include "tty_named_keys.h"
#undef E
		"\0";

	unsigned char *src;
	const unsigned char *nk;

	src = *input;
	if (*src >= ' ' && (*src < 0x7F || *src >= 0xA0))
		return NULL; /* Fast path */
	nk = named_keys;
	do {
		const unsigned char *p;
		size_t nk_len;

		p = strchr(nk, '\0');
		nk_len = p - nk;
		if (nk_len <= input_len && memcmp(src, nk, nk_len) == 0) {
			*input += nk_len;
			return p + 1;
		}
		nk = strchr(p + 1, '\0') + 1;
	} while (*nk != '\0');
	return NULL;
}

static const char *print_tty_data(const char *raw_data)
{
	struct string_buf buf;
	int in_printable;
	unsigned char *data, *data_pos, *data_end;

	if (!is_hex_string(raw_data))
		return strdup(raw_data);
	data = au_unescape((char *)raw_data);
	if (data == NULL)
		return NULL;
	data_end = data + strlen(raw_data) / 2;

	buf.allocated = 10;
	buf.buf = malloc(buf.allocated); /* NULL handled in append_char() */
	buf.pos = 0;
	in_printable = 0;
	data_pos = data;
	while (data_pos < data_end) {
		/* FIXME: Unicode */
		const char *desc;

		desc = tty_find_named_key(&data_pos, data_end - data_pos);
		if (desc != NULL) {
			if (in_printable != 0) {
				append_char(&buf, '"');
				in_printable = 0;
			}
			if (buf.pos != 0)
				append_char(&buf, ',');
			append_char(&buf, '<');
			while (*desc != '\0') {
				append_char(&buf, *desc);
				desc++;
			}
			append_char(&buf, '>');
		} else {
			if (in_printable == 0) {
				if (buf.pos != 0)
					append_char(&buf, ',');
				append_char(&buf, '"');
				in_printable = 1;
			}
			tty_append_printable_char(&buf, *data_pos);
			data_pos++;
		}
	}
	if (in_printable != 0)
		append_char(&buf, '"');
	append_char(&buf, '\0');
	free(data);
	return buf.buf;
}

static const char *print_session(const char *val)
{
	if (strcmp(val, "4294967295") == 0)
		return strdup("unset");
	else
		return strdup(val);
}

#define SECCOMP_RET_ACTION      0x7fff0000U
static const char *print_seccomp_code(const char *val)
{
	unsigned long code;
	char *out;
	const char *s;

	errno = 0;
        code = strtoul(val, NULL, 16);
	if (errno) {
		asprintf(&out, "conversion error(%s)", val);
		return out;
	}
	s = seccomp_i2s(code & SECCOMP_RET_ACTION);
	if (s != NULL)
		return strdup(s);
	asprintf(&out, "unknown seccomp code (%s)", val);
	return out;
}

int lookup_type(const char *name)
{
	int i;

	if (type_s2i(name, &i) != 0)
		return i;
	return AUPARSE_TYPE_UNCLASSIFIED;
}

const char *interpret(const rnode *r)
{
	const nvlist *nv = &r->nv;
	int type;
	nvnode *n;
	const char *out;
	const char *name = nvlist_get_cur_name(nv);
	const char *val = nvlist_get_cur_val(nv);

	/* Do some fixups */
	if (r->type == AUDIT_EXECVE && name[0] == 'a' && strcmp(name, "argc") &&
			!strstr(name, "_len"))
		type = AUPARSE_TYPE_ESCAPED;
	else if (r->type == AUDIT_AVC && strcmp(name, "saddr") == 0)
		type = -1;
	else if (r->type == AUDIT_USER_TTY && strcmp(name, "msg") == 0)
		type = AUPARSE_TYPE_ESCAPED;
	else if (r->type == AUDIT_NETFILTER_PKT && strcmp(name, "saddr") == 0)
		type = AUPARSE_TYPE_ADDR;
	else if (strcmp(name, "acct") == 0) {
		if (val[0] == '"')
			type = AUPARSE_TYPE_ESCAPED;
		else if (is_hex_string(val))
			type = AUPARSE_TYPE_ESCAPED;
		else
			type = -1;
	} else
		type = lookup_type(name);

	switch(type) {
		case AUPARSE_TYPE_UID:
			out = print_uid(val, 10);
			break;
		case AUPARSE_TYPE_GID:
			out = print_gid(val, 10);
			break;
		case AUPARSE_TYPE_SYSCALL:
			out = print_syscall(val, r);
			break;
		case AUPARSE_TYPE_ARCH:
			out = print_arch(val, r->machine);
			break;
		case AUPARSE_TYPE_EXIT:
			out = print_exit(val);
			break;
		case AUPARSE_TYPE_ESCAPED:
			out = print_escaped(val);
                        break;
		case AUPARSE_TYPE_PERM:
			out = print_perm(val);
			break;
		case AUPARSE_TYPE_MODE:
			out = print_mode(val,8);
			break;
		case AUPARSE_TYPE_SOCKADDR:
			out = print_sockaddr(val);
			break;
		case AUPARSE_TYPE_FLAGS:
			out = print_flags(val);
			break;
		case AUPARSE_TYPE_PROMISC:
			out = print_promiscuous(val);
			break;
		case AUPARSE_TYPE_CAPABILITY:
			out = print_capabilities(val);
			break;
		case AUPARSE_TYPE_SUCCESS:
			out = print_success(val);
			break;
		case AUPARSE_TYPE_A0:
			out = print_a0(val, r);
			break;
		case AUPARSE_TYPE_A1:
			out = print_a1(val, r);
			break;
		case AUPARSE_TYPE_A2:
			out = print_a2(val, r);
			break; 
		case AUPARSE_TYPE_A3:
			out = print_a3(val, r);
			break; 
		case AUPARSE_TYPE_SIGNAL:
			out = print_signals(val, 10);
			break; 
		case AUPARSE_TYPE_LIST:
			out = print_list(val);
			break;
		case AUPARSE_TYPE_TTY_DATA:
			out = print_tty_data(val);
			break;
		case AUPARSE_TYPE_SESSION:
			out = print_session(val);
			break;
		case AUPARSE_TYPE_CAP_BITMAP:
			out = print_cap_bitmap(val);
			break;
		case AUPARSE_TYPE_NFPROTO:
			out = print_nfproto(val);
			break; 
		case AUPARSE_TYPE_ICMPTYPE:
			out = print_icmptype(val);
			break; 
		case AUPARSE_TYPE_PROTOCOL:
			out = print_protocol(val);
			break; 
		case AUPARSE_TYPE_ADDR:
			out = print_addr(val);
			break;
		case AUPARSE_TYPE_PERSONALITY:
			out = print_personality(val);
			break;
		case AUPARSE_TYPE_SECCOMP:
			out = print_seccomp_code(val);
			break;
		case AUPARSE_TYPE_UNCLASSIFIED:
		default:
			out = strdup(val);
			break;
        }

	n = nvlist_get_cur(nv);
	n->interp_val = (char *)out;

	return out;
}
