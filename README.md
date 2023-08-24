Linux Audit
===========

The Linux Audit System is designed to make Linux compliant with the requirements from Common Criteria, DSS-PCI, and other security standards by intercepting system calls and serializing audit log entries from privileged user space applications. The framework allows the configured the events to be recorded from the set of all events that are possible to be audited. Each audit record contains the date and time of event, type of event, subject identity, user identity, and result (success/fail) of the action if applicable.

RUNTIME DEPENDENCIES
--------------------
* coreutils
* initscripts-service
* kernel >= 3.0 
* systemd

BUILD-TIME DEPENDENCIES
-----------------------
* gcc (or clang)
* autoconf
* automake
* libtool
* make
* kernel-headers >= 3.0
* systemd-devel

OPTIONAL DEPENDENCIES
---------------------
* golang
* krb5-devel
* libcap-ng-devel
* openldap-devel
* python3-devel
* swig

SUPPORTED ARCHITECTURES
-----------------------
* AARCH64
* ARM (some versions)
* PPC & PPCLE
* s390 & s390x
* x86_64 & i386

NOTE: **There is a moratorium on adding support for any new platforms.** Syscalls and other lookup tables get updated frequently. Without an active community with more people maintaining the code, it is not sustainable to add more. If you would like to see more platforms supported, please consider working on bugs and code cleanups and then maybe we can add more. Any submitted pull requests adding a new platform with be marked with a 'wont_fix' label. It will be left available in case anyone wants to use it. But it is unsupported.

MAIL LIST
---------
The audit community has a [mail list](http://www.redhat.com/mailman/listinfo/linux-audit). It is the best place to ask questions because the mail archive is searchable and therefore discoverable.

CONFIGURING AND COMPILING
-------------------------

To build from the repo after cloning and installing dependencies:

```
cd audit
./autogen.sh
./configure --with-python3=yes --enable-gssapi-krb5=yes --with-arm \
    --with-aarch64 --with-libcap-ng=yes --without-golang --with-io_uring
make
make install
```

But if you are packaging this, you probably want to do "make dist" and
use the resulting tar file with your package building framework. A spec file
is included in the git repo as an example of packaging it using rpm. This
spec file is not known to be the official spec file used by any distribution.
It's just an example.

CROSS COMPILING
---------------
Cross compiling is not supported. The audit system builds native binaries at
build time and uses those to create sorted btrees for fast lookup during
event processing and reporting. To enable cross compiling, those binaries
would need to be rewritten in python or another scripting langauge. No one is
currently working on that.

OVERVIEW
--------
The following image illustrates the architecture and relationship of the components shipped as part of this project:

![audit-components](https://github.com/linux-audit/audit-userspace/blob/assets/audit-components.png)

In the above diagram, auditd is in the middle. It interfaces with the kernel to receive events. It writes them to the audit logs. It also distributes events in realtime to audisp plugins. To load rules, you use the augenrules program. It in turn uses auditctl to load them into the kernel. Auditctl is used to create, load, and delete rules; configure the kernel's backlog and other parameters; and to gather status about the audit system. The kernel does the heavy lifting and generates the events. In the case of a trusted application, shadow-utils for example, it collects the event, adds origin information, timestamps, and queues the event for delivery to the audit daemon.

DAEMON CONSIDERATIONS
---------------------
Almost all Security Standards are concerned about what happens when logging space fills up. Because of this, the audit daemon keeps careful track of free space and emits warnings at admin defined levels called "space left" and "admin space left". The former is considered a low disk space warning which should give the admin time to do something. The latter is more serious because you are just about out.

To get an accurate reading, the audit daemon should log to a disk partition that is reserved only for the audit daemon. This way someone using the logger command can't suddenly fill up the audit space and trigger an admin defined action. It is recommended to set aside a partition, /var/log/audit, for use by the audit daemon.

The audit daemon is started by systemd. Some people run the "systemd-analyze security" command. It tells you all sorts of things to do to protect your system from auditd. However, doing the things it suggests places auditd in namespaces. When that happens, the audit rules may not trigger correctly and auditd may not be able to access trusted databases either. The audit service files are the results of trial and error based on well intentioned patchs gone wrong. You can lock it down more, but you probably will break something.

RULES
-----
The audit package comes with pre-written rules. The are likely located in /usr/share/audit/sample-rules. This will solve your problem most of the time. If you look at the rules, you will notice that they begin with a number. This number has the following suggested meaning:

```
10 - Kernel and auditctl configuration
20 - Rules that could match general rules but we want a different match
30 - Main rules
40 - Optional rules
50 - Server Specific rules
70 - System local rules
90 - Finalize (immutable)
```

The rules are meant to be used by the augenrules program. The augenrules program expects rules to be located in /etc/audit/rules.d/ The rules will get processed in a specific order based on their natural sort order. To use them, copy them from the /usr/share/audit/sample-rules directory to /etc/audit/rules.d.

The rules are not meant to be used all at once. They are pieces of a policy that should be thought out and individual files copied to /etc/audit/rules.d/ For example, if you wanted to set a system up in the STIG configuration, copy rules 10-base-config, 30-stig, 31-privileged, and 99-finalize. You can add more if you like.

If you want to learn more about writing custom rules, look for the audit.rules and auditctl man pages.

EVENTS
------
The audit events come in two flavors: simple and compound. A simple event is sent from a trusted application such as sshd. It has only one record in th event. A compound event has multiple records in the same event. They are considered to be in the same event because they have the same timestamp and serial number.

Audit events all start with the following preamble:

```
type=<something> msg=audit(1679598373.352:1256072):
```

The first item is the record type. This tells you what kind of information and the meaning of the record is. Next there is a msg=audit field which has parenthesis. Inside it is the time in seconds from the epoch, a millisecond time, and a serial number. The millisecond is used to separate events within the same second. The serial number is used to separate events within the same millisecond.

After the time stamp comes fields that are in key=value format. What these field are varies by record type. But they should have the following:

- Login ID (auid): the user ID that the user originally logged in with regardless of changing the real or effective user ID afterwards.
- Session ID (ses): an identifier unique to the specific login in case the same user has multiple logins.
- User ID (uid): the real user ID of the process at the time the audit event was generated.
- Process ID (pid): the process ID of the subject that caused the event.
- Results (res): Whether the subject's action was a success or failure.

There can be optional information, depending on the kind of the event, which may include, but is not limited to:

- The system call that a process made that caused the event
- The group ID of the subject
- Hostname or terminal the subject used for performing the action

SEARCHING AND REPORTING FROM LOGS
---------------------------------
The intended way to view audit events is by using the ausearch program. Audit events are not serialized in the kernel and could be interlaced and out of order. To straighten this out, ausearch/report/auparse all put the records on a list intil the event is complete. It then emits them in sequential order so they are presented in order.

Some fields are searchable. Typically you will search for a specific kind of event, a specific process, a specific file, or a specific user. The ausearch man page details all the different options. But we wll list some examples below:

```
```

Sometimes you want summary information. In this case you would want to use the aureport program. It can summarize all of the searchable kinds of fields. It can all so pick out all of a kind of data without summary so that you can use ausearch to see the full event. Below are some examples of using aureport:

```
```

Sometimes aureport provides too much information. You might want files summarized by accessed by a specific user. In this case, you can combine ausearch and aureport to get the information you need. For example:

```
```

The ausearch program also has a couple more tricks worth knowing about. It has an option, --format, which can take "csv" or "text" as options. In the case of csv, it will emit a condensed audit event normalized to be suitable as a Comma Separated Value file. In this format, you can take the audit logs and do data scince queries using python/pandas or the R programming language.

The other option, text, can be used to turn the audit events into simple sentences that describe what the event means. There are times when it doesn't have a mapping because the event is new. In those cases, the event may not make sense until the software is updated.

PERFORMANCE AND MONITORING
--------------------------
The audit system can output two sets of data to let you know how it's doing. The first method is to use:

```
auditctl -s
```

This outputs some basic information such as the kernel backlog size, the current backlog, and how many events have been lost. The backlog size is the size of the queue in records that the kernel can hold waiting for auditd to collect them. This should be around 8k or larger for a system that really does auditing. If you use the audit system to casually collect SELinux AVC's, then you can go lower to say 256.

The current backlog tells you how many events are awaitin delivery to auditd. This number should normally be low - less than 10. If this is getting bigger and approaching the backlog limit in size, then you have a problem to look into. Either you are generating too many events or an auditd plugin is taking too long to dequeue records.

Another way to check performance is to use

```
auditctl --signal state
```

This command causes auditd to dump its internal metrics.

AUPARSE
-------

