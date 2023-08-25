Linux Audit
===========

The Linux Audit System is designed to make Linux compliant with the requirements from Common Criteria, DSS-PCI, and other security standards by intercepting system calls and serializing audit log entries from privileged user space applications. The framework allows the configured events to be recorded to disk and distributed to plugins in realtime. Each audit event contains the date and time of event, type of event, subject identity, object acted upon, and result (success/fail) of the action if applicable.

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

NOTE: **There is a moratorium on adding support for any new platforms.** Syscalls and other lookup tables get updated frequently. Without an active community maintaining the code, it is not sustainable to add more. If you would like to see more platforms supported, please consider working on bugs and code cleanups and then maybe we can add more. Any submitted pull requests adding a new platform with be marked with a 'wont_fix' label. It will be left available in case anyone wants to use it. But it is unsupported.

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

If you are packaging this, you probably want to do "make dist" instead and use the resulting tar file with your package building framework. A spec file is included in the git repo as an example of packaging it using rpm. This spec file is not known to be the official spec file used by any distribution. It's just an example.

CROSS COMPILING
---------------
Cross compiling is not supported. The audit system builds native binaries at
build time and uses those to create sorted btrees for fast lookup during
event processing and reporting. To enable cross compiling, those binaries
would need to be rewritten in python or another scripting langauge. No one is
currently working on that.

OVERVIEW
--------
The following image illustrates the architecture and relationship of the components in this project:

![audit-components](https://github.com/linux-audit/audit-userspace/blob/assets/audit-components.png)

In the above diagram, auditd is in the middle. It interfaces with the kernel to receive events. It writes them to the audit logs. It also distributes events in realtime to audisp plugins. To load rules, you use the augenrules program. It in turn uses auditctl to load them into the kernel. Auditctl is used to create, load, and delete rules; configure the kernel's backlog and other parameters; and to gather status about the audit system. The kernel does the heavy lifting to generates the events. In the case of a trusted application, shadow-utils for example, it collects the event, adds origin information, timestamps, and queues the event for delivery to the audit daemon.

DAEMON CONSIDERATIONS
---------------------
Almost all Security Standards are concerned about what happens when logging space fills up. Because of this, the audit daemon keeps careful track of free space and emits warnings at admin defined levels called "space left" and "admin space left". The former is considered a low disk space warning which should give the admin time to do something. The latter is more serious because you are just about out.

To get an accurate reading, the audit daemon should log to a disk partition that is reserved only for the audit daemon. This way someone using the logger command can't suddenly fill up the audit space and trigger an admin defined action. It is recommended to set aside a partition, /var/log/audit, for use by the audit daemon. The size of which depends on your audit retention policy.

The audit daemon is started by systemd. Some people run the "systemd-analyze security" command. It tells you all sorts of things to do to protect your system from auditd. However, doing the things it suggests places auditd in namespaces. When that happens, the audit rules may not trigger correctly and auditd may not be able to access trusted databases. The audit service files are the result of trial and error based on well intentioned patchs gone wrong. You can lock it down more, but you probably will break something.

RULES
-----
The audit package comes with pre-written rules. They should be located in /usr/share/audit/sample-rules. These rules should solve your problem most of the time. If you look at the rules, you will notice that the filenames begin with a number. This number has the following suggested meaning:

```
10 - Kernel and auditctl configuration
20 - Rules that could match general rules - but we want a different match (override)
30 - Main rules
40 - Optional rules
50 - Server Specific rules
70 - System local rules
90 - Finalize (immutable)
```

The rules are meant to be used by the augenrules program. The augenrules program expects rules to be located in /etc/audit/rules.d/ The rules will get processed in a specific order based on their natural sort order. To use them, copy them from the /usr/share/audit/sample-rules directory to /etc/audit/rules.d. The kernel's rule engine uses a first match wins strategy. So, the order of the rules matters.

The sample rules are not meant to be used all at the same time. They are pieces of a policy that should be thought out and individual files copied to /etc/audit/rules.d/ For example, if you wanted to set a system up in the STIG configuration, copy rules 10-base-config, 30-stig, 31-privileged, and 99-finalize. You can add more if you like. But these 4 files are a baseline policy.

If you want to learn more about writing custom rules, look for the audit.rules and auditctl man pages.

EVENTS
------
The audit events come in two flavors: simple and compound. A simple event is sent from a trusted application such as sshd. It has only one record in the event. A compound event has multiple records in the same event. These multiple records are considered to be in the same event because they have the same timestamp and serial number.

Audit events all start with the following preamble:

```
type=<something> msg=audit(1679598373.352:1256072):
```

The first item is the record type. This tells you what kind of information and the meaning of the record is. Next there is a msg=audit field which has parenthesis. Inside it is the time since the epoch in seconds, a millisecond time, and a serial number. The millisecond is used to separate events within the same second. The serial number is used to separate events within the same millisecond.

After the time stamp comes fields that are in key=value format. What these field are varies by record type. But the overall event should have the following:

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
The intended way to view audit events is by using the ausearch program. Audit events are not serialized in the kernel and could be interlaced and out of order. To straighten this out, ausearch/aureport/auparse all put the records on a holding list until the event is complete. It then emits them in sequential order so they are presented in order.

Some fields are searchable. Typically you will search for a specific kind of event, a specific process, a specific file, or a specific user. The ausearch man page details all the different options. Here are some example searches:

```
Searching for bad logins:
ausearch -m USER_LOGIN --success no -i

Searching for events on shadow file today:
ausearch --start today -f shadow -i

Searching for failed file opens for user acct 1000:
ausearch -m PATH --success no --syscall open --loginuid 1000 -i
```

Sometimes you want summary information. In this case you would want to use the aureport program. It can summarize all of the searchable kinds of fields. It can also pick out all of a kind of data without summary so that you can later use ausearch to see the full event. Below are some examples of using aureport:

```
Monthly summary report:
aureport --start this-month --summary

Files accessed today summary:
aureport --start today --file --summary

Syscall events summarized by key:
aureport --start today --key --summary

All account modifications this month:
aureport --start this-month --mods -i

Report all log files and their time range:
aureport -t
```

Sometimes aureport provides too much information. You might want files summarized by accessed by a specific user. In this case, you can combine ausearch and aureport to get the information you need. The main trick to remember is that the output of ausearch has to be in the "raw" format. For example:

```
Summary of files accessed by uid 1000
ausearch --start today --auid 1000 --raw | aureport --file --summary

Summary of files accessed by vi
ausearch --start this-week -x vi --raw | aureport --file --summary

Summary of programs with files access associated with the unsuccessful-access key
ausearch --start this-month --key unsuccessful-access --raw | aureport -x --summary -i

Hosts user logged in from
ausearch --start this-week -m user_login --raw | aureport --host --summary
```

The ausearch program also has a couple more tricks worth knowing about. It has an option, --format, which can take "csv" or "text" as options. In the case of csv, it will emit a condensed audit event normalized to be suitable as a Comma Separated Value file. In this format, you can take the audit logs and do data science queries using python/pandas or the R programming language.

The other option, text, can be used to turn the audit events into simple sentences that describe what the event means. There are times when it doesn't have a mapping because the event is new. In those cases, the event may not make sense until the software is updated.

PERFORMANCE AND MONITORING
--------------------------
The audit system can output two sets of data to let you know how it's doing. The first method is to use:

```
auditctl -s
```

This outputs some basic information such as the kernel backlog size, the current backlog, and how many events have been lost. The backlog size is the size of the queue in records that the kernel can hold records waiting for auditd to collect them. This should be around 8k or larger for a system that really does auditing. If you use the audit system to casually collect SELinux AVC's, then you can go lower to something like 256.

The current backlog tells you how many events are awaiting delivery to auditd at that instant. This number should normally be low - less than 10. If this is getting bigger and approaching the backlog limit in size, then you have a problem to look into. Either you are generating too many events or an auditd plugin is taking too long to dequeue records. The auditd deamon is very fast at writing records to disk and can handle thousands per second.

Another way to check performance is to use

```
auditctl --signal state
cat /var/run/auditd.state

audit version = 3.1.2
current time = 08/24/23 20:21:31
process priority = -4
writing to logs = yes
current log size = 2423 KB
max log size = 8192 KB
logs detected last rotate/shift = 0
space left on partition = yes
Logging partition free space 45565 MB
space_left setting 75 MB
admin_space_left setting 50 MB
logging suspended = no
file system space action performed = no
admin space action performed = no
disk error detected = no
Number of active plugins = 1
current plugin queue depth = 0
max plugin queue depth used = 4
plugin queue size = 2000
plugin queue overflow detected = no
plugin queueing suspended = no
listening for network connections = no
```

This command causes auditd to dump its internal metrics to /var/run/auditd.state. This can tell you if auditd is healthy.

AUPARSE
-------
The auparse library is available to allow one to create custom reporting applications. The library is patterned after a dbase or foxpro database library and hass the following categories of functions:

- General functions that affect operation of the library
- Functions that traverse events
- Accessors to event data
- Functions that traverse records in the same event
- Accessors to record data
- Functions that traverse fields in the same record
- Accessors to field data

You can write programs in one of two ways: iterate across events, records, and fields; or use the feed API and to which a callback function is presented with a single, complete event that can be iterated across the records and fields. The former is best for working with files, while the latter is more appropriate for realtime data for a plugin.

