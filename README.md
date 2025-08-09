# Linux Audit

The Linux Audit System is designed to make Linux compliant with the requirements from Common Criteria, PCI-DSS, and other security standards by intercepting system calls and serializing audit log entries from privileged user space applications. The framework allows the configured events to be recorded to disk and distributed to plugins in realtime. Each audit event contains the date and time of event, type of event, subject identity, object acted upon, and result (success/fail) of the action if applicable.

## RUNTIME DEPENDENCIES

* coreutils
* initscripts-service (Recommended - soft requirement)
* kernel >= 5.15
* systemd

NOTE: While this repository provides support for systemd to start the audit
daemon, other init systems can be used as well. For example, [Alpine
Linux](https://git.alpinelinux.org/aports/tree/main/audit/auditd.initd) provides
an init script for OpenRC.

## BUILD-TIME DEPENDENCIES (for tar file)
* gcc (or clang)
* make
* kernel-headers >= 5.15
* systemd

## ADDITIONAL BUILD-TIME DEPENDENCIES (if using github sources)
* autoconf
* automake
* libtool

## OPTIONAL DEPENDENCIES
* libcap-ng-devel  (dropping capabilities)
* krb5-devel       (remote logging)
* python3-devel    (python bindings)
* swig             (python bindings)
* openldap-devel   (zos-remote logging)
* golang           (golang bindings)

## SUPPORTED ARCHITECTURES
* AARCH64
* ARM (some versions)
* MIPS
* PPC & PPCLE
* s390 & s390x
* x86_64 & i386

NOTE: **There is a moratorium on adding support for any new platforms.** Syscalls and other lookup tables get updated frequently. Without an active community maintaining the code, it is not sustainable to add more. If you would like to see more platforms supported, please consider working on bugs and code cleanups and then maybe we can add more. Any submitted pull requests adding a new platform with be marked with a 'wont_fix' label. It will be left available in case anyone wants to use it. But it is unsupported.

## MAIL LIST
The audit community has a [mail list](https://lists.linux-audit.osci.io/archives/list/linux-audit@lists.linux-audit.osci.io/). It is the best place to ask questions because the mail archive is searchable and therefore discoverable.

## CONFIGURING AND COMPILING
To build from the repo after cloning and installing dependencies:

```
cd audit
autoreconf -f --install
./configure --with-python3=yes --enable-gssapi-krb5=yes --with-arm \
    --with-aarch64 --with-libcap-ng=yes --without-golang --with-io_uring
make
make install
```

If you are packaging this, you probably want to do "make dist" instead and use the resulting tar file with your package building framework. A spec file is included in the git repo as an example of packaging it using rpm. This spec file is not known to be the official spec file used by any distribution. It's just an example.

## CROSS COMPILING
Cross compiling is not officially supported. There have been people that have submitted patches to make it work. But it is not documented how to make it work. It is likely that you have to somehow override CC, CXX, RANLIB, AR, LD, and NM when running configure to pickup the cross compiler, linker, archive, etc. If you have patches that fix any problems, they will be merged. If you have suggestions for how to improve cross compiling documentation, file an issue stating how to improve instructions.

## OVERVIEW
The following image illustrates the architecture and relationship of the components in this project:

![audit-components](https://github.com/linux-audit/audit-userspace/blob/assets/audit-components.png)

In the above diagram, auditd is in the middle. It interfaces with the kernel to receive events. It writes them to the audit logs. It also distributes events in realtime to audisp plugins. To load rules on 3.x audit system, you use the augenrules program. As of audit-4.0, you would use the audit-rules.service with systemctl. They in turn uses auditctl to load rules into the kernel. Auditctl is used to create, load, and delete rules; configure the kernel's backlog and other parameters; and to gather status about the audit system.

The kernel does the heavy lifting to generates the events. In the case of a trusted application such as shadow-utils, the kernel receives the event, adds origin information, timestamps, and queues the event for delivery to the audit daemon.

## DAEMON CONSIDERATIONS
### Disk Full
Almost all Security Standards are concerned about what happens when logging space fills up. Because of this, the audit daemon keeps careful track of free space and emits warnings at admin defined levels called "space left" and "admin space left". The former is considered a low disk space warning which should give the admin time to do something. The latter is more serious because you are just about out.

To get an accurate reading, the audit daemon should log to a disk partition that is reserved only for the audit daemon. This way someone using the logger command can't suddenly fill up the audit space and trigger an admin defined action. It is recommended to set aside a partition, /var/log/audit, for exclusive use by the audit daemon. The size of which depends on your audit retention policy.

### Systemd Security Settings
The audit daemon is started by systemd. Some people run the "systemd-analyze security" command. It tells you all sorts of things to do to protect your system from auditd. However, doing the things it suggests places auditd in namespaces. When that happens, the audit rules may not trigger correctly and auditd may not be able to access trusted databases. The auditd.service file is the result of trial and error based on well intentioned patches gone wrong. You can lock auditd down more, but it likely will not work as intended.

### Starting and Stopping the Daemon
The systemctl application was designed to interact with systemd to control system services. It is designed to use dbus to talk to systemd which then works to carry out the command if the user is authorized to do so. This can create a problem on shutdown.

Many people have to run in environments that require compliance to regulatory standards. One of these requirements is to record anyone's interaction with the audit trail. See [FAU_GEN1.1](https://www.niap-ccevs.org/static_html/protection-profile/469/OS%204.3%20PP/index.html#fau) clause "a" and "c" bullet point 2. This means direct file access, changes to audit configuration, or starting/stopping the daemon. We can place watches on the files to meet the requirements. However, who stopped the daemon is trickier.

Prior to systemd, people used sysvinit and then upstart. Both of those used a service command to wrap the need to send signals to the daemon to direct it to do something. SIGHUP meant reload the configuration. SIGTERM meant halt the daemon. To meet Common Criteria requirements, the Linux kernel notices any signal heading to the audit daemon and records the login uid of whoever sent it. When the audit daemon receives this signal, it queries the kernel so that it can create an event with this information.

As noted above, systemctl uses dbus to ask systemd to send the signal. Dbus loses the login uid information of who sent the signal. So, when auditd queries the kernel, the login uid is -1 which means unknown. Therefore any use of systemctl to interact with the audit daemon is non-compliant with many security standards. To solve this, the default auditd service file includes the setting:

```
RefuseManualStop=yes
```

This causes systemctl to refuse stopping the audit system. This requires us use the old service command to send signals in the user's login context so that the audit trail is not broken. To work correctly, the service command must support legacy actions. The audit daemon ships these which must be installed to

```
/usr/libexec/initscripts/legacy-actions/
```

These scripts are wrappers to "auditctl --signal" which locates the audit daemon and then sends the right signal to it. A lot of distributions want to get rid of this legacy mode of action, but it cannot be done away with. The original plan was to move dbus into the kernel where it could see both ends of a socket and transfer credentials if both parties agreed. This was shotdown back around 2010 and now we're stuck. (This also means the Linux desktop cannot meet common criteria or any serious security standards since it loses who originated any action.)

The main point is that if you use systemctl and only systemctl to manage auditd, you not in compliance with security standards that require monitoring the configuration of the audit trail.

## RULES
The audit package comes with pre-written rules. For audit-3.x, they should be located in /usr/share/audit/sample-rules. For audit-4.x, they should be located in /usr/share/audit-rules. These rules should be close enough most of the time. To use them, copy select rules to /etc/auditd/rules.d. If you look at the rules, you will notice that the filenames begin with a number. This number has the following suggested meaning:

```
10 - Kernel and auditctl configuration
20 - Rules that could match general rules - but we want a different match (override)
30 - Main rules
40 - Optional rules
50 - Server Specific rules
70 - System local rules
90 - Finalize (immutable)
```

The rules are meant to be used by the augenrules program. The augenrules program expects rules to be located in /etc/audit/rules.d. The rules will get processed in a specific order based on their natural sort order. The kernel's rule engine uses a first match wins strategy. So, the order of the rules matters.

The sample rules are not meant to be used all at the same time. They are pieces of a policy that should be thought out and individual files copied to /etc/audit/rules.d/ For example, if you wanted to set a system up in the STIG configuration, copy rules 10-base-config, 30-stig, 31-privileged, and 99-finalize. You can add more if you like. But these 4 files are a baseline policy.

If you want to learn more about writing custom rules, look for the audit.rules and auditctl man pages.

## EVENTS
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
- File being accessed
- Process being executed with arguments
- Network address
- Keystrokes
- Netfilter packet decisions

## SEARCHING AND REPORTING FROM LOGS
The intended way to view audit events is by using the ausearch program. Audit events are not serialized in the kernel and could be interlaced and out of order. To straighten this out, ausearch/aureport/auparse all put the records on a holding list until the event is complete. It then emits them in sequential order so they are presented in numeric order.

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

Sometimes aureport provides too much information. You might want a summary of files accessed by a specific user. In this case, you can combine ausearch and aureport to get the information you need. The main trick to remember is that the output of ausearch has to be in the "raw" format. For example:

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

The ausearch program also has a couple more tricks worth knowing about. It has an option, --format, which can take "csv" or "text" as options. In the case of csv, it will emit a condensed audit event normalized to be suitable as a Comma Separated Value file. In this format, you can take the audit logs and do data science queries using Excel/Sheets, python/pandas, or the R programming language.

The other option, text, can be used to turn the audit events into simple sentences that describe what the event means. There are times when it doesn't have a mapping because the event is new. In those cases, the event may not make sense until the software is updated.

## PERFORMANCE AND MONITORING
The audit system can output two sets of data to let you know how it's doing. The first method is to use:

```
auditctl -s
```

This outputs some basic information such as the kernel backlog size, the current backlog, and how many events have been lost. The backlog size is the size of the queue in records that the kernel can hold waiting for auditd to collect them. This should be around 8k or larger for a system that really does auditing. If you use the audit system to casually collect SELinux AVC's, then you can go lower to something like 256.

The current backlog tells you how many events are awaiting delivery to auditd at that instant. This number should normally be low - less than 10. If this is getting bigger and approaching the backlog limit in size, then you have a problem to look into. Either you are generating too many events (rules need adjusting) or an auditd plugin is taking too long to dequeue records. The auditd daemon is very fast at writing records to disk and can handle thousands per second.

Another way to check performance is to use

```
auditctl --signal state
cat /run/audit/auditd.state

audit version = 4.0.5
current time = 06/02/25 20:21:31
process priority = -4
writing to logs = yes
current log size = 2423 KiB
max log size = 8192 KiB
logs detected last rotate/shift = 0
space left on partition = yes
Logging partition free space 45565 MiB
space_left setting 75 MiB
admin_space_left setting 50 MiB
logging suspended = no
file system space action performed = no
admin space action performed = no
disk error detected = no
Number of active plugins = 1
current plugin queue depth = 0
max plugin queue depth used = 5
plugin queue size = 2000
plugin queue overflow detected = no
plugin queueing suspended = no
listening for network connections = no
glibc arena (total memory) is: 388 KiB, was: 388 KiB
glibc uordblks (in use memory) is: 92 KiB, was: 90 KiB
glibc fordblks (total free space) is: 295 KiB, was: 297 KiB
```

This command causes auditd to dump its internal metrics to /run/audit/auditd.state. This can tell you if auditd is healthy. Also, you can make auditd periodically update the state file by adjusting the report_interval setting in auditd.conf (note - only available in audit-4.0.5 and later). See the man page for details. Setting this allows for the continuous updating for metrics collection.

## AUPARSE
The auparse library is available to allow one to create custom reporting applications. The library is patterned after a dbase or foxpro database library and has the following categories of functions:

- General functions that affect operation of the library
- Functions that traverse events
- Accessors to event data
- Functions that traverse records in the same event
- Accessors to record data
- Functions that traverse fields in the same record
- Accessors to field data

You can write programs in one of two ways: iterate across events, records, and fields; or use the feed API to which a callback function is presented with a single, complete event that can be iterated across the records and fields. The former is best for working with files, while the latter is more appropriate for realtime data for a plugin.

## AUPLUGIN
The auplugin library helps developers write auditd plugins. It multi-threads
a plugin with a queue in between the threads. One thread pulls event records
from auditd, then enqueues them. The other thread sees the events and calls
back a function of your choosing. This keeps auditd running at top speed
since plugins keep their socket drained. The library offers functions to
manage an event queue and dispatch audit records to a callback for
processing.  Its functionality falls into several categories:

- Initialization and shutdown helpers
- Event loop processing or feeding events through libauparse
- Queue statistics and management helpers
- Buffered line readers for descriptor based input

Plugins generally follow one of two patterns.  They can use
`auplugin_event_loop()` with a record callback when raw records are
sufficient.  Alternatively `auplugin_event_feed()` queues the records
for libauparse and presents fully formed events to the callback.  The
latter is typically used when plugin logic needs structured event data.

## Audit Standards
You can find the standards to which the audit system conforms to in the ![Audit Documentation Project](https://github.com/linux-audit/audit-documentation).

