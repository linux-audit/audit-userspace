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

SEARCHING AND REPORTING FROM LOGS
---------------------------------

PERFORMANCE AND MONITORING
--------------------------

AUPARSE
-------

