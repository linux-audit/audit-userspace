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
* gcc
* autoconf
* automake
* libtool
* make
* kernel-headers >= 3.0
* systemd-devel

Optional Dependencies
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

NOTE: There is a moratorium on adding support for any new platforms. Syscalls and other lookup tables get updated frequently. Without an active community with more people maintaining the code, it is not sustainable to add more. If you would like to see more platforms support, please consider working on bugs and code cleanups and then maybe we can add more.

MAIL LIST
---------
The audit community has a [mail list](http://www.redhat.com/mailman/listinfo/linux-audit). It is the best place to ask questions because the mail archive is searchable and therefore discoverable.

CONFIGURING AND COMPILING
-------------------------

To build from the repo after cloning and installing dependencies:

```bash
cd audit
./autogen.sh
./configure --with-python3=yes --enable-gssapi-krb5=yes --with-arm \
    --with-aarch64 --with-libcap-ng=yes --without-golang --with-io_uring
make
make install
```

But if you are packaging this, you probably want to do "make dist" and
use the resulting tar file with your package building framework.

OVERVIEW
--------

RULES
-----

SEARCHING AND REPORTING FROM LOGS
---------------------------------

PERFORMANCE AND MONITORING
--------------------------

