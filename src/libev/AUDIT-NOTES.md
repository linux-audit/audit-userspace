# How audit alters libev

When a new release happens, it is unpacked and the ev_iouring.c file is
removed. It has a number of coding issues and people constantly want
to patch it, but audit doesn't use it. So, it's removed so everyone
understands it's not used.

Next, this patch is applied: [commit 6d6355](https://github.com/linux-audit/audit-userspace/commit/06d6355dacfc8e5cd6ad076253f427efd4109b0a). This patch
fixes a number of static analysis and compiler warnings. Otherwise, I really
do not want patches against libev. Anything wrong really needs to be
reported upstream.

As of July 2026, the last release is 4.33 from March 18, 2020.
