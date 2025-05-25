# Repository Guidelines

This project contains the userspace tools for the Linux Audit system.  
The repository uses autotools and has optional self-tests.  
Follow the instructions below when making changes.

## Building

1. Bootstrap and configure the build. The README shows an example:

   ```
   cd audit-userspace
   autoreconf -f --install
   ./configure --with-python3=yes --enable-gssapi-krb5=yes --with-arm \
       --with-aarch64 --with-libcap-ng=yes --without-golang \
       --enable-experimental --with-io_uring
   make
   ```

2. Tests can be run with `make check` as described in INSTALL:

   ```
   2. Type 'make' to compile the package.

   3. Optionally, type 'make check' to run any self-tests that come with
      the package, generally using the just-built uninstalled binaries.
   ```

   The CI workflow uses the same commands:
   ```
   - name: Build
     run: |
       autoreconf -f --install
       ./configure --with-python3=yes --enable-gssapi-krb5=yes \
         --with-arm --with-aarch64 --with-libcap-ng=yes \
         --without-golang --enable-zos-remote \
         --enable-experimental --with-io_uring
       make -j$(nproc)

   - name: Run tests
     if: matrix.container != 'ubuntu:latest'
     run: make check
   ```

3. Installation (`make install`) is typically performed only after
successful tests.

## Project Structure for Navigation

- `/src`: This is where the code that makes up auditd, audictl, ausearch, and aureport is located
- `/common`: A library of internal routines
- `/lib`: This is where the code for libaudit is located
- `/auparse`: This is where the code for libauparse is located
- `/audisp`: This is where we find the code for the real time event dispatcher (which is linked into auditd) and its plugins.
  - `/plugins`: The main directory holding all of the auditd plugins
- `/tools`: This holds the code for ausyscall, aulast, and aulastlog
- `/docs`: This holds all of the man pages
- `/bindings`: This holds swig based python binds for libaudit and hand written python bindings for libauparse
- `/contrib`: This holds an example real time plugin

## Code Style

Contributions should follow the Linux Kernel coding style:

```
So, if you would like to test it and report issues or even contribute code
feel free to do so. But please discuss the contribution first to ensure
that its acceptable. This project uses the Linux Kernel Style Guideline.
Please follow it if you wish to contribute.
```

In practice this means:

- Indent with tabs (8 spaces per tab).
- Keep lines within ~80 columns.
- Place braces and other formatting as in the kernel style.

## Commit Messages

- Use a concise one-line summary followed by a blank line and additional
  details if needed (similar to existing commits).

## Special Files

The `rules` directory contains groups of audit rules intended for
`augenrules` and should remain organized as documented:

```
This group of rules are meant to be used with the augenrules program.
The augenrules program expects rules to be located in /etc/audit/rules.d/
The rules will get processed in a specific order based on their natural
sort order. To make things easier to use, the files in this directory are
organized into groups with the following meanings:

 10 - Kernel and auditctl configuration
 20 - Rules that could match general rules but we want a different match
 30 - Main rules
 40 - Optional rules
 50 - Server Specific rules
 70 - System local rules
 90 - Finalize (immutable)
```

When editing rule files, keep them in the correct group and preserve the
intended ordering.

## Summary

- Build with `autoreconf`, `configure`, and `make`.
- Run `make check` to execute the self-tests.
- Follow Linux Kernel coding style (tabs, 80 columns).
- Keep commit messages short and descriptive.
- Maintain rule file organization as described in `rules/README-rules`.

These guidelines should help future contributors and automated tools
work consistently within the audit-userspace repository.

