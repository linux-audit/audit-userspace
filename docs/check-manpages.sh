#!/bin/sh
#
# Check every manual page source in the repository with groff warnings enabled.
# man exits successfully for formatter warnings, so stderr is treated as a
# test failure.

set -u

: "${MAN:=man}"
: "${top_srcdir:=${top_builddir:-..}}"
: "${top_builddir:=$top_srcdir}"

if ! command -v "$MAN" >/dev/null 2>&1; then
	echo "SKIP: man command not found"
	exit 77
fi

if command -v locale >/dev/null 2>&1; then
	if ! LC_ALL=C.UTF-8 locale charmap >/dev/null 2>&1; then
		echo "SKIP: C.UTF-8 locale not available"
		exit 77
	fi
fi

if ! "$MAN" --help 2>&1 | grep -- "--warnings" >/dev/null 2>&1; then
	echo "SKIP: man command does not support --warnings"
	exit 77
fi

failed=0
found=0
page_list=$(mktemp "${TMPDIR:-/tmp}/audit-manpages.XXXXXX") || exit 1
trap 'rm -f "$page_list"' EXIT HUP INT TERM

find "$top_srcdir" \
	-type d \( -name .git -o -name .libs -o -name autom4te.cache \) \
	-prune -o -type f -name '*.[1-9]' -print > "$page_list" || exit 1
if test "$top_builddir" != "$top_srcdir"; then
	find "$top_builddir" \
		-type d \( -name .git -o -name .libs -o -name autom4te.cache \) \
		-prune -o -type f -name '*.[1-9]' -print \
		>> "$page_list" || exit 1
fi
sort -u "$page_list" -o "$page_list" || exit 1

while IFS= read -r page; do
	found=1

	# .so-only stubs redirect to another page via a manpath-relative
	# path (e.g. "man3/foo.3") that cannot resolve under man -l.
	# Skip them; they work correctly once installed.
	if grep -qx '\.so man[0-9]/.*' "$page" 2>/dev/null; then
		continue
	fi

	output=$(
		LC_ALL=C.UTF-8 MANROFFSEQ='' MANWIDTH=80 \
			"$MAN" --warnings -E UTF-8 -l -Tutf8 -Z "$page" \
			2>&1 >/dev/null
	)
	status=$?

	if test $status -ne 0 || test -n "$output"; then
		failed=1
		echo "$page:"
		if test -n "$output"; then
			printf '%s\n' "$output"
		fi
		if test $status -ne 0; then
			echo "man exited with status $status"
		fi
	fi
done < "$page_list"

if test $found -eq 0; then
	echo "No manual pages found"
	exit 1
fi

exit $failed
