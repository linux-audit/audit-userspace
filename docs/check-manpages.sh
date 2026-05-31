#!/bin/sh
#
# Check every manual page source in this directory with groff warnings enabled.
# man exits successfully for formatter warnings, so stderr is treated as a
# test failure.

set -u

: "${MAN:=man}"
: "${srcdir:=.}"

if test "$srcdir" = "."; then
	case "$0" in
	*/*)
		srcdir=${0%/*}
		;;
	esac
fi

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

for page in "$srcdir"/*.[0-9]; do
	test -e "$page" || continue
	found=1

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
done

if test $found -eq 0; then
	echo "No manual pages found"
	exit 1
fi

exit $failed
