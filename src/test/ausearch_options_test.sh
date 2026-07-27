#!/bin/sh

ausearch=${AUSEARCH:-../ausearch}

if test ! -x "$ausearch"; then
	echo "$ausearch must be built before running this test"
	exit 1
fi

expect_rejected()
{
	expected=$1
	shift
	output=$("$ausearch" "$@" --input /dev/null 2>&1)
	case "$output" in
		*"$expected"*)
			;;
		*)
			echo "ausearch accepted malformed arguments: $*"
			echo "$output"
			return 1
			;;
	esac
}

expect_rejected "Illegal value for audit event ID" --event 1junk ||
	exit 1
expect_rejected "Numeric group ID conversion error" --gid 1junk ||
	exit 1
expect_rejected "Numeric message type conversion error" --message 1300junk ||
	exit 1
expect_rejected "Process id must be a numeric value" --pid 12junk ||
	exit 1
expect_rejected "Parent process id must be a numeric value" --ppid 12junk ||
	exit 1
expect_rejected "Syscall numeric conversion error" --syscall 0junk ||
	exit 1
expect_rejected "Error converting" --session 1junk ||
	exit 1
expect_rejected "Error converting" --exit 1junk ||
	exit 1
expect_rejected "Numeric user ID conversion error" --uid 0junk ||
	exit 1
expect_rejected "Numeric user ID conversion error" --loginuid 0junk ||
	exit 1
expect_rejected "Numeric user ID conversion error" --uid 4294967296 ||
	exit 1
