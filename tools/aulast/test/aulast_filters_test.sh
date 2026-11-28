#!/bin/sh

set -eu

aulast=$(cd .. && pwd)/aulast
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' 0

cat > "$test_dir/events.log" <<'EOF'
type=USER_LOGIN msg=audit(1700000000.001:1): pid=100 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="bob" exe="/usr/bin/login" hostname=? addr=? terminal=pts/2 res=failed'
type=USER_LOGIN msg=audit(1700000001.001:2): pid=101 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="alice" exe="/usr/bin/login" hostname=? addr=? terminal=pts/1 res=failed'
type=USER_LOGIN msg=audit(1700000002.001:3): pid=102 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="alice" exe="/usr/bin/login" hostname=? addr=? terminal=pts/12 res=failed'
type=USER_END msg=audit(1700000003.001:4): pid=104 uid=0 auid=4294967295 ses=4294967295
type=USER_LOGIN msg=audit(1700000004.001:5): pid=200 uid=0 auid=0 ses=10 msg='op=login acct="dave" exe="/usr/bin/login" hostname=? addr=? terminal=tty3 res=success'
type=USER_LOGIN msg=audit(1700000005.001:6): pid=103 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="carol" exe="/usr/bin/login" hostname=? addr=? terminal=/dev/tty0 res=failed'
type=USER_END msg=audit(1700000006.001:7): pid=105 uid=0 auid=4294967295 ses=4294967295
EOF

# Arguments are the expected rows and filters; exit nonzero on a mismatch.
check_report()
{
	expected=$1
	shift
	output=$("$aulast" -f "$test_dir/events.log" --bad "$@") || exit 1
	actual=$(printf '%s\n' "$output" | awk 'NF { print $1, $2 }')
	if test "$actual" != "$expected"; then
		echo "unexpected report for $*: $actual"
		exit 1
	fi
}

check_report 'alice pts/1' --tty pts/1
check_report 'alice pts/1' --user alice --tty pts/1
check_report 'alice pts/1' --tty /dev/pts/1
check_report 'alice pts/1' --tty 1
check_report 'alice pts/12' --tty pts/12
check_report 'carol tty0' --tty 0
check_report 'carol tty0' --tty tty0
check_report 'carol tty0' --tty /dev/tty0

# Arguments are expected report/raw rows and filters; exit nonzero on mismatch.
check_extract()
{
	expected_report=$1
	expected_raw=$2
	shift 2
	output=$(cd "$test_dir" &&
		"$aulast" -f events.log --bad --extract "$@") || exit 1
	actual_report=$(printf '%s\n' "$output" |
		awk 'NF { print $1, $2 }')
	actual_raw=$(sed -n \
		's/.*acct="\([^"]*\)".*terminal=\([^ ]*\).*/\1 \2/p' \
		"$test_dir/aulast.log")
	expected_lines=$(printf '%s\n' "$expected_raw" | wc -l)
	actual_lines=$(wc -l < "$test_dir/aulast.log")
	if test "$actual_report" != "$expected_report" ||
	   test "$actual_raw" != "$expected_raw" ||
	   test "$actual_lines" -ne "$expected_lines"; then
		echo "unexpected bad-login extract for $*"
		echo "report: $actual_report"
		echo "raw: $actual_raw"
		exit 1
	fi
}

check_extract 'alice pts/1' 'alice pts/1' --user alice --tty pts/1
check_extract 'carol tty0' 'carol /dev/tty0' --tty 0
check_extract 'bob pts/2
alice pts/1
alice pts/12
carol tty0' 'bob pts/2
alice pts/1
alice pts/12
carol /dev/tty0'
