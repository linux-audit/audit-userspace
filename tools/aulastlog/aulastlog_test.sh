#!/bin/sh

# Verify that an empty passwd enumeration produces an empty report.
output=$(AULASTLOG_TEST_EMPTY_PASSWD=1 \
	./aulastlog_test --stdin </dev/null) || {
	echo "aulastlog failed with an empty passwd enumeration"
	exit 1
}

expected="Username         Port         From                       Latest"
if test "$output" != "$expected"; then
	echo "unexpected empty-passwd report: $output"
	exit 1
fi

# Verify that a missing timestamp does not update or crash on a matching user.
event='type=USER_LOGIN msg=audit(1.000:1): pid=1 uid=0 auid=1234'
event="$event ses=1 hostname=? terminal=tty1 res=success"
output=$(printf '%s\n' "$event" | AULASTLOG_TEST_NULL_TIMESTAMP=1 \
	./aulastlog_test --stdin --user test-user) || {
	echo "aulastlog failed with a NULL event timestamp"
	exit 1
}

case "$output" in
	*"test-user"*"**Never logged in**") ;;
	*)
		echo "unexpected null-timestamp report: $output"
		exit 1
		;;
esac
