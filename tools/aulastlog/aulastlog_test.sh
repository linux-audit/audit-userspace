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
