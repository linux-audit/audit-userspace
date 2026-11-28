#!/bin/sh

ausearch=${AUSEARCH:-../ausearch}
input=${srcdir:-.}/ausearch_avc_short_comm.log

if test ! -x "$ausearch"; then
	echo "$ausearch must be built before running this test" >&2
	exit 1
fi

output=$("$ausearch" --input "$input" --comm A --file x --raw 2>/dev/null) || {
	echo "ausearch rejected the AVC fixture" >&2
	exit 1
}

case "$output" in
	*'audit(1710000003.001:201)'*) ;;
	*)
		echo "ausearch skipped the short hex comm record" >&2
		exit 1
		;;
esac

case "$output" in
	*'audit(1710000006.001:202)'*) ;;
	*)
		echo "ausearch skipped the quoted comm control record" >&2
		exit 1
		;;
esac

case "$output" in
	*'audit(1710000000.001:200)'*)
		echo "ausearch accepted an incomplete AVC record" >&2
		exit 1
		;;
esac
