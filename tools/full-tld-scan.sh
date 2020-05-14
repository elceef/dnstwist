#!/usr/bin/env sh
#
# dnstwist's full TLD scanner script
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0

if [ $# -lt 1 ]
then
	echo "This script checks a domain name against all the top-level domains (TLD)."
	echo "Optionally it can be run only against the country code top-level domains"
	echo "(ccTLD) or the generic top-level domains (gTLD)."
	echo "For each TLD a distinct file will be created in the current directory."
	echo
	echo "Usage: $0 DOMAIN [gtld|cctld]"
	echo
	echo "Example: $0 google cctld"
	echo
	exit
fi

PUBLIC_SUFFIX_LIST="./public_suffix_list.dat"

DNSTWIST_SCRIPT="./dnstwist.py"
DNSTWIST_ARGS="--format csv"

if [ ! -f "$PUBLIC_SUFFIX_LIST" ]
then
	echo "ERROR: Cannot locate TLD database file: $PUBLIC_SUFFIX_LIST"
	echo "Please download the latest version from https://publicsuffix.org/list/public_suffix_list.dat"
	exit 1
fi

if [ ! -f "$DNSTWIST_SCRIPT" ]
then
	echo "ERROR: Cannot locate dnstwist script: $DNSTWIST_SCRIPT"
	exit 1
fi

DOMAIN="$1"

case $2 in
	gtld)
		TLDS="com org net edu info"
		;;
	cctld)
		TLDS=$(egrep -o "^[a-z]{2}$" "$PUBLIC_SUFFIX_LIST")
		;;
	*|full)
		TLDS=$(egrep -o "^[a-z]{2,}$" "$PUBLIC_SUFFIX_LIST")
esac

for tld in $TLDS
do
	echo "Running $DNSTWIST_SCRIPT $DNSTWIST_ARGS $DOMAIN.$tld"
	$DNSTWIST_SCRIPT $DNSTWIST_ARGS $DOMAIN.$tld > $DOMAIN.$tld
done

echo "Finished!"

exit 0
