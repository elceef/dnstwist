#!/usr/bin/env sh
#
# dnstwist - Full TLD scan script
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0

echo "==============================="
echo "dnstwist - Full TLD scan script"
echo "==============================="
echo

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

EFFECTIVE_TLD_NAMES="../database/effective_tld_names.dat"

DNSTWIST_SCRIPT="../dnstwist.py"
DNSTWIST_ARGS="--csv"

if [ ! -f "$EFFECTIVE_TLD_NAMES" ]
then
	echo "ERROR: Cannot locate file: $EFFECTIVE_TLD_NAMES"
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
		TLDS=$(egrep -o "^[a-z]{2}$" "$EFFECTIVE_TLD_NAMES")
		;;
	*|full)
		TLDS=$(egrep -o "^[a-z]{2,}$" "$EFFECTIVE_TLD_NAMES")
esac

for tld in $TLDS
do
	echo "Running dnstwist against: $DOMAIN.$tld"
	$DNSTWIST_SCRIPT "$DNSTWIST_ARGS" "$DOMAIN.$tld" > "$DOMAIN.$tld"
done

echo "Finished!"

exit 0
