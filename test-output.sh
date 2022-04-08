#!/bin/bash
set -e

image=$1

echo "running dnstwist to test output"

# run dnstwist and grab the putput
output=$(docker run $image -f json -a -g 1.com)

if ! command -v jq &> /dev/null
then
    echo "installing jq"
    brew install jq
fi

# check the type of the top level JSON entity - should be an array
type=$(echo $output | jq -r '. | type')
if [[ $type != "array" ]]
then
  echo "test failed: JSON output type was not array, got $type"
  exit 1
fi

# grab an example permutation which has all DNS record types
examplePermutation=$(echo $output | jq '[.[]|select(.dns_a and .dns_mx and .dns_ns)][0]')
if [[ $examplePermutation = "null" ]]
then
  echo "test failed: couldn't find result with dns_a, dns_mx, dns_ns keys"
  exit 1
fi

# check DNS types
type=$(echo $examplePermutation | jq -r '[.dns_a, .dns_mx, .dns_ns] | .[] | type' | uniq)
if [[ $type != "array" ]]
then
  echo "test failed: dns_a, dns_mx, dns_ns fields must be arrays, got $type"
  exit 1
fi

# check DNS element types
type=$(echo $examplePermutation | jq -r '[.dns_a[0], .dns_mx[0], .dns_ns[0]] | .[] | type' | uniq)
if [[ $type != "string" ]]
then
  echo "test failed: dns_a, dns_mx, dns_ns array values must be strings, got $type"
  exit 1
fi

# check remaining fields
type=$(echo $examplePermutation | jq -r '[.domain, .fuzzer, .geoip] | .[] | type' | uniq)
if [[ $type != "string" ]]
then
  echo "test failed: domain, fuzzer, geoip fields must be strings, got $type"
  exit 1
fi

echo "output test passed"
