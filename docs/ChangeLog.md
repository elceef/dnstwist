Change log
==========

This is the list of all noteworthy changes made in every release of the tool.

dnstwist 1.02
-------------

- Added Docker and MacOSX support
- Added JSON output
- Added new fuzzer: "Addition"
- Changed CLI output: new colors and percentage progress indicator
- Added QWERTZ and AZERTY keyboard layouts for wider typo coverage
- Added full-tld-scan.sh script

dnstwist 1.01
-------------

- Added --mxcheck option to test if SMTP servers from DNS MX record can be used
  to intercept misdirected e-mails.
- Added --dictionary option to generate additional domain variants.
- Added URL parser which extends --ssdeep functionality.
- Added new glyph definitions to the homoglyph fuzzing function.
- Added local copies of GeoIP and TLD databases.
- Added a few various and common phishing domain transforms.

dnstwist 1.00
-------------

- First stable release with multithreaded job distribution.
- Extra features include: evaluating web pages similarity with fuzzy hashes,
  banner grabbing for HTTP and SMTP, GeoIP and WHOIS lookups.
