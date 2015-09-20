dnstwist
========
See what sort of trouble users can get in trying to type your domain name. Find similar-looking domains that adversaries can use to attack you. Can detect fraud, phishing attacks and corporate espionage. Useful as an additional source of targeted threat intelligence.

Demo
----
![demo](http://i.imgur.com/8IeMdXO.png)

You are also welcome to see some [example reports](https://github.com/elceef/dnstwist/tree/master/examples).

Features
--------
There are several good reasons to give it a try:

* Wide range of domain fuzzing algorithms
* Resolving domain names to IPv4 and IPv6
* Queries for NS and MX records
* Optional: Evaluating web page similarity with fuzzy hashes
* Optional: GeoIP location information
* Optional: Banner grabbing for HTTP and SMTP services
* Optional: WHOIS lookups for creation and modification date
* Optional: Output in CSV format

Required modules
----------------
If you want *dnstwist* to develop full power, please make sure the following Python modules are present on your system. If missing, *dnstwist* **will still work**, but without many cool features.

* [Python GeoIP](https://pypi.python.org/pypi/GeoIP/)
* [A DNS toolkit for Python](http://www.dnspython.org/)
* [WHOIS](https://pypi.python.org/pypi/whois)
* [Requests: HTTP for Humans](http://www.python-requests.org/en/latest/)
* [ssdeep](https://pypi.python.org/pypi/ssdeep)

If running Ubuntu or Debian, you can install dependencies like this:

`$ sudo apt-get install python-dnspython python-geoip python-whois python-requests`

Installation of *ssdeep* module requires a little more effort:

`$ sudo apt-get install build-essential libffi-dev python python-dev python-pip automake autoconf libtool`
`$ sudo BUILD_LIB=1 pip install ssdeep`

Contact
-------
To send questions, comments or a chocolate, just drop an e-mail at [marcin@ulikowski.pl](mailto:marcin@ulikowski.pl)

* LinkedIn: [Marcin Ulikowski](https://pl.linkedin.com/in/elceef)
* Twitter: [@elceef](https://twitter.com/elceef)

Special thanks
--------------
* Patricia Lipp
* Steve Steiner
* Christopher Schmidt
* James Lane
* Piotr Chmyłkowski
* Eugene Kogan
