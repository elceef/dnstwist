dnstwist
========
See what sort of trouble users can get in trying to type your domain name. Find similar-looking domains that adversaries can use to attack you. Can detect typosquatters, phishing attacks, fraud and corporate espionage. Useful as an additional source of targeted threat intelligence.

![Screenshot](http://i.imgur.com/RILUsjY.png)

Key features
------------
Just not to waste time there are several good reasons to give it a try:

- Wide range of efficient domain fuzzing algorithms
- Multithreaded job distribution
- Resolving domain names to IPv4 and IPv6
- Querying for NS and MX records
- Optional: Evaluating web page similarity with fuzzy hashes
- Optional: GeoIP location information
- Optional: Banner grabbing for HTTP and SMTP services
- Optional: WHOIS lookups for creation and modification date
- Optional: Output in CSV format

Running
-------
If you want *dnstwist* to develop full power, please make sure the following Python modules are present on your system. If missing, *dnstwist* **will still work**, but without many cool features.

- [A DNS toolkit for Python](http://www.dnspython.org/)
- [Python GeoIP](https://pypi.python.org/pypi/GeoIP/)
- [Python WHOIS](https://pypi.python.org/pypi/whois)
- [Requests: HTTP for Humans](http://www.python-requests.org/)
- [ssdeep Python wrapper](https://pypi.python.org/pypi/ssdeep)

If running Ubuntu or Debian, you can install dependencies like this:

```
$ sudo apt-get install python-dnspython python-geoip python-whois python-requests
```

Installation of *ssdeep* module requires just a little bit more effort:

```
$ sudo apt-get install build-essential libffi-dev python-dev python-pip automake autoconf libtool
$ sudo BUILD_LIB=1 pip install ssdeep
```

Now it is fully equipped and ready for action.

Contact
-------
To send questions, comments or a chocolate, just drop an e-mail at [marcin@ulikowski.pl](mailto:marcin@ulikowski.pl)

Any feedback is appreciated. I like to receive notifications from satisfied customers so if you were able to run the tool and you are happy with the results after just let me know.

- LinkedIn: [Marcin Ulikowski](https://pl.linkedin.com/in/elceef)
- Twitter: [@elceef](https://twitter.com/elceef)

Special thanks
--------------
- Patricia Lipp
- Steve Steiner
- Christopher Schmidt
- James Lane
- Piotr Chmyłkowski
- Eugene Kogan
- Mike Saunders
- Charles McCauley
- Sean Whalen
