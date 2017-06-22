                     _           _            _     _
                  __| |_ __  ___| |___      _(_)___| |_
                 / _` | '_ \/ __| __\ \ /\ / / / __| __|
                | (_| | | | \__ \ |_ \ V  V /| \__ \ |_
                 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__|


See what sort of trouble users can get in trying to type your domain name.
Find similar-looking domains that adversaries can use to attack you. Can detect
typosquatters, phishing attacks, fraud and corporate espionage. Useful as an
additional source of targeted threat intelligence.

![Demo](/docs/screens/demo.gif)

The idea is quite straightforward: *dnstwist* takes in your domain name as a
seed, generates a list of potential phishing domains and then checks to see if
they are registered.
Additionally it can test if the mail server from MX record can be used to
intercept misdirected corporate e-mails and it can generate fuzzy hashes of the
web pages to see if they are live phishing sites.


Key features
------------

- A wide range of efficient domain fuzzing algorithms
- Unicode domain names (IDN)
- Multithreaded job distribution
- Queries A, AAAA, NS and MX records
- Evaluates web page similarity with fuzzy hashes to find live phishing sites
- Tests if MX host (mail server) can be used to intercept misdirected e-mails
- Additional domain variants using dictionary files
- GeoIP location information
- Grabs HTTP and SMTP service banners
- WHOIS lookups for creation and modification date
- Output in CSV and JSON format


Requirements
------------

**Linux**

Ubuntu Linux is the primary development platform. If running Ubuntu 15.04 or
newer, you can install dependencies like this:

```
$ sudo apt-get install python-dnspython python-geoip python-whois \
python-requests python-ssdeep python-cffi
```

Alternately, you can use Python tooling. This can be done within a virtual
environment to avoid conflicts with other installations. However, you will
still need a couple of libraries installed at the system level.

```
$ sudo apt-get install libgeoip-dev libffi-dev
$ BUILD_LIB=1 pip install -r requirements.txt
```

**OSX**

If you're on a Mac, you can install dnstwist via
[Homebrew](https://github.com/Homebrew/homebrew) like so:

```
$ brew install dnstwist
```

This is going to install `dnstwist.py` as `dnstwist` only, along with all
requirements mentioned above. The usage is the same, you can just omit the
file extension, and the binary will be added to `PATH`.

**Docker**

If you use Docker, you can pull official image from Docker Hub and run it:

```
$ docker pull elceef/dnstwist
$ docker run elceef/dnstwist example.com
```


How to use
----------

To start, it's a good idea to enter only the domain name as an argument. The
tool will run it through its fuzzing algorithms and generate a list of
potential phishing domains with the following DNS records: A, AAAA, NS and MX.

```
$ dnstwist.py example.com
```

Usually generated list of domains has more than a hundred of rows - especially
for longer domain names. In such cases, it may be practical to display only
registered (resolvable) ones using *--registered* argument.

```
$ dnstwist.py --registered example.com
```

Manually checking each domain name in terms of serving a phishing site might be
time consuming. To address this, *dnstwist* makes use of so called fuzzy hashes
(context triggered piecewise hashes). Fuzzy hashing is a concept which involves
the ability to compare two inputs (in this case HTML code) and determine a
fundamental level of similarity. This unique feature of *dnstwist* can be
enabled with *--ssdeep* argument. For each generated domain, *dnstwist* will
fetch content from responding HTTP server (following possible redirects) and
compare its fuzzy hash with the one for the original (initial) domain. The
level of similarity will be expressed as a percentage. Please keep in mind it's
rather unlikely to get 100% match for a dynamically generated web page, but each
notification should be inspected carefully regardless of the percentage level.

```
$ dnstwist.py --ssdeep example.com
```

In some cases phishing sites are served from a specific URL. If you provide a
full or partial URL address as an argument, *dnstwist* will parse it and apply
for each generated domain name variant. This ability is obviously useful only
in conjunction with fuzzy hashing feature.

```
$ dnstwist.py --ssdeep https://example.com/owa/
$ dnstwist.py --ssdeep example.com/crm/login
```

Very often attackers set up e-mail honey pots on phishing domains and wait for
mistyped e-mails to arrive. In this scenario, attackers would configure their
server to vacuum up all e-mail addressed to that domain, regardless of the user
it was sent towards. Another *dnstwist* feature allows to perform a simple test
on each mail server (advertised through DNS MX record) in order to check which
one can be used for such hostile intent. Suspicious servers will be marked with
*SPYING-MX* string.

Please be aware of possible false positives. Some mail servers only pretend to
accept incorrectly addressed e-mails but then discard those messages. This
technique is used to prevent a directory harvest attack.

```
$ dnstwist.py --mxcheck example.com
```

Not always domain names generated by the fuzzing algorithms are sufficient. To
generate even more domain name variants please feed *dnstwist* with a
dictionary file. Some dictionary samples with a list of the most common words
used in targeted phishing campaigns are included. Feel free to adapt it to your
needs.

```
$ dnstwist.py --dictionary dictionaries/english.dict example.com
``` 

Apart from the default nice and colorful text terminal output, the tool
provides two well known and easy to parse output formats: CSV and JSON. Use it
for data interchange.

```
$ dnstwist.py --csv example.com > out.csv
$ dnstwist.py --json example.com > out.json
```

The tool is shipped with built-in GeoIP database. Use *--geoip* argument to
display geographical location (country name) for each IPv4 address.

```
$ dnstwist.py --geoip example.com
```

Of course all of the features offered by *dnstwist* together with brief
descriptions are always available at your fingertips:

```
$ dnstwist.py --help
```

Good luck!


Coverage
--------

Along with the length of the domain, the number of variants generated by the
algorithms increases considerably and therefore the number of DNS queries
needed to verify them. For example, to check all variants for google.com, you
would have to send over 300k queries. For the domain facebook.com the number
increases to over 5 million. How easy it is to guess it takes a lot of
resources and most importantly even more time. For longer domains checking all
is simply not possible. For this reason, this tool generates and checks domains
very close to the original - the Levenshtein distance does not exceed 2.
Theoretically, these are the most attractive domains from the attacker's point
of view. However, be aware that the imagination of the aggressors is unlimited.


Contact
-------

To send questions, comments or a chocolate, just drop an e-mail at
[marcin@ulikowski.pl](mailto:marcin@ulikowski.pl)

You can also reach the author via:

- Twitter: [@elceef](https://twitter.com/elceef)
- LinkedIn: [Marcin Ulikowski](https://pl.linkedin.com/in/elceef)

Any feedback is appreciated. If you were able to run the tool and you are happy
with the results just let me know. If you find some confirmed phishing domains
with *dnstwist* and are comfortable with sharing them, also please send me a
message. Thank you.
