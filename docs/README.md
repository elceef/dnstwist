dnstwist
========

See what sort of trouble users can get in trying to type your domain name.
Find lookalike domains that adversaries can use to attack you. Can detect
typosquatters, phishing attacks, fraud, and corporate espionage. Useful as an
additional source of targeted threat intelligence.

![Demo](/docs/demo.gif)

The idea is quite straightforward: with the original domain name as input, the
tool generates a list of potentially malicious domains and then checks which
are registered. Additionally, it can generate fuzzy hashes of the web pages to
see if they are part of an ongoing phishing attack or brand impersonation, and
much more!


Key features
------------

- A wide range of efficient domain fuzzing algorithms
- Unicode domain names (IDN)
- Additional domain permutations using dictionary files
- Multithreaded job distribution
- Queries IPv4, IPv6, NS and MX records
- Evaluates web page similarity with fuzzy hashes to find live phishing sites
- Tests if MX host (mail server) can be used to intercept misdirected e-mails
- GeoIP location information
- Grabs HTTP and SMTP service banners
- WHOIS lookups for creation and modification date
- Output in CSV and JSON format


Installation
------------

**Python PIP**

```
$ pip install dnstwist
```

**Git**

If you want to run the latest version of the code, you can install it from Git:

```
$ git clone https://github.com/elceef/dnstwist.git
$ cd dnstwist
$ pip install .
```

**OSX**

Installation is simplified thanks to [Homebrew](https://brew.sh/) package:

```
$ brew install dnstwist
```

This will install `dnstwist` along with all dependencies, and the binary will
be added to `$PATH`.

**Docker**

If you prefer Docker, you can pull and run official image from the Docker Hub:

```
$ docker run elceef/dnstwist
```


Requirements
------------

This tool is designed to run fine with just standard Python3 library. However,
a couple of third-party packages are required to show its full potential.

**Debian/Ubuntu/Kali Linux**

If running Debian-based distribution, you can install all external libraries
with just single command:

```
$ sudo apt install python3-dnspython python3-tld python3-geoip python3-whois \
python3-requests python3-ssdeep
```

Alternatively, you can use Python PIP. This can be done within a virtual
environment to avoid conflicts with other installations. However, you will
still need essential build tools and a couple of libraries installed.

```
$ sudo apt install libfuzzy-dev
$ pip3 install -r requirements.txt
```


Quick start
-----------

The tool will run the provided domain name through its fuzzing algorithms and
generate a list of potential phishing domains with the following DNS records:
A, AAAA, NS and MX.

Usually thousands of domain permutations are generated - especially for longer
input domains. In such cases, it may be practical to display only registered
(resolvable) ones using `--registered` argument.

```
$ dnstwist --registered domain.name
```

Ensure your DNS server can handle thousands of requests within a short period
of time. Otherwise, you can specify an external DNS server with `--nameservers`
argument.

Manually checking each domain name in terms of serving a phishing site might be
time-consuming. To address this, `dnstwist` makes use of so-called fuzzy hashes
(context triggered piecewise hashes). Fuzzy hashing is a concept that involves
the ability to compare two inputs (in this case HTML code) and determine a
fundamental level of similarity. This unique feature of `dnstwist` can be
enabled with `--ssdeep` argument. For each generated domain, `dnstwist` will
fetch content from responding HTTP server (following possible redirects) and
compare its fuzzy hash with the one for the original (initial) domain. The
level of similarity will be expressed as a percentage.

Please keep in mind it's rather unlikely to get 100% match for a dynamically
generated web page. However, each notification should be inspected carefully
regardless of the score.

```
$ dnstwist --ssdeep domain.name
```

In some cases, phishing sites are served from a specific URL. If you provide a
full or partial URL address as an argument, `dnstwist` will parse it and apply
for each generated domain name variant. This is obviously useful only with the
fuzzy hashing feature.

```
$ dnstwist --ssdeep https://domain.name/owa/
$ dnstwist --ssdeep domain.name/login
```

Very often attackers set up e-mail honey pots on phishing domains and wait for
mistyped e-mails to arrive. In this scenario, attackers would configure their
server to vacuum up all e-mail addressed to that domain, regardless of the user
it was sent towards. Another `dnstwist` feature allows performing a simple test
on each mail server (advertised through DNS MX record) to check which one can
be used for such hostile intent. Suspicious servers will be flagged with
`SPYING-MX` string.

Please be aware of possible false positives. Some mail servers only pretend to
accept incorrectly addressed e-mails but then discard those messages. This
technique is used to prevent "directory harvesting attack".

```
$ dnstwist --mxcheck domain.name
```

If domain permutations generated by the fuzzing algorithms are insufficient,
please supply `dnstwist` with a dictionary file. Some dictionary samples with
a list of the most common words used in phishing campaigns are included. Feel
free to adapt it to your needs.

```
$ dnstwist --dictionary dictionaries/english.dict domain.name
```

If you need to check whether domains with different TLDs exist, you can use the
`--tld` option. You'll need to supply the TLDs list in a text file. A sample
file is provided.

```
$ dnstwist --tld dictionaries/common_tlds.dict example.com
```

Apart from the default nice and colorful text terminal output, the tool
provides two well known and easy to parse output formats: CSV and JSON. Use it
for convenient data interchange.

```
$ dnstwist --format csv domain.name | column -t -s,
$ dnstwist --format json domain.name | jq
```

In case you want to chain `dnstwist` with other tools and you need only domain
permutations without making any DNS lookups, you can use `--format idle`:

```
$ dnstwist --format idle domain.name
```

The tool can perform real-time lookups to return geographical location of IPv4
addresses. Use `--geoip` option to display country name next to each address.

```
$ dnstwist --geoip domain.name
```

To display all available options with brief descriptions simply execute the
tool without any arguments.

Happy hunting!


Coverage
--------

Along with the length of the domain, the number of variants generated by the
algorithms increases considerably, and therefore the number of DNS queries
needed to verify them. It's mathematically impossible to check all domain
permutations - especially for longer input domains.
For this reason, this tool generates and checks domains very close to the
original one. Theoretically, these are the most attractive domains from the
attacker's point of view. However, be aware that the imagination of the
aggressors is unlimited.


Contact
-------

To send questions, comments or a bar of chocolate, just drop an e-mail at
[marcin@ulikowski.pl](mailto:marcin@ulikowski.pl)

You can also reach the author via:

- Twitter: [@elceef](https://twitter.com/elceef)
- LinkedIn: [Marcin Ulikowski](https://pl.linkedin.com/in/elceef)

Any feedback is appreciated. If you have found some confirmed phishing domains
or just like this tool, please don't hesitate and send a message. Thank you.
