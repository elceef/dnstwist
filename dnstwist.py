#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r'''
     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__|

Generate and resolve domain variations to detect typo squatting,
phishing and corporate espionage.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

__author__ = 'Marcin Ulikowski'
__version__ = '20201228'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket
import signal
import time
import argparse
import threading
from os import path, environ
import smtplib
import json
import queue

try:
	from dns.resolver import Resolver, NXDOMAIN, NoNameservers
	import dns.rdatatype
	from dns.exception import DNSException
	MODULE_DNSPYTHON = True
except ImportError:
	MODULE_DNSPYTHON = False

GEOLITE2_MMDB = environ.get('GEOLITE2_MMDB' , path.join(path.dirname(__file__), 'GeoLite2-Country.mmdb'))
try:
	import geoip2.database
	_ = geoip2.database.Reader(GEOLITE2_MMDB)
except Exception:
	try:
		import GeoIP
		_ = GeoIP.new(-1)
	except Exception:
		MODULE_GEOIP = False
	else:
		MODULE_GEOIP = True
		class geoip:
			def __init__(self):
				self.reader = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
			def country_by_addr(self, ipaddr):
				return self.reader.country_name_by_addr(ipaddr)
else:
	MODULE_GEOIP = True
	class geoip:
		def __init__(self):
			self.reader = geoip2.database.Reader(GEOLITE2_MMDB)
		def country_by_addr(self, ipaddr):
			return self.reader.country(ipaddr).country.name

try:
	import whois
	MODULE_WHOIS = True
except ImportError:
	MODULE_WHOIS = False

try:
	import ssdeep
	MODULE_SSDEEP = True
except ImportError:
	try:
		import ppdeep as ssdeep
		MODULE_SSDEEP = True
	except ImportError:
		MODULE_SSDEEP = False

try:
	import requests
	requests.packages.urllib3.disable_warnings()
	MODULE_REQUESTS = True
except ImportError:
	MODULE_REQUESTS = False

try:
	import idna
except ImportError:
	class idna:
		@staticmethod
		def decode(domain):
			return domain.encode().decode('idna')
		@staticmethod
		def encode(domain):
			return domain.encode('idna')


VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)', re.IGNORECASE)

REQUEST_TIMEOUT_DNS = 2.5
REQUEST_RETRIES_DNS = 2
REQUEST_TIMEOUT_HTTP = 5
REQUEST_TIMEOUT_SMTP = 5
THREAD_COUNT_DEFAULT = 10

if sys.platform != 'win32' and sys.stdout.isatty():
	FG_RND = '\x1b[3{}m'.format(int(time.time())%8+1)
	FG_YEL = '\x1b[33m'
	FG_CYA = '\x1b[36m'
	FG_BLU = '\x1b[34m'
	FG_RST = '\x1b[39m'
	ST_BRI = '\x1b[1m'
	ST_RST = '\x1b[0m'
else:
	FG_RND = FG_YEL = FG_CYA = FG_BLU = FG_RST = ST_BRI = ST_RST = ''


def domain_tld(domain):
	try:
		from tld import parse_tld
	except ImportError:
		ctld = ['org', 'com', 'net', 'gov', 'edu', 'co', 'mil', 'nom', 'ac', 'info', 'biz']
		d = domain.rsplit('.', 3)
		if len(d) == 2:
			return '', d[0], d[1]
		if len(d) > 2:
			if d[-2] in ctld:
				return '.'.join(d[:-3]), d[-3], '.'.join(d[-2:])
			else:
				return '.'.join(d[:-2]), d[-2], d[-1]
	else:
		d = parse_tld(domain, fix_protocol=True)[::-1]
		if d[1:] == d[:-1] and None in d:
			d = tuple(domain.rsplit('.', 2))
			d = ('',) * (3-len(d)) + d
		return d


class UrlParser():
	def __init__(self, url):
		self.url = 'http://' + url if '://' not in url else url
		self.scheme = ''
		self.authority = ''
		self.domain = ''
		self.path = ''
		self.query = ''
		self._parse()

	def _parse(self):
		re_rfc3986_enhanced = re.compile(
			r'''
			^
			(?:(?P<scheme>[^:/?#\s]+):)?
			(?://(?P<authority>[^/?#\s]*))?
			(?P<path>[^?#\s]*)
			(?:\?(?P<query>[^#\s]*))?
			(?:\#(?P<fragment>[^\s]*))?
			$
			''', re.MULTILINE | re.VERBOSE
			)
		m_uri = re_rfc3986_enhanced.match(self.url)
		if m_uri:
			if m_uri.group('scheme'):
				if m_uri.group('scheme').startswith('http'):
					self.scheme = m_uri.group('scheme')
				else:
					self.scheme = 'http'
			if m_uri.group('authority'):
				self.authority = m_uri.group('authority')
				self.domain = self.authority.split(':')[0].lower()
				if not self._validate_domain(self.domain):
					raise ValueError('Invalid domain name')
			if m_uri.group('path'):
				self.path = m_uri.group('path')
			if m_uri.group('query'):
				if len(m_uri.group('query')):
					self.query = '?' + m_uri.group('query')

	def _validate_domain(self, domain):
		if len(domain) > 253:
			return False
		if VALID_FQDN_REGEX.match(domain):
			try:
				_ = idna.decode(domain)
			except Exception:
				return False
			else:
				return True
		return False

	def full_uri(self):
		return self.scheme + '://' + self.domain + self.path + self.query


class Permutation(dict):
	def __init__(self, fuzzer='', domain=''):
		super(dict, self).__init__()
		self['fuzzer'] = fuzzer
		self['domain'] = domain

	def __hash__(self):
		return hash(self['domain'])

	def __eq__(self, other):
		return self['domain'] == other['domain']

	def __lt__(self, other):
		return self['fuzzer'] + self['domain'] < other['fuzzer'] + other['domain']

	def is_registered(self):
		return len(self) > 2


class Fuzzer():
	def __init__(self, domain, dictionary=[], tld_dictionary=[]):
		self.subdomain, self.domain, self.tld = domain_tld(domain)
		self.domain = idna.decode(self.domain)
		self.dictionary = list(dictionary)
		self.tld_dictionary = list(tld_dictionary)
		self.domains = set()
		self.qwerty = {
			'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
			'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
			'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
			'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
			}
		self.qwertz = {
			'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
			'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
			'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
			'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
			}
		self.azerty = {
			'1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
			'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
			'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
			'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
			}
		self.keyboards = [self.qwerty, self.qwertz, self.azerty]
		self.glyphs = {
			'2': ['ƻ'],
			'5': ['ƽ'],
			'a': ['à', 'á', 'à', 'â', 'ã', 'ä', 'å', 'ɑ', 'ạ', 'ǎ', 'ă', 'ȧ', 'ą', 'ə'],
			'b': ['d', 'lb', 'ʙ', 'ɓ', 'ḃ', 'ḅ', 'ḇ', 'ƅ'],
			'c': ['e', 'ƈ', 'ċ', 'ć', 'ç', 'č', 'ĉ', 'ᴄ'],
			'd': ['b', 'cl', 'dl', 'ɗ', 'đ', 'ď', 'ɖ', 'ḑ', 'ḋ', 'ḍ', 'ḏ', 'ḓ'],
			'e': ['c', 'é', 'è', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'ẹ', 'ę', 'ȩ', 'ɇ', 'ḛ'],
			'f': ['ƒ', 'ḟ'],
			'g': ['q', 'ɢ', 'ɡ', 'ġ', 'ğ', 'ǵ', 'ģ', 'ĝ', 'ǧ', 'ǥ'],
			'h': ['lh', 'ĥ', 'ȟ', 'ħ', 'ɦ', 'ḧ', 'ḩ', 'ⱨ', 'ḣ', 'ḥ', 'ḫ', 'ẖ'],
			'i': ['1', 'l', 'í', 'ì', 'ï', 'ı', 'ɩ', 'ǐ', 'ĭ', 'ỉ', 'ị', 'ɨ', 'ȋ', 'ī', 'ɪ'],
			'j': ['ʝ', 'ǰ', 'ɉ', 'ĵ'],
			'k': ['lk', 'ik', 'lc', 'ḳ', 'ḵ', 'ⱪ', 'ķ', 'ᴋ'],
			'l': ['1', 'i', 'ɫ', 'ł'],
			'm': ['n', 'nn', 'rn', 'rr', 'ṁ', 'ṃ', 'ᴍ', 'ɱ', 'ḿ'],
			'n': ['m', 'r', 'ń', 'ṅ', 'ṇ', 'ṉ', 'ñ', 'ņ', 'ǹ', 'ň', 'ꞑ'],
			'o': ['0', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ᴏ'],
			'p': ['ƿ', 'ƥ', 'ṕ', 'ṗ'],
			'q': ['g', 'ʠ'],
			'r': ['ʀ', 'ɼ', 'ɽ', 'ŕ', 'ŗ', 'ř', 'ɍ', 'ɾ', 'ȓ', 'ȑ', 'ṙ', 'ṛ', 'ṟ'],
			's': ['ʂ', 'ś', 'ṣ', 'ṡ', 'ș', 'ŝ', 'š', 'ꜱ'],
			't': ['ţ', 'ŧ', 'ṫ', 'ṭ', 'ț', 'ƫ'],
			'u': ['ᴜ', 'ǔ', 'ŭ', 'ü', 'ʉ', 'ù', 'ú', 'û', 'ũ', 'ū', 'ų', 'ư', 'ů', 'ű', 'ȕ', 'ȗ', 'ụ'],
			'v': ['ṿ', 'ⱱ', 'ᶌ', 'ṽ', 'ⱴ', 'ᴠ'],
			'w': ['vv', 'ŵ', 'ẁ', 'ẃ', 'ẅ', 'ⱳ', 'ẇ', 'ẉ', 'ẘ', 'ᴡ'],
			'x': ['ẋ', 'ẍ'],
			'y': ['ʏ', 'ý', 'ÿ', 'ŷ', 'ƴ', 'ȳ', 'ɏ', 'ỿ', 'ẏ', 'ỵ'],
			'z': ['ʐ', 'ż', 'ź', 'ᴢ', 'ƶ', 'ẓ', 'ẕ', 'ⱬ']
			}

	def _bitsquatting(self):
		masks = [1, 2, 4, 8, 16, 32, 64, 128]
		chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
		for i, c in enumerate(self.domain):
			for mask in masks:
				b = chr(ord(c) ^ mask)
				if b in chars:
					yield self.domain[:i] + b + self.domain[i+1:]

	def _homoglyph(self):
		def mix(domain):
			glyphs = self.glyphs
			for w in range(1, len(domain)):
				for i in range(len(domain)-w+1):
					pre = domain[:i]
					win = domain[i:i+w]
					suf = domain[i+w:]
					for c in win:
						for g in glyphs.get(c, []):
							yield pre + win.replace(c, g) + suf
		result1 = set(mix(self.domain))
		result2 = set()
		for r in result1:
			result2.update(set(mix(r)))
		return result1 | result2

	def _hyphenation(self):
		return {self.domain[:i] + '-' + self.domain[i:] for i in range(1, len(self.domain))}

	def _insertion(self):
		result = set()
		for i in range(1, len(self.domain)-1):
			prefix, orig_c, suffix = self.domain[:i], self.domain[i], self.domain[i+1:]
			for c in (c for keys in self.keyboards for c in keys.get(orig_c, [])):
				result.update({
					prefix + c + orig_c + suffix,
					prefix + orig_c + c + suffix
				})
		return result

	def _omission(self):
		return {self.domain[:i] + self.domain[i+1:] for i in range(len(self.domain))}

	def _repetition(self):
		return {self.domain[:i] + c + self.domain[i:] for i, c in enumerate(self.domain)}

	def _replacement(self):
		for i, c in enumerate(self.domain):
			pre = self.domain[:i]
			suf = self.domain[i+1:]
			for layout in self.keyboards:
				for r in layout.get(c, ''):
					yield pre + r + suf

	def _subdomain(self):
		for i in range(1, len(self.domain)-1):
			if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
				yield self.domain[:i] + '.' + self.domain[i:]

	def _transposition(self):
		return {self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:] for i in range(len(self.domain)-1)}

	def _vowel_swap(self):
		vowels = 'aeiou'
		for i in range(0, len(self.domain)):
			for vowel in vowels:
				if self.domain[i] in vowels:
					yield self.domain[:i] + vowel + self.domain[i+1:]

	def _addition(self):
		return {self.domain + chr(i) for i in (*range(48, 58), *range(97, 123))}

	def _dictionary(self):
		result = set()
		for word in self.dictionary:
			if not (self.domain.startswith(word) and self.domain.endswith(word)):
				result.update({
					self.domain + '-' + word,
					self.domain + word,
					word + '-' + self.domain,
					word + self.domain
				})
		return result

	def _tld(self):
		if self.tld in self.tld_dictionary:
			self.tld_dictionary.remove(self.tld)
		return set(self.tld_dictionary)

	def generate(self):
		self.domains.add(Permutation(fuzzer='*original', domain='.'.join(filter(None, [self.subdomain, self.domain, self.tld]))))
		for f_name in [
			'addition', 'bitsquatting', 'homoglyph', 'hyphenation',
			'insertion', 'omission', 'repetition', 'replacement',
			'subdomain', 'transposition', 'vowel-swap', 'dictionary',
		]:
			f = getattr(self, f'_{f_name}'.replace('-', '_'))
			for domain in f():
				self.domains.add(Permutation(fuzzer=f_name, domain='.'.join(filter(None, [self.subdomain, domain, self.tld]))))
		for tld in self._tld():
			self.domains.add(Permutation(fuzzer='tld-swap', domain='.'.join(filter(None, [self.subdomain, self.domain, tld]))))
		if '.' in self.tld:
			self.domains.add(Permutation(fuzzer='various', domain=self.domain + '.' + self.tld.split('.')[-1]))
			self.domains.add(Permutation(fuzzer='various', domain=self.domain + self.tld))
		if '.' not in self.tld:
			self.domains.add(Permutation(fuzzer='various', domain=self.domain + self.tld + '.' + self.tld))
		if self.tld != 'com' and '.' not in self.tld:
			self.domains.add(Permutation(fuzzer='various', domain=self.domain + '-' + self.tld + '.com'))
		def _punycode(domain):
			try:
				domain['domain'] = idna.encode(domain['domain']).decode()
			except Exception:
				domain['domain'] = ''
			return domain
		self.domains = set(map(_punycode, self.domains))
		for domain in self.domains.copy():
			if not VALID_FQDN_REGEX.match(domain.get('domain')):
				self.domains.discard(domain)

	def permutations(self, registered=False, dns_all=False):
		domains = set({x for x in self.domains.copy() if x.is_registered()}) if registered else self.domains.copy()
		if not dns_all:
			for domain in domains:
				for k in ('dns_ns', 'dns_a', 'dns_aaaa', 'dns_mx'):
					if k in domain:
						domain[k] = domain[k][:1]
		return sorted(domains)


class Scanner(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.jobs = queue
		self.kill_received = False
		self.debug = False
		self.ssdeep_init = ''
		self.ssdeep_effective_url = ''
		self.uri_scheme = 'http'
		self.uri_path = ''
		self.uri_query = ''
		self.option_extdns = False
		self.option_geoip = False
		self.option_ssdeep = False
		self.option_banners = False
		self.option_mxcheck = False
		self.nameservers = []
		self.useragent = ''

	def _debug(self, text):
		if self.debug:
			print(str(text), file=sys.stderr, flush=True)

	def _banner_http(self, ip, vhost):
		try:
			http = socket.socket()
			http.settimeout(1)
			http.connect((ip, 80))
			http.send('HEAD / HTTP/1.1\r\nHost: {}\r\nUser-agent: {}\r\n\r\n'.format(vhost, self.useragent).encode())
			response = http.recv(1024).decode()
			http.close()
		except Exception:
			pass
		else:
			headers = response.splitlines()
			for field in headers:
				if field.lower().startswith('server: '):
					return field[8:]

	def _banner_smtp(self, mx):
		try:
			smtp = socket.socket()
			smtp.settimeout(1)
			smtp.connect((mx, 25))
			response = smtp.recv(1024).decode()
			smtp.close()
		except Exception:
			pass
		else:
			hello = response.splitlines()[0]
			if hello.startswith('220'):
				return hello[4:].strip()
			return hello[:40]

	def _mxcheck(self, mx, from_domain, to_domain):
		from_addr = 'randombob1986@' + from_domain
		to_addr = 'randomalice1986@' + to_domain
		try:
			smtp = smtplib.SMTP(mx, 25, timeout=REQUEST_TIMEOUT_SMTP)
			smtp.sendmail(from_addr, to_addr, 'And that\'s how the cookie crumbles')
			smtp.quit()
		except Exception:
			return False
		else:
			return True

	def _answer_to_list(self, answers):
		return sorted([str(x).split(' ')[-1].rstrip('.') for x in answers])

	def stop(self):
		self.kill_received = True

	def run(self):
		if self.option_extdns:
			if self.nameservers:
				resolv = Resolver(configure=False)
				resolv.nameservers = self.nameservers
			else:
				resolv = Resolver()
				resolv.search = []

			resolv.lifetime = REQUEST_TIMEOUT_DNS * REQUEST_RETRIES_DNS
			resolv.timeout = REQUEST_TIMEOUT_DNS
			EDNS_PAYLOAD = 1232
			resolv.use_edns(edns=True, ednsflags=0, payload=EDNS_PAYLOAD)

			if hasattr(resolv, 'resolve'):
				resolve = resolv.resolve
			else:
				resolve = resolv.query

		if self.option_geoip:
			geo = geoip()

		while not self.kill_received:
			try:
				task = self.jobs.get(block=False)
			except queue.Empty:
				self.kill_received = True
				return

			domain = task.get('domain')

			dns_a = False
			dns_aaaa = False
			if self.option_extdns:
				nxdomain = False
				dns_ns = False
				dns_mx = False

				try:
					task['dns_ns'] = self._answer_to_list(resolve(domain, rdtype=dns.rdatatype.NS))
					dns_ns = True
				except NXDOMAIN:
					nxdomain = True
				except NoNameservers:
					task['dns_ns'] = ['!ServFail']
				except DNSException as e:
					self._debug(e)

				if nxdomain is False:
					try:
						task['dns_a'] = self._answer_to_list(resolve(domain, rdtype=dns.rdatatype.A))
						dns_a = True
					except NoNameservers:
						task['dns_a'] = ['!ServFail']
					except DNSException as e:
						self._debug(e)

					try:
						task['dns_aaaa'] = self._answer_to_list(resolve(domain, rdtype=dns.rdatatype.AAAA))
						dns_aaaa = True
					except NoNameservers:
						task['dns_aaaa'] = ['!ServFail']
					except DNSException as e:
						self._debug(e)

				if nxdomain is False and dns_ns is True:
					try:
						task['dns_mx'] = self._answer_to_list(resolve(domain, rdtype=dns.rdatatype.MX))
						dns_mx = True
					except NoNameservers:
						task['dns_mx'] = ['!ServFail']
					except DNSException as e:
						self._debug(e)
			else:
				try:
					ip = socket.getaddrinfo(domain, 80)
				except socket.gaierror as e:
					if e.errno == -3:
						task['dns_a'] = ['!ServFail']
				except Exception as e:
					self._debug(e)
				else:
					task['dns_a'] = list()
					task['dns_aaaa'] = list()
					for j in ip:
						if '.' in j[4][0]:
							task['dns_a'].append(j[4][0])
						if ':' in j[4][0]:
							task['dns_aaaa'].append(j[4][0])
					task['dns_a'] = sorted(task['dns_a'])
					task['dns_aaaa'] = sorted(task['dns_aaaa'])
					dns_a = True
					dns_aaaa = True

			if self.option_mxcheck:
				if dns_mx is True:
					if domain != self.domain_init:
						if self._mxcheck(task['dns_mx'][0], self.domain_init, domain):
							task['mx_spy'] = True

			if self.option_geoip:
				if dns_a is True:
					try:
						country = geo.country_by_addr(task['dns_a'][0])
					except Exception as e:
						self._debug(e)
						pass
					else:
						if country:
							task['geoip'] = country.split(',')[0]

			if self.option_banners:
				if dns_a is True:
					banner = self._banner_http(task['dns_a'][0], domain)
					if banner:
						task['banner_http'] = banner
				if dns_mx is True:
					banner = self._banner_smtp(task['dns_mx'][0])
					if banner:
						task['banner_smtp'] = banner

			if self.option_ssdeep:
				if dns_a is True or dns_aaaa is True:
					try:
						req = requests.get(self.uri_scheme + '://' + domain + self.uri_path + self.uri_query,
							timeout=REQUEST_TIMEOUT_HTTP, headers={'User-Agent': self.useragent}, verify=False)
					except Exception as e:
						self._debug(e)
						pass
					else:
						if req.status_code // 100 == 2 and req.url.split('?')[0] != self.ssdeep_effective_url:
							ssdeep_curr = ssdeep.hash(''.join(req.text.split()).lower())
							task['ssdeep'] = ssdeep.compare(self.ssdeep_init, ssdeep_curr)

			self.jobs.task_done()


def create_json(domains=[]):
	return json.dumps(domains, indent=4, sort_keys=True)


def create_csv(domains=[]):
	csv = ['fuzzer,domain,dns_a,dns_aaaa,dns_mx,dns_ns,geoip,whois_registrar,whois_created,ssdeep']
	for domain in domains:
		csv.append(','.join([domain.get('fuzzer'), domain.get('domain'),
			';'.join(domain.get('dns_a', [])),
			';'.join(domain.get('dns_aaaa', [])),
			';'.join(domain.get('dns_mx', [])),
			';'.join(domain.get('dns_ns', [])),
			domain.get('geoip', ''), domain.get('whois_registrar', ''), domain.get('whois_created', ''),
			str(domain.get('ssdeep', ''))]))
	return '\n'.join(csv)


def create_list(domains=[]):
	return '\n'.join([x.get('domain') for x in sorted(domains)])


def create_cli(domains=[]):
	cli = []
	domains = list(domains)
	if sys.stdout.encoding.lower() == 'utf-8':
		for domain in domains:
			name = domain['domain']
			domain['domain'] = idna.decode(name)
	width_fuzzer = max([len(x['fuzzer']) for x in domains]) + 1
	width_domain = max([len(x['domain']) for x in domains]) + 1
	for domain in domains:
		info = []
		if 'dns_a' in domain:
			if 'geoip' in domain:
				info.append(';'.join(domain['dns_a']) + FG_CYA + '/' + domain['geoip'].replace(' ', '') + FG_RST)
			else:
				info.append(';'.join(domain['dns_a']))
		if 'dns_aaaa' in domain:
			info.append(';'.join(domain['dns_aaaa']))
		if 'dns_ns' in domain:
			info.append(FG_YEL + 'NS:' + FG_CYA + ';'.join(domain['dns_ns']) + FG_RST)
		if 'dns_mx' in domain:
			if 'mx_spy' in domain:
				info.append(FG_YEL + 'SPYING-MX:' + FG_CYA + ';'.join(domain['dns_mx']) + FG_RST)
			else:
				info.append(FG_YEL + 'MX:' + FG_CYA + ';'.join(domain['dns_mx']) + FG_RST)
		if 'banner_http' in domain:
			info.append(FG_YEL + 'HTTP:' + FG_CYA + domain['banner_http'] + FG_RST)
		if 'banner_smtp' in domain:
			info.append(FG_YEL + 'SMTP:' + FG_CYA + domain['banner_smtp'] + FG_RST)
		if 'whois_registrar' in domain:
			info.append(FG_YEL + 'REGISTRAR:' + FG_CYA + domain['whois_registrar'] + FG_RST)
		if 'whois_created' in domain:
			info.append(FG_YEL + 'CREATED:' + FG_CYA + domain['whois_created'] + FG_RST)
		if domain.get('ssdeep', 0) > 0:
			info.append(FG_YEL + 'SSDEEP:' + str(domain['ssdeep']) + FG_RST)
		if not info:
			info = ['-']
		cli.append(' '.join([FG_BLU + domain['fuzzer'].ljust(width_fuzzer) + FG_RST,
			domain['domain'].ljust(width_domain), ' '.join(info)]))
	return '\n'.join(cli)


def main():
	parser = argparse.ArgumentParser(
		usage='%s [OPTION]... DOMAIN' % sys.argv[0],
		add_help=False,
		description=
		'''Domain name permutation engine for detecting homograph phishing attacks, '''
		'''typosquatting, fraud and brand impersonation.''',
		formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=30)
		)

	parser.add_argument('domain', help='Domain name or URL to scan')
	parser.add_argument('-a', '--all', action='store_true', help='Show all DNS records')
	parser.add_argument('-b', '--banners', action='store_true', help='Determine HTTP and SMTP service banners')
	parser.add_argument('-d', '--dictionary', type=str, metavar='FILE', help='Generate more domains using dictionary FILE')
	parser.add_argument('-f', '--format', type=str, choices=['cli', 'csv', 'json', 'list'], default='cli', help='Output format (default: cli)')
	parser.add_argument('-g', '--geoip', action='store_true', help='Lookup for GeoIP location')
	parser.add_argument('-m', '--mxcheck', action='store_true', help='Check if MX can be used to intercept emails')
	parser.add_argument('-o', '--output', type=str, metavar='FILE', help='Save output to FILE')
	parser.add_argument('-r', '--registered', action='store_true', help='Show only registered domain names')
	parser.add_argument('-s', '--ssdeep', action='store_true', help='Fetch web pages and compare their fuzzy hashes to evaluate similarity')
	parser.add_argument('--ssdeep-url', metavar='URL', help='Override URL to fetch the original web page from')
	parser.add_argument('-t', '--threads', type=int, metavar='NUMBER', default=THREAD_COUNT_DEFAULT,
		help='Start specified NUMBER of threads (default: %s)' % THREAD_COUNT_DEFAULT)
	parser.add_argument('-w', '--whois', action='store_true', help='Lookup WHOIS database for creation date')
	parser.add_argument('--tld', type=str, metavar='FILE', help='Generate more domains by swapping TLD from FILE')
	parser.add_argument('--nameservers', type=str, metavar='LIST', help='DNS or DoH servers to query (separated with commas)')
	parser.add_argument('--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnstwist/%s' % __version__,
		help='User-Agent STRING to send with HTTP requests (default: Mozilla/5.0 dnstwist/%s)' % __version__)
	parser.add_argument('--debug', action='store_true', help='Display debug messages')

	def _exit(code):
		sys.exit(code)

	if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
		print('{}dnstwist {} by <{}>{}\n'.format(ST_BRI, __version__, __email__, ST_RST))
		parser.print_help()
		_exit(0)

	threads = []

	args = parser.parse_args()

	def p_cli(text):
		if args.format == 'cli' and sys.stdout.isatty(): print(text, end='', flush=True)
	def p_err(text):
		print(str(text), file=sys.stderr, flush=True)

	def signal_handler(signal, frame):
		print('\nStopping threads... ', file=sys.stderr, end='', flush=True)
		for worker in threads:
			worker.stop()
			worker.join()
		print('Done', file=sys.stderr)
		_exit(0)

	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)

	if args.threads < 1:
		parser.error('number of threads must be greater than zero')

	nameservers = []
	if args.nameservers:
		if not MODULE_DNSPYTHON:
			parser.error('missing DNSPython library')
		nameservers = args.nameservers.split(',')
		for addr in nameservers:
			if re.match(r'^https://[a-z0-9.-]{4,253}/dns-query$', addr):
				try:
					from dns.query import https
				except ImportError:
					parser.error('DNS-over-HTTPS requires DNSPython 2.x or newer')
				else:
					del https
				continue
			if re.match(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$', addr):
				continue
			parser.error('invalid nameserver: {}'.format(addr))

	dictionary = []
	if args.dictionary:
		if not path.exists(args.dictionary):
			parser.error('dictionary file not found: %s' % args.dictionary)
		with open(args.dictionary) as f:
			dictionary = [x for x in set(f.read().splitlines()) if x.isalnum()]

	tld = []
	if args.tld:
		if not path.exists(args.tld):
			parser.error('dictionary file not found: %s' % args.tld)
		with open(args.tld) as f:
			tld = [x for x in set(f.read().splitlines()) if x.isascii()]

	if args.output:
		try:
			sys.stdout = open(args.output, 'x')
		except FileExistsError:
			parser.error('file already exists: %s' % args.output)
		except FileNotFoundError:
			parser.error('file not found: %s' % args.output)
		except PermissionError:
			parser.error('permission denied: %s' % args.output)

	ssdeep_url = None
	if args.ssdeep:
		if not MODULE_SSDEEP:
			parser.error('missing ssdeep library')
		if not MODULE_REQUESTS:
			parser.error('missing Requests library')
		if args.ssdeep_url:
			try:
				ssdeep_url = UrlParser(args.ssdeep_url)
			except ValueError:
				parser.error('invalid domain name: ' + args.ssdeep_url)

	if args.whois:
		if not MODULE_WHOIS:
			parser.error('missing whois library')

	if args.geoip:
		if not MODULE_GEOIP:
			parser.error('missing GeoIP library or database')

	try:
		url = UrlParser(args.domain) if args.domain.isascii() else UrlParser(idna.encode(args.domain).decode())
	except Exception:
		parser.error('invalid domain name: ' + args.domain)

	fuzz = Fuzzer(url.domain, dictionary=dictionary, tld_dictionary=tld)
	fuzz.generate()
	domains = fuzz.domains

	if args.format == 'list':
		print(create_list(domains))
		_exit(0)

	if not MODULE_DNSPYTHON:
		p_err('WARNING: DNS features are limited due to lack of DNSPython library')

	p_cli(FG_RND + ST_BRI +
r'''     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}

''' % __version__ + FG_RST + ST_RST)

	ssdeep_init = str()
	ssdeep_effective_url = str()
	if args.ssdeep:
		request_url = ssdeep_url.full_uri() if ssdeep_url else url.full_uri()
		p_cli('Fetching content from: %s ' % request_url)
		try:
			req = requests.get(request_url, timeout=REQUEST_TIMEOUT_HTTP, headers={'User-Agent': args.useragent})
		except requests.exceptions.ConnectionError:
			p_cli('Connection error\n')
			_exit(1)
		except requests.exceptions.HTTPError:
			p_cli('Invalid HTTP response\n')
			_exit(1)
		except requests.exceptions.Timeout:
			p_cli('Timeout (%d seconds)\n' % REQUEST_TIMEOUT_HTTP)
			_exit(1)
		except Exception:
			p_cli('Failed!\n')
			_exit(1)
		else:
			if len(req.history) > 1:
				p_cli('➔ %s ' % req.url.split('?')[0])
			p_cli('%d %s (%.1f Kbytes)\n' % (req.status_code, req.reason, float(len(req.text))/1000))
			if req.status_code // 100 == 2:
				ssdeep_init = ssdeep.hash(''.join(req.text.split()).lower())
				ssdeep_effective_url = req.url.split('?')[0]
			else:
				args.ssdeep = False

	jobs = queue.Queue()

	for task in domains:
		jobs.put(task)

	for _ in range(args.threads):
		worker = Scanner(jobs)
		worker.setDaemon(True)

		worker.uri_scheme = url.scheme
		worker.uri_path = url.path
		worker.uri_query = url.query

		worker.domain_init = url.domain

		worker.option_extdns = MODULE_DNSPYTHON
		if args.geoip:
			worker.option_geoip = True
		if args.banners:
			worker.option_banners = True
		if args.ssdeep and ssdeep_init:
			worker.option_ssdeep = True
			worker.ssdeep_init = ssdeep_init
			worker.ssdeep_effective_url = ssdeep_effective_url
		if args.mxcheck:
			worker.option_mxcheck = True
		if args.nameservers:
			worker.nameservers = nameservers
		worker.useragent = args.useragent

		worker.debug = args.debug

		worker.start()
		threads.append(worker)

	ttime = 0
	ival = 0.5
	while not jobs.empty():
		time.sleep(ival)
		ttime += ival
		comp = len(domains) - jobs.qsize()
		if not comp:
			continue
		perc = 100 * comp / len(domains)
		rate = comp / ttime
		eta = int(jobs.qsize() / rate)
		found = sum([1 for x in domains if x.is_registered()])
		p_cli('\rPermutations: {:.2f}% of {}, Found: {}, ETA: {} [{:3.0f} qps]'.format(perc, len(domains), found, time.strftime('%M:%S', time.gmtime(eta)), rate))
	p_cli('\n')

	for worker in threads:
		worker.stop()
		worker.join()

	domains = fuzz.permutations(registered=args.registered, dns_all=args.all)

	if args.whois:
		total = sum([1 for x in domains if x.is_registered()])
		for i, domain in enumerate([x for x in domains if x.is_registered()]):
			p_cli('\rWHOIS: {:.2f}% of {}'.format(100*(i+1)/total, total))
			try:
				_, dom, tld = domain_tld(domain['domain'])
				whoisq = whois.query('.'.join([dom, tld]))
			except Exception as e:
				if args.debug:
					p_err(e)
			else:
				if whoisq is None:
					continue
				if whoisq.creation_date:
					domain['whois_created'] = str(whoisq.creation_date).split(' ')[0]
				if whoisq.registrar:
					domain['whois_registrar'] = str(whoisq.registrar)
		p_cli('\n')

	p_cli('\n')

	if domains:
		if args.format == 'csv':
			print(create_csv(domains))
		elif args.format == 'json':
			print(create_json(domains))
		else:
			print(create_cli(domains))

	_exit(0)


if __name__ == '__main__':
	main()
