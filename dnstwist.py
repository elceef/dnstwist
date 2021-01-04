#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
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
from os import path
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

try:
	import GeoIP
	MODULE_GEOIP = True
except ImportError:
	MODULE_GEOIP = False
else:
	try:
		_ = GeoIP.new(-1)
	except Exception:
		MODULE_GEOIP = False

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


VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', re.IGNORECASE)

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


class UrlParser():
	def __init__(self, url):
		if '://' not in url:
			self.url = 'http://' + url
		else:
			self.url = url
		self.scheme = ''
		self.authority = ''
		self.domain = ''
		self.path = ''
		self.query = ''

		self.__parse()

	def __parse(self):
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
				if not self.__validate_domain(self.domain):
					raise ValueError('Invalid domain name')
			if m_uri.group('path'):
				self.path = m_uri.group('path')
			if m_uri.group('query'):
				if len(m_uri.group('query')):
					self.query = '?' + m_uri.group('query')

	def __validate_domain(self, domain):
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


class DomainFuzz():
	def __init__(self, domain, dictionary=[], tld_dictionary=[]):
		self.subdomain, self.domain, self.tld = self.domain_tld(domain)
		self.domain = idna.decode(self.domain)
		self.dictionary = list(dictionary)
		self.tld_dictionary = list(tld_dictionary)
		self.domains = []
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

	@staticmethod
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

	def __postprocess(self):
		def punycode(domain):
			try:
				return idna.encode(domain).decode()
			except Exception:
				return ''
		for idx, domain in enumerate(map(punycode, [x.get('domain-name') for x in self.domains])):
			self.domains[idx]['domain-name'] = domain
		seen = set()
		filtered = []
		for domain in self.domains:
			name = domain.get('domain-name')
			if VALID_FQDN_REGEX.match(name) and name not in seen:
				filtered.append(domain)
				seen.add(name)
		self.domains = filtered

	def __bitsquatting(self):
		result = []
		masks = [1, 2, 4, 8, 16, 32, 64, 128]
		for i in range(0, len(self.domain)):
			c = self.domain[i]
			for j in range(0, len(masks)):
				b = chr(ord(c) ^ masks[j])
				o = ord(b)
				if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
					result.append(self.domain[:i] + b + self.domain[i+1:])
		return result

	def __homoglyph(self):
		glyphs = {
			'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'ạ', 'ǎ', 'ă', 'ȧ', 'ą'],
			'b': ['d', 'lb', 'ʙ', 'ɓ', 'ḃ', 'ḅ', 'ḇ', 'ƅ'],
			'c': ['e', 'ƈ', 'ċ', 'ć', 'ç', 'č', 'ĉ'],
			'd': ['b', 'cl', 'dl', 'ɗ', 'đ', 'ď', 'ɖ', 'ḑ', 'ḋ', 'ḍ', 'ḏ', 'ḓ'],
			'e': ['c', 'é', 'è', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'ẹ', 'ę', 'ȩ', 'ɇ', 'ḛ'],
			'f': ['ƒ', 'ḟ'],
			'g': ['q', 'ɢ', 'ɡ', 'ġ', 'ğ', 'ǵ', 'ģ', 'ĝ', 'ǧ', 'ǥ'],
			'h': ['lh', 'ĥ', 'ȟ', 'ħ', 'ɦ', 'ḧ', 'ḩ', 'ⱨ', 'ḣ', 'ḥ', 'ḫ', 'ẖ'],
			'i': ['1', 'l', 'í', 'ì', 'ï', 'ı', 'ɩ', 'ǐ', 'ĭ', 'ỉ', 'ị', 'ɨ', 'ȋ', 'ī'],
			'j': ['ʝ', 'ɉ'],
			'k': ['lk', 'ik', 'lc', 'ḳ', 'ḵ', 'ⱪ', 'ķ'],
			'l': ['1', 'i', 'ɫ', 'ł'],
			'm': ['n', 'nn', 'rn', 'rr', 'ṁ', 'ṃ', 'ᴍ', 'ɱ', 'ḿ'],
			'n': ['m', 'r', 'ń', 'ṅ', 'ṇ', 'ṉ', 'ñ', 'ņ', 'ǹ', 'ň', 'ꞑ'],
			'o': ['0', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö'],
			'p': ['ƿ', 'ƥ', 'ṕ', 'ṗ'],
			'q': ['g', 'ʠ'],
			'r': ['ʀ', 'ɼ', 'ɽ', 'ŕ', 'ŗ', 'ř', 'ɍ', 'ɾ', 'ȓ', 'ȑ', 'ṙ', 'ṛ', 'ṟ'],
			's': ['ʂ', 'ś', 'ṣ', 'ṡ', 'ș', 'ŝ', 'š'],
			't': ['ţ', 'ŧ', 'ṫ', 'ṭ', 'ț', 'ƫ'],
			'u': ['ᴜ', 'ǔ', 'ŭ', 'ü', 'ʉ', 'ù', 'ú', 'û', 'ũ', 'ū', 'ų', 'ư', 'ů', 'ű', 'ȕ', 'ȗ', 'ụ'],
			'v': ['ṿ', 'ⱱ', 'ᶌ', 'ṽ', 'ⱴ'],
			'w': ['vv', 'ŵ', 'ẁ', 'ẃ', 'ẅ', 'ⱳ', 'ẇ', 'ẉ', 'ẘ'],
			'y': ['ʏ', 'ý', 'ÿ', 'ŷ', 'ƴ', 'ȳ', 'ɏ', 'ỿ', 'ẏ', 'ỵ'],
			'z': ['ʐ', 'ż', 'ź', 'ᴢ', 'ƶ', 'ẓ', 'ẕ', 'ⱬ']
			}
		result_1pass = set()
		for ws in range(1, len(self.domain)):
			for i in range(0, (len(self.domain)-ws)+1):
				win = self.domain[i:i+ws]
				j = 0
				while j < ws:
					c = win[j]
					if c in glyphs:
						win_copy = win
						for g in glyphs[c]:
							win = win.replace(c, g)
							result_1pass.add(self.domain[:i] + win + self.domain[i+ws:])
							win = win_copy
					j += 1
		result_2pass = set()
		for domain in result_1pass:
			for ws in range(1, len(domain)):
				for i in range(0, (len(domain)-ws)+1):
					win = domain[i:i+ws]
					j = 0
					while j < ws:
						c = win[j]
						if c in glyphs:
							win_copy = win
							for g in glyphs[c]:
								win = win.replace(c, g)
								result_2pass.add(domain[:i] + win + domain[i+ws:])
								win = win_copy
						j += 1
		return list(result_1pass | result_2pass)

	def __hyphenation(self):
		result = []
		for i in range(1, len(self.domain)):
			result.append(self.domain[:i] + '-' + self.domain[i:])
		return result

	def __insertion(self):
		result = []
		for i in range(1, len(self.domain)-1):
			for keys in self.keyboards:
				if self.domain[i] in keys:
					for c in keys[self.domain[i]]:
						result.append(self.domain[:i] + c + self.domain[i] + self.domain[i+1:])
						result.append(self.domain[:i] + self.domain[i] + c + self.domain[i+1:])
		return list(set(result))

	def __omission(self):
		result = []
		for i in range(0, len(self.domain)):
			result.append(self.domain[:i] + self.domain[i+1:])
		return list(set(result))

	def __repetition(self):
		result = []
		for i in range(0, len(self.domain)):
			if self.domain[i].isalnum():
				result.append(self.domain[:i] + self.domain[i] + self.domain[i] + self.domain[i+1:])
		return list(set(result))

	def __replacement(self):
		result = []
		for i in range(0, len(self.domain)):
			for keys in self.keyboards:
				if self.domain[i] in keys:
					for c in keys[self.domain[i]]:
						result.append(self.domain[:i] + c + self.domain[i+1:])
		return list(set(result))

	def __subdomain(self):
		result = []
		for i in range(1, len(self.domain)-1):
			if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
				result.append(self.domain[:i] + '.' + self.domain[i:])
		return result

	def __transposition(self):
		result = []
		for i in range(0, len(self.domain)-1):
			if self.domain[i+1] != self.domain[i]:
				result.append(self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:])
		return result

	def __vowel_swap(self):
		vowels = 'aeiou'
		result = []
		for i in range(0, len(self.domain)):
			for vowel in vowels:
				if self.domain[i] in vowels:
					result.append(self.domain[:i] + vowel + self.domain[i+1:])
		return list(set(result))

	def __addition(self):
		result = []
		for i in range(97, 123):
			result.append(self.domain + chr(i))
		return result

	def __dictionary(self):
		result = []
		for word in self.dictionary:
			if not (self.domain.startswith(word) and self.domain.endswith(word)):
				result.append(self.domain + '-' + word)
				result.append(self.domain + word)
				result.append(word + '-' + self.domain)
				result.append(word + self.domain)
		return list(set(result))

	def __tld(self):
		if self.tld in self.tld_dictionary:
			self.tld_dictionary.remove(self.tld)
		return list(set(self.tld_dictionary))

	def generate(self):
		self.domains.append({'fuzzer': 'original*', 'domain-name': '.'.join(filter(None, [self.subdomain, self.domain, self.tld]))})
		for domain in self.__addition():
			self.domains.append({'fuzzer': 'addition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__bitsquatting():
			self.domains.append({'fuzzer': 'bitsquatting', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__homoglyph():
			self.domains.append({'fuzzer': 'homoglyph', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__hyphenation():
			self.domains.append({'fuzzer': 'hyphenation', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__insertion():
			self.domains.append({'fuzzer': 'insertion', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__omission():
			self.domains.append({'fuzzer': 'omission', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__repetition():
			self.domains.append({'fuzzer': 'repetition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__replacement():
			self.domains.append({'fuzzer': 'replacement', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__subdomain():
			self.domains.append({'fuzzer': 'subdomain', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__transposition():
			self.domains.append({'fuzzer': 'transposition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__vowel_swap():
			self.domains.append({'fuzzer': 'vowel-swap', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for domain in self.__dictionary():
			self.domains.append({'fuzzer': 'dictionary', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})
		for tld in self.__tld():
			self.domains.append({'fuzzer': 'tld-swap', 'domain-name': '.'.join(filter(None, [self.subdomain, self.domain, tld]))})
		if '.' in self.tld:
			self.domains.append({'fuzzer': 'various', 'domain-name': self.domain + '.' + self.tld.split('.')[-1]})
			self.domains.append({'fuzzer': 'various', 'domain-name': self.domain + self.tld})
		if '.' not in self.tld:
			self.domains.append({'fuzzer': 'various', 'domain-name': self.domain + self.tld + '.' + self.tld})
		if self.tld != 'com' and '.' not in self.tld:
			self.domains.append({'fuzzer': 'various', 'domain-name': self.domain + '-' + self.tld + '.com'})
		self.__postprocess()

	def permutations(self, registered=False, dns_all=False):
		domains = []
		if registered:
			domains = [x.copy() for x in self.domains if len(x) > 2]
		else:
			domains = self.domains.copy()
		if not dns_all:
			for i in range(len(domains)):
				for k in ('dns-ns', 'dns-a', 'dns-aaaa', 'dns-mx'):
					if k in domains[i]:
						domains[i][k] = domains[i][k][:1]
		return domains


class DomainThread(threading.Thread):
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

	def __debug(self, text):
		if self.debug:
			print(str(text), file=sys.stderr, flush=True)

	def __banner_http(self, ip, vhost):
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

	def __banner_smtp(self, mx):
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

	def __mxcheck(self, mx, from_domain, to_domain):
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

	def __answer_to_list(self, answers):
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

		while not self.kill_received:
			try:
				domain = self.jobs.get(block=False)
			except queue.Empty:
				self.kill_received = True
				return

			if self.option_extdns:
				nxdomain = False
				dns_ns = False
				dns_a = False
				dns_aaaa = False
				dns_mx = False

				try:
					domain['dns-ns'] = self.__answer_to_list(resolve(domain['domain-name'], rdtype=dns.rdatatype.NS))
					dns_ns = True
				except NXDOMAIN:
					nxdomain = True
				except NoNameservers:
					domain['dns-ns'] = ['!ServFail']
				except DNSException as e:
					self.__debug(e)

				if nxdomain is False:
					try:
						domain['dns-a'] = self.__answer_to_list(resolve(domain['domain-name'], rdtype=dns.rdatatype.A))
						dns_a = True
					except NoNameservers:
						domain['dns-a'] = ['!ServFail']
					except DNSException as e:
						self.__debug(e)

					try:
						domain['dns-aaaa'] = self.__answer_to_list(resolve(domain['domain-name'], rdtype=dns.rdatatype.AAAA))
						dns_aaaa = True
					except NoNameservers:
						domain['dns-aaaa'] = ['!ServFail']
					except DNSException as e:
						self.__debug(e)

				if nxdomain is False and dns_ns is True:
					try:
						domain['dns-mx'] = self.__answer_to_list(resolve(domain['domain-name'], rdtype=dns.rdatatype.MX))
						dns_mx = True
					except NoNameservers:
						domain['dns-mx'] = ['!ServFail']
					except DNSException as e:
						self.__debug(e)
			else:
				try:
					ip = socket.getaddrinfo(domain['domain-name'], 80)
				except socket.gaierror as e:
					if e.errno == -3:
						domain['dns-a'] = ['!ServFail']
				except Exception as e:
					self.__debug(e)
				else:
					domain['dns-a'] = list()
					domain['dns-aaaa'] = list()
					for j in ip:
						if '.' in j[4][0]:
							domain['dns-a'].append(j[4][0])
						if ':' in j[4][0]:
							domain['dns-aaaa'].append(j[4][0])
					domain['dns-a'] = sorted(domain['dns-a'])
					domain['dns-aaaa'] = sorted(domain['dns-aaaa'])
					dns_a = True
					dns_aaaa = True

			if self.option_mxcheck:
				if dns_mx is True:
					if domain['domain-name'] != self.domain_init:
						if self.__mxcheck(domain['dns-mx'][0], self.domain_init, domain['domain-name']):
							domain['mx-spy'] = True

			if self.option_geoip:
				if dns_a is True:
					try:
						country = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE).country_name_by_addr(domain['dns-a'][0])
					except Exception as e:
						self.__debug(e)
						pass
					else:
						if country:
							domain['geoip-country'] = country.split(',')[0]

			if self.option_banners:
				if dns_a is True:
					banner = self.__banner_http(domain['dns-a'][0], domain['domain-name'])
					if banner:
						domain['banner-http'] = banner
				if dns_mx is True:
					banner = self.__banner_smtp(domain['dns-mx'][0])
					if banner:
						domain['banner-smtp'] = banner

			if self.option_ssdeep:
				if dns_a is True or dns_aaaa is True:
					try:
						req = requests.get(self.uri_scheme + '://' + domain['domain-name'] + self.uri_path + self.uri_query,
							timeout=REQUEST_TIMEOUT_HTTP, headers={'User-Agent': self.useragent}, verify=False)
					except Exception as e:
						self.__debug(e)
						pass
					else:
						if req.status_code // 100 == 2 and req.url.split('?')[0] != self.ssdeep_effective_url:
							ssdeep_curr = ssdeep.hash(''.join(req.text.split()).lower())
							domain['ssdeep-score'] = ssdeep.compare(self.ssdeep_init, ssdeep_curr)

			self.jobs.task_done()


def create_json(domains=[]):
	return json.dumps(domains, indent=4, sort_keys=True)


def create_csv(domains=[]):
	csv = ['fuzzer,domain-name,dns-a,dns-aaaa,dns-mx,dns-ns,geoip-country,whois-registrar,whois-created,ssdeep-score']
	for domain in domains:
		csv.append(','.join([domain.get('fuzzer'), domain.get('domain-name'),
			';'.join(domain.get('dns-a', [])),
			';'.join(domain.get('dns-aaaa', [])),
			';'.join(domain.get('dns-mx', [])),
			';'.join(domain.get('dns-ns', [])),
			domain.get('geoip-country', ''), domain.get('whois-registrar', ''), domain.get('whois-created', ''),
			str(domain.get('ssdeep-score', ''))]))
	return '\n'.join(csv)


def create_list(domains=[]):
	return '\n'.join([x.get('domain-name') for x in domains])


def create_cli(domains=[]):
	cli = []
	domains = list(domains)
	if sys.stdout.encoding.lower() == 'utf-8':
		for domain in domains:
			name = domain['domain-name']
			domain['domain-name'] = idna.decode(name)
	width_fuzzer = max([len(x['fuzzer']) for x in domains]) + 1
	width_domain = max([len(x['domain-name']) for x in domains]) + 1
	for domain in domains:
		info = []
		if 'dns-a' in domain:
			if 'geoip-country' in domain:
				info.append(';'.join(domain['dns-a']) + FG_CYA + '/' + domain['geoip-country'].replace(' ', '') + FG_RST)
			else:
				info.append(';'.join(domain['dns-a']))
		if 'dns-aaaa' in domain:
			info.append(';'.join(domain['dns-aaaa']))
		if 'dns-ns' in domain:
			info.append(FG_YEL + 'NS:' + FG_CYA + ';'.join(domain['dns-ns']) + FG_RST)
		if 'dns-mx' in domain:
			if 'mx-spy' in domain:
				info.append(FG_YEL + 'SPYING-MX:' + FG_CYA + ';'.join(domain['dns-mx']) + FG_RST)
			else:
				info.append(FG_YEL + 'MX:' + FG_CYA + ';'.join(domain['dns-mx']) + FG_RST)
		if 'banner-http' in domain:
			info.append(FG_YEL + 'HTTP:' + FG_CYA + domain['banner-http'] + FG_RST)
		if 'banner-smtp' in domain:
			info.append(FG_YEL + 'SMTP:' + FG_CYA + domain['banner-smtp'] + FG_RST)
		if 'whois-registrar' in domain:
			info.append(FG_YEL + 'REGISTRAR:' + FG_CYA + domain['whois-registrar'] + FG_RST)
		if 'whois-created' in domain:
			info.append(FG_YEL + 'CREATED:' + FG_CYA + domain['whois-created'] + FG_RST)
		if domain.get('ssdeep-score', 0) > 0:
			info.append(FG_YEL + 'SSDEEP:' + str(domain['ssdeep-score']) + FG_RST)
		if not info:
			info = ['-']
		cli.append(' '.join([FG_BLU + domain['fuzzer'].ljust(width_fuzzer) + FG_RST,
			domain['domain-name'].ljust(width_domain), ' '.join(info)]))
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
	parser.add_argument('--nameservers', type=str, metavar='LIST', help='DNS servers to query (separated with commas)')
	parser.add_argument('--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnstwist/%s' % __version__,
		help='User-Agent STRING to send with HTTP requests (default: Mozilla/5.0 dnstwist/%s)' % __version__)
	parser.add_argument('--debug', action='store_true', help='Display debug messages')

	def _exit(code):
		print(FG_RST + ST_RST, end='')
		sys.exit(code)

	if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
		print('{}dnstwist {} by <{}>{}\n'.format(ST_BRI, __version__, __email__, ST_RST))
		parser.print_help()
		_exit(0)

	threads = []

	args = parser.parse_args()

	def p_cli(text):
		if args.format == 'cli': print(text, end='', flush=True)
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
		nameservers = args.nameservers.split(',')
		for r in nameservers:
			if len(r.split('.')) != 4:
				parser.error('invalid DNS nameserver')

	dictionary = []
	if args.dictionary:
		if not path.exists(args.dictionary):
			parser.error('dictionary file not found: %s' % args.dictionary)
		with open(args.dictionary) as f:
			dictionary = set(f.read().splitlines())
			dictionary = [x for x in dictionary if x.isalnum()]

	tld = []
	if args.tld:
		if not path.exists(args.tld):
			parser.error('dictionary file not found: %s' % args.tld)
		with open(args.tld) as f:
			tld = set(f.read().splitlines())
			tld = [x for x in tld if x.isalpha()]

	if args.output:
		try:
			sys.stdout = open(args.output, 'x')
		except FileExistsError:
			parser.error('file already exists: %s' % args.output)
		except FileNotFoundError:
			parser.error('not such file or directory: %s' % args.output)
		except PermissionError:
			parser.error('permission denied: %s' % args.output)

	ssdeep_url = None
	if args.ssdeep_url:
		try:
			ssdeep_url = UrlParser(args.ssdeep_url)
		except ValueError:
			parser.error('invalid domain name: ' + args.ssdeep_url)

	try:
		url = UrlParser(args.domain)
	except ValueError:
		parser.error('invalid domain name: ' + args.domain)

	fuzz = DomainFuzz(url.domain, dictionary=dictionary, tld_dictionary=tld)
	fuzz.generate()
	domains = fuzz.domains

	if args.format == 'list':
		print(create_list(domains))
		_exit(0)

	if not MODULE_DNSPYTHON:
		p_err('Notice: Missing module DNSPython (DNS features limited)')
	if not MODULE_GEOIP and args.geoip:
		p_err('Notice: Missing GeoIP module or database (geographical location not available)')
	if not MODULE_WHOIS and args.whois:
		p_err('Notice: Missing module whois (WHOIS database not accessible)')
	if not MODULE_SSDEEP and args.ssdeep:
		p_err('Notice: Missing module ssdeep (fuzzy hashes not available)')
	if not MODULE_REQUESTS and args.ssdeep:
		p_err('Notice: Missing module Requests (webpage downloads not possible)')

	p_cli(FG_RND + ST_BRI +
'''     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}

''' % __version__ + FG_RST + ST_RST)

	ssdeep_init = str()
	ssdeep_effective_url = str()
	if args.ssdeep and MODULE_SSDEEP and MODULE_REQUESTS:
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

	p_cli('Processing %d permutations ' % len(domains))

	jobs = queue.Queue()

	for i in range(len(domains)):
		jobs.put(domains[i])

	for _ in range(args.threads):
		worker = DomainThread(jobs)
		worker.setDaemon(True)

		worker.uri_scheme = url.scheme
		worker.uri_path = url.path
		worker.uri_query = url.query

		worker.domain_init = url.domain

		if MODULE_DNSPYTHON:
			worker.option_extdns = True
		if MODULE_GEOIP and args.geoip:
			worker.option_geoip = True
		if args.banners:
			worker.option_banners = True
		if args.ssdeep and MODULE_REQUESTS and MODULE_SSDEEP and ssdeep_init:
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

	qperc = 0
	while not jobs.empty():
		p_cli('.')
		qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
		if qcurr - 20 >= qperc:
			qperc = qcurr
			p_cli('%u%%' % qperc)
		time.sleep(1.0)

	for worker in threads:
		worker.stop()
		worker.join()

	p_cli(' %d hits\n' % sum([1 for x in domains if len(x) > 2]))

	domains = fuzz.permutations(registered=args.registered, dns_all=args.all)

	if MODULE_WHOIS and args.whois:
		p_cli('Querying WHOIS servers ')
		for domain in domains:
			if len(domain) > 2:
				p_cli('·')
				try:
					_, dom, tld = fuzz.domain_tld(domain['domain-name'])
					whoisq = whois.query('.'.join([dom, tld]))
				except Exception as e:
					if args.debug:
						p_err(e)
				else:
					if whoisq is None:
						continue
					if whoisq.creation_date:
						domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
					if whoisq.registrar:
						domain['whois-registrar'] = str(whoisq.registrar)
		p_cli(' Done\n')

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
