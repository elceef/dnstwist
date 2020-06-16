#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#      _           _            _     _
#   __| |_ __  ___| |___      _(_)___| |_
#  / _` | '_ \/ __| __\ \ /\ / / / __| __|
# | (_| | | | \__ \ |_ \ V  V /| \__ \ |_
#  \__,_|_| |_|___/\__| \_/\_/ |_|___/\__|
#
# Generate and resolve domain variations to detect typo squatting,
# phishing and corporate espionage.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = 'Marcin Ulikowski'
__version__ = '20200521'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket
import signal
import time
import argparse
import threading
import warnings
from random import randint
from os import path
import smtplib
import json
import queue

try:
	import dns.resolver
	import dns.rdatatype
	from dns.exception import DNSException
	MODULE_DNSPYTHON = True
except ImportError:
	MODULE_DNSPYTHON = False
	pass

try:
	import GeoIP
	MODULE_GEOIP = True
except ImportError:
	MODULE_GEOIP = False
	pass

try:
	import whois as whoislib
	MODULE_WHOIS = True
except ImportError:
	MODULE_WHOIS = False
	pass

try:
	import ssdeep as ssdeeplib
	MODULE_SSDEEP = True
except ImportError:
	try:
		import ppdeep as ssdeeplib
		MODULE_SSDEEP = True
	except ImportError:
		MODULE_SSDEEP = False
		pass

try:
	import requests
	requests.packages.urllib3.disable_warnings()
	MODULE_REQUESTS = True
except ImportError:
	MODULE_REQUESTS = False
	pass

REQUEST_TIMEOUT_DNS = 2.5
REQUEST_RETRIES_DNS = 2
REQUEST_TIMEOUT_HTTP = 5
REQUEST_TIMEOUT_SMTP = 5
THREAD_COUNT_DEFAULT = 10

if sys.platform != 'win32' and sys.stdout.isatty():
	FG_RND = '\x1b[3%dm' % randint(1, 8)
	FG_RED = '\x1b[31m'
	FG_YEL = '\x1b[33m'
	FG_GRE = '\x1b[32m'
	FG_MAG = '\x1b[35m'
	FG_CYA = '\x1b[36m'
	FG_BLU = '\x1b[34m'
	FG_RST = '\x1b[39m'
	ST_BRI = '\x1b[1m'
	ST_RST = '\x1b[0m'
else:
	FG_RND = FG_RED = FG_YEL = FG_GRE = FG_MAG = FG_CYA = FG_BLU = FG_RST = ST_BRI = ST_RST = ''

# pulled out p_cli, p_error, _exit, and sigint_handler so dnstwist function can reference them
def p_cli(data):
	global args
	if args.format == 'cli':
		sys.stdout.write(data)
		sys.stdout.flush()


def p_err(data):
	sys.stderr.write(path.basename(sys.argv[0]) + ': ' + data)
	sys.stderr.flush()

def _exit(code):
	print(FG_RST + ST_RST, end='')
	sys.exit(code)


def signal_handler(signal, frame):
		print('\nStopping threads... ', file=sys.stderr, end='', flush=True)
		for worker in threads:
			worker.stop()
			worker.join()
		print('Done', file=sys.stderr)
		_exit(0)


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
		domain.strip('.')
		allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
		return allowed.match(domain)

	def full_uri(self):
		return self.scheme + '://' + self.domain + self.path + self.query

class DomainFuzz():
	def __init__(self, domain, dictionary=[], tld_dictionary=[]):
		self.subdomain, self.domain, self.tld = self.__domain_tld(domain)
		self.dictionary = dictionary
		self.tld_dictionary = tld_dictionary
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

	def __domain_tld(self, domain):
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

	def __filter_domains(self):
		def idna(domain):
			try:
				return domain.encode('idna').decode()
			except UnicodeError:
				return b''
		idna_domains = list(map(idna, [x['domain-name'] for x in self.domains]))
		valid_regex = re.compile('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)', re.IGNORECASE)
		seen = set()
		filtered = []
		for idx, domain in enumerate(idna_domains):
			if valid_regex.match(domain) and domain not in seen:
				filtered.append(self.domains[idx])
				seen.add(domain)
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
			'a': [u'à', u'á', u'â', u'ã', u'ä', u'å', u'ɑ', u'ạ', u'ǎ', u'ă', u'ȧ', u'ą'],
			'b': ['d', 'lb', u'ʙ', u'ɓ', u'ḃ', u'ḅ', u'ḇ', u'ƅ'],
			'c': ['e', u'ƈ', u'ċ', u'ć', u'ç', u'č', u'ĉ'],
			'd': ['b', 'cl', 'dl', u'ɗ', u'đ', u'ď', u'ɖ', u'ḑ', u'ḋ', u'ḍ', u'ḏ', u'ḓ'],
			'e': ['c', u'é', u'è', u'ê', u'ë', u'ē', u'ĕ', u'ě', u'ė', u'ẹ', u'ę', u'ȩ', u'ɇ', u'ḛ'],
			'f': [u'ƒ', u'ḟ'],
			'g': ['q', u'ɢ', u'ɡ', u'ġ', u'ğ', u'ǵ', u'ģ', u'ĝ', u'ǧ', u'ǥ'],
			'h': ['lh', u'ĥ', u'ȟ', u'ħ', u'ɦ', u'ḧ', u'ḩ', u'ⱨ', u'ḣ', u'ḥ', u'ḫ', u'ẖ'],
			'i': ['1', 'l', u'í', u'ì', u'ï', u'ı', u'ɩ', u'ǐ', u'ĭ', u'ỉ', u'ị', u'ɨ', u'ȋ', u'ī'],
			'j': [u'ʝ', u'ɉ'],
			'k': ['lk', 'ik', 'lc', u'ḳ', u'ḵ', u'ⱪ', u'ķ'],
			'l': ['1', 'i', u'ɫ', u'ł'],
			'm': ['n', 'nn', 'rn', 'rr', u'ṁ', u'ṃ', u'ᴍ', u'ɱ', u'ḿ'],
			'n': ['m', 'r', u'ń', u'ṅ', u'ṇ', u'ṉ', u'ñ', u'ņ', u'ǹ', u'ň', u'ꞑ'],
			'o': ['0', u'ȯ', u'ọ', u'ỏ', u'ơ', u'ó', u'ö'],
			'p': [u'ƿ', u'ƥ', u'ṕ', u'ṗ'],
			'q': ['g', u'ʠ'],
			'r': [u'ʀ', u'ɼ', u'ɽ', u'ŕ', u'ŗ', u'ř', u'ɍ', u'ɾ', u'ȓ', u'ȑ', u'ṙ', u'ṛ', u'ṟ'],
			's': [u'ʂ', u'ś', u'ṣ', u'ṡ', u'ș', u'ŝ', u'š'],
			't': [u'ţ', u'ŧ', u'ṫ', u'ṭ', u'ț', u'ƫ'],
			'u': [u'ᴜ', u'ǔ', u'ŭ', u'ü', u'ʉ', u'ù', u'ú', u'û', u'ũ', u'ū', u'ų', u'ư', u'ů', u'ű', u'ȕ', u'ȗ', u'ụ'],
			'v': [u'ṿ', u'ⱱ', u'ᶌ', u'ṽ', u'ⱴ'],
			'w': ['vv', u'ŵ', u'ẁ', u'ẃ', u'ẅ', u'ⱳ', u'ẇ', u'ẉ', u'ẘ'],
			'y': [u'ʏ', u'ý', u'ÿ', u'ŷ', u'ƴ', u'ȳ', u'ɏ', u'ỿ', u'ẏ', u'ỵ'],
			'z': [u'ʐ', u'ż', u'ź', u'ᴢ', u'ƶ', u'ẓ', u'ẕ', u'ⱬ']
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
		n = re.sub(r'(.)\1+', r'\1', self.domain)
		if n not in result and n != self.domain:
			result.append(n)
		return list(set(result))

	def __repetition(self):
		result = []
		for i in range(0, len(self.domain)):
			if self.domain[i].isalpha():
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
		for i in range(1, len(self.domain)-3):
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
		self.__filter_domains()

class DomainThread(threading.Thread):

	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.jobs = queue
		self.kill_received = False

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
		from_addr = 'randombob' + str(randint(1, 9)) + '@' + from_domain
		to_addr = 'randomalice' + str(randint(1, 9)) + '@' + to_domain
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
		while not self.kill_received:
			try:
				domain = self.jobs.get(block=False)
			except queue.Empty:
				self.kill_received = True
				return

			domain['domain-name'] = domain['domain-name'].encode('idna').decode()

			if self.option_extdns:
				if self.nameservers:
					resolv = dns.resolver.Resolver(configure=False)
					resolv.nameservers = args.nameservers.split(',')
					if args.port:
						resolv.port = args.port
				else:
					resolv = dns.resolver.Resolver()

				resolv.lifetime = REQUEST_TIMEOUT_DNS * REQUEST_RETRIES_DNS
				resolv.timeout = REQUEST_TIMEOUT_DNS

				nxdomain = False
				dns_ns = False
				dns_a = False
				dns_aaaa = False
				dns_mx = False

				# default init
				domain['dns-ns'] = list()
				domain['dns-a'] = list()
				domain['dns-aaaa'] = list()
				domain['dns-mx'] = list()

				try:
					domain['dns-ns'] = self.__answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.NS))
					dns_ns = True
				except dns.resolver.NXDOMAIN:
					nxdomain = True
					pass
				except dns.resolver.NoNameservers:
					domain['dns-ns'] = ['!ServFail']
					pass
				except DNSException:
					pass

				if nxdomain is False:
					try:
						domain['dns-a'] = self.__answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.A))
						dns_a = True
					except dns.resolver.NoNameservers:
						domain['dns-a'] = ['!ServFail']
						pass
					except DNSException:
						pass

					try:
						domain['dns-aaaa'] = self.__answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.AAAA))
						dns_aaaa = True
					except dns.resolver.NoNameservers:
						domain['dns-aaaa'] = ['!ServFail']
						pass
					except DNSException:
						pass

				if nxdomain is False and dns_ns is True:
					try:
						domain['dns-mx'] = self.__answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.MX))
						dns_mx = True
					except dns.resolver.NoNameservers:
						domain['dns-mx'] = ['!ServFail']
						pass
					except DNSException:
						pass
			else:
				try:
					ip = socket.getaddrinfo(domain['domain-name'], 80)
				except socket.gaierror as e:
					if e.errno == -3:
						domain['dns-a'] = ['!ServFail']
					pass
				except Exception:
					pass
				else:
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
				domain['mx-spy'] = False
				if dns_mx is True:
					if domain['domain-name'] != self.domain_init:
						if self.__mxcheck(domain['dns-mx'][0], self.domain_init, domain['domain-name']):
							domain['mx-spy'] = True

			if self.option_geoip:
				domain['geoip-country'] = str()
				if dns_a is True:
					gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
					try:
						country = gi.country_name_by_addr(domain['dns-a'][0])
					except Exception:
						pass
					else:
						if country:
							domain['geoip-country'] = country.split(',')[0]

			if self.option_banners:
				domain['banner-http'] = str()
				domain['banner-smtp'] = str()
				if dns_a is True or dns_aaaa is True:
					banner = self.__banner_http(domain['dns-a'][0], domain['domain-name'])
					if banner:
						domain['banner-http'] = banner
				if dns_mx is True:
					banner = self.__banner_smtp(domain['dns-mx'][0])
					if banner:
						domain['banner-smtp'] = banner

			if self.option_ssdeep:
				domain['ssdeep-score'] = 0
				if dns_a is True or dns_aaaa is True:
					try:
						req = requests.get(self.uri_scheme + '://' + domain['domain-name'] + self.uri_path + self.uri_query,
							timeout=REQUEST_TIMEOUT_HTTP, headers={'User-Agent': self.useragent}, verify=False)
					except Exception:
						pass
					else:
						if req.status_code // 100 == 2 and req.url.split('?')[0] != self.ssdeep_effective_url:
							ssdeep_curr = ssdeeplib.hash(''.join(req.text.split()).lower())
							domain['ssdeep-score'] = ssdeeplib.compare(self.ssdeep_init, ssdeep_curr)


			domain['domain-name'] = domain['domain-name'].encode().decode('idna')
			self.jobs.task_done()

def create_json(domains=[]):
	domains = list(domains)
	for domain in domains:
		domain['domain-name'] = domain['domain-name'].encode('idna').decode()
	return json.dumps(domains, indent=4, sort_keys=True)


def create_csv(domains=[]):
	csv = ['fuzzer,domain-name,dns-a,dns-aaaa,dns-mx,dns-ns,geoip-country,whois-created,whois-updated,ssdeep-score']
	for domain in domains:
		csv.append(','.join([domain.get('fuzzer'), domain.get('domain-name').encode('idna').decode(),
			';'.join(domain.get('dns-a', [])),
			';'.join(domain.get('dns-aaaa', [])),
			';'.join(domain.get('dns-mx', [])),
			';'.join(domain.get('dns-ns', [])),
			domain.get('geoip-country', ''), 
			domain.get('whois-created', ''),
			domain.get('whois-updated'),
			str(domain.get('ssdeep-score', ''))]))
	return '\n'.join(csv)

def create_idle(domains=[]):
	idle = '\n'.join([x.get('domain-name').encode('idna').decode() for x in domains])
	return idle

def create_cli(domains=[]):
	cli = []

	width_fuzzer = max([len(d['fuzzer']) for d in domains]) + 1
	width_domain = max([len(d['domain-name']) for d in domains]) + 1

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
			info.append(FG_YEL + 'HTTP:' + FG_CYA + '"' + domain['banner-http'] + '"' + FG_RST)

		if 'banner-smtp' in domain:
			info.append(FG_YEL + 'SMTP:' + FG_CYA + '"' + domain['banner-smtp'] + '"' + FG_RST)
		if 'whois-created' in domain and 'whois-updated' in domain and (len(domain['whois-created']) > 1 or len(domain['whois-updated']) > 1):
			if domain['whois-created'] == domain['whois-updated']:
				info.append(FG_YEL + 'CREATED/UPDATED:' + FG_CYA + domain['whois-created'] + FG_RST)
			else:
				if 'whois-created' in domain:
					info.append(FG_YEL + 'CREATED:' + FG_CYA + domain['whois-created'] + FG_RST)
				if 'whois-updated' in domain:
					info.append(FG_YEL + 'UPDATED:' + FG_CYA + domain['whois-updated'] + FG_RST)
		if domain.get('ssdeep-score', 0) > 0:
			info.append(FG_YEL + 'SSDEEP:' + str(domain['ssdeep-score']) + FG_RST)
		if not info:
			info = ['-']
		cli.append(' '.join([FG_BLU + domain['fuzzer'].ljust(width_fuzzer) + FG_RST,
			domain['domain-name'].ljust(width_domain), ' '.join(info)]))
	return '\n'.join(cli)

def write_log(message,cli=False):
	if cli:
		p_cli(message)
	else:
		print(message)

def write_warning(warning,cli=False):
	if cli:
		p_err(warning)
	else:
		warnings.warn(warning)

def write_error(error,cli=False):
	if cli:
		p_err(error.args[0])
		_exit(-1)
	else:
		raise error


def dnstwist(domain,all=False,banners=False,dictionary=None,geoip=False,mxcheck=False,output=None,registered=False,ssdeep=False,ssdeep_url=None,threadcount=THREAD_COUNT_DEFAULT,whois=False,tld=None,nameservers=None,port=53,useragent=None,cli=False,format="cli"):
	# When args are parsed in from the cli, they create a Namespace object
	# this object is essentially just strings that are parsed out to objects at time of use
	# most are bool or string, so nbd, but namespaces can take a list... kind of
	# it's expecting a comma separated list, not an actual list() object
	#
	# uses the same params as main() with the exception of format which is assumed to be json
	global args
	global threads

	if isinstance(nameservers, list):
		nameservers = ",".join(nameservers)
	args = argparse.Namespace(**locals())
	threads = []
	nameservers = []
	dictionary = []
	tld = []

	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)

	if args.threadcount < 1:
		args.threadcount = THREAD_COUNT_DEFAULT

	if args.nameservers:
		nameservers = args.nameservers.split(',')
		for r in nameservers:
			if len(r.split('.')) != 4:
				write_error(ValueError('Error: Invalid DNS nameserver',cli))

	if args.dictionary:
		if not path.exists(args.dictionary):
			write_error(FileNotFoundError('Error: Dictionary file not found: %s\n' % args.dictionary),cli)
		with open(args.dictionary) as f:
			dictionary = set(f.read().splitlines())
			dictionary = [x for x in dictionary if x.isalnum()]

	if args.tld:
		if not path.exists(args.tld):
			write_error(FileNotFoundError('Error: Dictionary file not found: %s\n' % args.tld),cli)
		with open(args.tld) as f:
			tld = set(f.read().splitlines())
			tld = [x for x in tld if x.isalpha()]

	if args.output:
		try:
			sys.stdout = open(args.output, 'x')
		except FileExistsError:
			write_error(FileExistsError('File already exists: %s' % args.output),cli)
			raise
		except FileNotFoundError:
			write_error(FileNotFoundError('No such file or directory: %s' % args.output),cli)
			raise
		except PermissionError:
			write_error(PermissionError('Permission denied: %s' % args.output),cli)
			raise

	if args.ssdeep_url:
		try:
			ssdeep_url = UrlParser(args.ssdeep_url)
		except ValueError:
			write_error(ValueError('Invalid domain name: ' + args.ssdeep_url),cli)
	
	try:
		url = UrlParser(args.domain)
	except ValueError as err:
		write_error(ValueError('Error: %s\n' % err),cli)
		raise

	fuzz = DomainFuzz(url.domain, dictionary=dictionary, tld_dictionary=tld)
	fuzz.generate()
	domains = fuzz.domains

	if args.format == 'idle' and cli:
		print(create_idle(domains))
		_exit(0)

	if not MODULE_DNSPYTHON:
		write_warning('Notice: Missing module DNSPython (DNS features limited)\n',cli)
	if not MODULE_GEOIP and args.geoip:
		write_warning('Notice: Missing module GeoIP (geographical location not available)\n',cli)		
	if not MODULE_WHOIS and args.whois:
		write_warning('Notice: Missing module whois (WHOIS database not accessible)\n',cli)
	if not MODULE_SSDEEP and args.ssdeep:
		write_warning('Notice: Missing module ssdeep (fuzzy hashes not available)\n',cli)
	if not MODULE_REQUESTS and args.ssdeep:
		write_warning('Notice: Missing module Requests (webpage downloads not possible)\n',cli)

	if cli:
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
		write_log('Fetching content from: ' + request_url + ' ... ',cli)
		try:
			req = requests.get(request_url, timeout=REQUEST_TIMEOUT_HTTP, headers={'User-Agent': args.useragent})
		except requests.exceptions.ConnectionError:
			write_log('Connection error\n')
			args.ssdeep = False
			pass
		except requests.exceptions.HTTPError:
			write_log('Invalid HTTP response\n')
			args.ssdeep = False
			pass
		except requests.exceptions.Timeout:
			write_log('Timeout (%d seconds)\n' % REQUEST_TIMEOUT_HTTP)
			args.ssdeep = False
			pass
		except Exception:
			write_log('Failed!\n')
			args.ssdeep = False
			pass
		else:
			if len(req.history) > 1:
				p_cli('➔ %s ' % req.url.split('?')[0])
			write_log('%d %s (%.1f Kbytes)\n' % (req.status_code, req.reason, float(len(req.text))/1000),cli)
			if req.status_code / 100 == 2:
				ssdeep_init = ssdeeplib.hash(''.join(req.text.split()).lower())
				ssdeep_effective_url = req.url.split('?')[0]
			else:
				args.ssdeep = False

	write_log('Processing %d premutations ' % len(domains))

	jobs = queue.Queue()

	for i in range(len(domains)):
		jobs.put(domains[i])

	for i in range(args.threadcount):
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
		if args.ssdeep and MODULE_REQUESTS and MODULE_SSDEEP and 'ssdeep_init' in locals():
			worker.option_ssdeep = True
			worker.ssdeep_init = ssdeep_init
			worker.ssdeep_effective_url = ssdeep_effective_url
		if args.mxcheck:
			worker.option_mxcheck = True
		if args.nameservers:
			worker.nameservers = nameservers
		worker.useragent = args.useragent

		worker.start()
		threads.append(worker)

	qperc = 0
	while not jobs.empty():
		if cli:
			p_cli('.')
		qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
		if qcurr - 20 >= qperc:
			qperc = qcurr
			write_log('%u%%' % qperc,cli)
		time.sleep(1.0)

	hits_total = sum([1 for x in domains if len(x) > 2])
	write_log(' %d hits\n' % hits_total,cli)

	for worker in threads:
		worker.stop()
		worker.join()

	hits_total = sum('dns-ns' in d or 'dns-a' in d for d in domains)
	hits_percent = 100 * hits_total / len(domains)
	write_log(' %d hits (%d%%)\n\n' % (hits_total, hits_percent),cli)

	if args.registered:
		domains[:] = [d for d in domains if 'dns-a' in d and len(d['dns-a']) > 0]

	if MODULE_WHOIS and args.whois and not fuzz.subdomain:
		write_log('Querying WHOIS servers ',cli)
		for domain in domains:
			domain['whois-created'] = str()
			domain['whois-updated'] = str()
			if len(domain) > 2:
				if cli:
					p_cli('·')
				try:
					whoisq = whoislib.query(domain['domain-name'].encode('idna').decode())
					if whoisq:
						domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
						domain['whois-updated'] = str(whoisq.last_updated).split(' ')[0]
				except Exception:
					pass
		write_log(' Done\n',cli)

	write_log('\n',cli)

	if not args.all:
		for i in range(len(domains)):
			for k in ['dns-ns', 'dns-a', 'dns-aaaa', 'dns-mx']:
				if k in domains[i]:
					domains[i][k] = domains[i][k][:1]

	if domains:
		if not cli:
			return json.loads(create_json(domains))
		else:
			if args.format == 'csv':
				print(create_csv(domains))
			if args.format == 'json':
				print(create_json(domains))
			else:
				print(create_cli(domains))
			_exit(0)



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
	parser.add_argument('-f', '--format', type=str, choices=['cli', 'csv', 'json', 'idle'], default='cli', help='Output format (default: cli)')
	parser.add_argument('-g', '--geoip', action='store_true', help='Lookup for GeoIP location')
	parser.add_argument('-m', '--mxcheck', action='store_true', help='Check if MX can be used to intercept emails')
	parser.add_argument('-o', '--output', type=str, metavar='FILE', help='Save output to FILE')
	parser.add_argument('-r', '--registered', action='store_true', help='Show only registered domain names')
	parser.add_argument('-s', '--ssdeep', action='store_true', help='Fetch web pages and compare their fuzzy hashes to evaluate similarity')
	parser.add_argument('--ssdeep-url', metavar='URL', help='Override URL to fetch the original web page from')
	parser.add_argument('-t', '--threadcount', type=int, metavar='NUMBER', default=THREAD_COUNT_DEFAULT, 
		help='Start specified NUMBER of threads (default: %d)' % THREAD_COUNT_DEFAULT)
	parser.add_argument('-w', '--whois', action='store_true', help='Lookup for WHOIS creation/update time')
	parser.add_argument('--tld', type=str, metavar='FILE', help='Generate more domains by swapping TLD from FILE')
	parser.add_argument('--nameservers', type=str, metavar='LIST', help='DNS servers to query (separated with commas)')
	parser.add_argument('--port', type=int, metavar='PORT', default=53, help='DNS server port number (default: 53)')
	parser.add_argument('--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnstwist/%s' % __version__, 
		help='User-Agent STRING to send with HTTP requests (default: Mozilla/5.0 dnstwist/%s)' % __version__)

	if len(sys.argv) < 2:
		sys.stdout.write('%sdnstwist %s by <%s>%s\n\n' % (ST_BRI, __version__, __email__, ST_RST))
		parser.print_help()
		_exit(0)

	argNamespace = parser.parse_args()
	args = vars(argNamespace)

	dnstwist(**args,cli=True)


if __name__ == '__main__':
	main()