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
__version__ = '20200429'
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

try:
	import queue
except ImportError:
	import Queue as queue

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
	import whois
	MODULE_WHOIS = True
except ImportError:
	MODULE_WHOIS = False
	pass

try:
	import ssdeep as ssdeeplib
	MODULE_SSDEEP = True
except ImportError:
	MODULE_SSDEEP = False

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
WHOIS_MAX_TRIES = 1

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


def p_cli(data):
	global args
	if args.format == 'cli':
		sys.stdout.write(data)
		sys.stdout.flush()


def p_err(data):
	sys.stderr.write(path.basename(sys.argv[0]) + ': ' + data)
	sys.stderr.flush()


def p_csv(data):
	global args
	if args.format == 'csv':
		sys.stdout.write(data)


def p_json(data):
	global args
	if args.format == 'json':
		sys.stdout.write(data)


def bye(code):
	sys.stdout.write(FG_RST + ST_RST)
	sys.exit(code)


def sigint_handler(signal, frame):
	sys.stdout.write('\nStopping threads... ')
	sys.stdout.flush()
	for worker in threads:
		worker.stop()
		worker.join()
	sys.stdout.write('Done\n')
	bye(0)


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
		if len(domain) > 255:
			return False
		if domain[-1] == '.':
			domain = domain[:-1]
		allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
		return allowed.match(domain)

	def get_full_uri(self):
		return self.scheme + '://' + self.domain + self.path + self.query


class DomainFuzz():

	def __init__(self, domain):
		self.subdomain, self.domain, self.tld = self.__domain_tld(domain)
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
		self.keyboards = [ self.qwerty, self.qwertz, self.azerty ]

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

	def __validate_domain(self, domain):
		try:
			domain_idna = domain.encode('idna').decode()
		except UnicodeError:
			# '.tla'.encode('idna') raises UnicodeError: label empty or too long
			# This can be obtained when __omission takes a one-letter domain.
			return False
		if len(domain) == len(domain_idna) and domain != domain_idna:
			return False
		allowed = re.compile('(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)', re.IGNORECASE)
		return allowed.match(domain_idna)

	def __filter_domains(self):
		seen = set()
		filtered = []

		for d in self.domains:
			#if not self.__validate_domain(d['domain-name']):
				#p_err("debug: invalid domain %s\n" % d['domain-name'])
			if self.__validate_domain(d['domain-name']) and d['domain-name'] not in seen:
				seen.add(d['domain-name'])
				filtered.append(d)

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

	def generate(self):
		self.domains.append({ 'fuzzer': 'Original*', 'domain-name': '.'.join(filter(None, [self.subdomain, self.domain, self.tld])) })

		for domain in self.__addition():
			self.domains.append({ 'fuzzer': 'Addition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__bitsquatting():
			self.domains.append({ 'fuzzer': 'Bitsquatting', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__homoglyph():
			self.domains.append({ 'fuzzer': 'Homoglyph', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__hyphenation():
			self.domains.append({ 'fuzzer': 'Hyphenation', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__insertion():
			self.domains.append({ 'fuzzer': 'Insertion', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__omission():
			self.domains.append({ 'fuzzer': 'Omission', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__repetition():
			self.domains.append({ 'fuzzer': 'Repetition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__replacement():
			self.domains.append({ 'fuzzer': 'Replacement', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__subdomain():
			self.domains.append({ 'fuzzer': 'Subdomain', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__transposition():
			self.domains.append({ 'fuzzer': 'Transposition', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })
		for domain in self.__vowel_swap():
			self.domains.append({ 'fuzzer': 'Vowel-swap', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })

		if '.' in self.tld:
			self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + '.' + self.tld.split('.')[-1] })
			self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + self.tld })
		if '.' not in self.tld:
			self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + self.tld + '.' + self.tld })
		if self.tld != 'com' and '.' not in self.tld:
			self.domains.append({ 'fuzzer': 'Various', 'domain-name': self.domain + '-' + self.tld + '.com' })

		self.__filter_domains()


class DomainDict(DomainFuzz):

	def __init__(self, domain):
		DomainFuzz.__init__(self, domain)
		self.dictionary = []

	def load_dict(self, file):
		if path.exists(file):
			for word in open(file):
				word = word.strip('\n')
				if word.isalpha() and word not in self.dictionary:
					self.dictionary.append(word)

	def __dictionary(self):
		result = []

		for word in self.dictionary:
			result.append(self.domain + '-' + word)
			result.append(self.domain + word)
			result.append(word + '-' + self.domain)
			result.append(word + self.domain)

		return result

	def generate(self):
		for domain in self.__dictionary():
			self.domains.append({ 'fuzzer': 'Dictionary', 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld])) })


class TldDict(DomainDict):

	def generate(self):
		if self.tld in self.dictionary:
			self.dictionary.remove(self.tld)
		for tld in self.dictionary:
				self.domains.append({ 'fuzzer': 'TLD-swap', 'domain-name': '.'.join(filter(None, [self.subdomain, self.domain, tld])) })


class DomainThread(threading.Thread):

	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.jobs = queue
		self.kill_received = False

		self.ssdeep_orig = ''
		self.domain_orig = ''

		self.uri_scheme = 'http'
		self.uri_path = ''
		self.uri_query = ''

		self.option_extdns = False
		self.option_geoip = False
		self.option_whois = False
		self.option_ssdeep = False
		self.option_banners = False
		self.option_mxcheck = False

	def __banner_http(self, ip, vhost):
		try:
			http = socket.socket()
			http.settimeout(1)
			http.connect((ip, 80))
			http.send(b'HEAD / HTTP/1.1\r\nHost: %s\r\nUser-agent: %s\r\n\r\n' % (vhost.encode(), args.useragent.encode()))
			response = http.recv(1024).decode()
			http.close()
		except Exception:
			pass
		else:
			sep = '\r\n' if '\r\n' in response else '\n'
			headers = response.split(sep)
			for field in headers:
				if field.startswith('Server: '):
					return field[8:]
			banner = headers[0].split(' ')
			if len(banner) > 1:
				return 'HTTP %s' % banner[1]

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
			sep = '\r\n' if '\r\n' in response else '\n'
			hello = response.split(sep)[0]
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

	def stop(self):
		self.kill_received = True

	@staticmethod
	def answer_to_list(answers):
		return sorted(list(map(lambda record: str(record).strip(".") if len(str(record).split(' ')) == 1 else str(record).split(' ')[1].strip('.'), answers)))

	def run(self):
		while not self.kill_received:
			try:
				domain = self.jobs.get(block=False)
			except queue.Empty:
				self.kill_received = True
				return

			domain['domain-name'] = domain['domain-name'].encode('idna').decode()

			if self.option_extdns:
				if args.nameservers:
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
					domain['dns-ns'] = self.answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.NS))
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
						domain['dns-a'] = self.answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.A))
						dns_a = True
					except dns.resolver.NoNameservers:
						domain['dns-a'] = ['!ServFail']
						pass
					except DNSException:
						pass

					try:
						domain['dns-aaaa'] = self.answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.AAAA))
						dns_aaaa = True
					except dns.resolver.NoNameservers:
						domain['dns-aaaa'] = ['!ServFail']
						pass
					except DNSException:
						pass

				if nxdomain is False and dns_ns is True:
					try:
						domain['dns-mx'] = self.answer_to_list(resolv.query(domain['domain-name'], rdtype=dns.rdatatype.MX))
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
					if domain['domain-name'] is not self.domain_orig:
						if self.__mxcheck(domain['dns-mx'][0], self.domain_orig, domain['domain-name']):
							domain['mx-spy'] = True

			if self.option_whois:
				domain['whois-created'] = None
				domain['whois-updated'] = None
				if nxdomain is False and dns_ns is True:
					whoisAttempts = 0
					while whoisAttempts < WHOIS_MAX_TRIES:
						try:
							whoisdb = whois.query(domain['domain-name'])
							domain['whois-created'] = str(whoisdb.creation_date).split(' ')[0]
							domain['whois-updated'] = str(whoisdb.last_updated).split(' ')[0]
							break
						except Exception:
							whoisAttempts += 1

			if self.option_geoip:
				domain['geoip-country'] = None
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
				domain['banner-http'] = None
				domain['banner-smtp'] = None
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
						req = requests.get(self.uri_scheme + '://' + domain['domain-name'] + self.uri_path + self.uri_query, timeout=REQUEST_TIMEOUT_HTTP, headers={'User-Agent': args.useragent}, verify=False)
						#ssdeep_fuzz = ssdeeplib.hash(req.text.replace(' ', '').replace('\n', ''))
						ssdeep_fuzz = ssdeeplib.hash(req.text)
					except Exception:
						pass
					else:
						if req.status_code // 100 == 2:
							domain['ssdeep-score'] = ssdeeplib.compare(self.ssdeep_orig, ssdeep_fuzz)

			domain['domain-name'] = domain['domain-name'].encode().decode('idna')

			self.jobs.task_done()


def one_or_all(answers):
	if args.all:
		result = ';'.join(answers)
	else:
		if len(answers):
			result = answers[0]
		else:
			result = ''
	return result


def generate_json(domains):
	json_domains = domains
	for domain in json_domains:
		domain['domain-name'] = domain['domain-name'].lower().encode('idna').decode()
		domain['fuzzer'] = domain['fuzzer'].lower()

	return json.dumps(json_domains, indent=4, sort_keys=True)


def generate_csv(domains):
	output = 'fuzzer,domain-name,dns-a,dns-aaaa,dns-mx,dns-ns,geoip-country,whois-created,whois-updated,ssdeep-score\n'

	for domain in domains:
		output += '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' % (
			domain.get('fuzzer'),
			domain.get('domain-name').encode('idna').decode(),
			one_or_all(domain.get('dns-a', [''])),
			one_or_all(domain.get('dns-aaaa', [''])),
			one_or_all(domain.get('dns-mx', [''])),
			one_or_all(domain.get('dns-ns', [''])),
			domain.get('geoip-country', ''),
			domain.get('whois-created', ''),
			domain.get('whois-updated', ''),
			str(domain.get('ssdeep-score', ''))
			)

	return output


def generate_idle(domains):
	idle = '\n'.join([x.get('domain-name').encode('idna').decode() for x in domains])
	return idle + '\n'


def generate_cli(domains):
	output = ''

	width_fuzzer = max([len(d['fuzzer']) for d in domains]) + 1
	width_domain = max([len(d['domain-name']) for d in domains]) + 1

	for domain in domains:
		info = ''

		if 'dns-a' in domain:
			info += one_or_all(domain['dns-a'])
			if 'geoip-country' in domain:
				info += FG_CYA + '/' + domain['geoip-country'] + FG_RST
			info += ' '

		if 'dns-aaaa' in domain:
			info += one_or_all(domain['dns-aaaa']) + ' '

		if 'dns-ns' in domain:
			info += '%sNS:%s%s%s ' % (FG_YEL, FG_CYA, one_or_all(domain['dns-ns']), FG_RST)

		if 'dns-mx' in domain:
			if 'mx-spy' in domain:
				info += '%sSPYING-MX:%s%s' % (FG_YEL, domain['dns-mx'][0], FG_RST)
			else:
				info += '%sMX:%s%s%s ' % (FG_YEL, FG_CYA, one_or_all(domain['dns-mx']), FG_RST)

		if 'banner-http' in domain:
			info += '%sHTTP:%s"%s"%s ' % (FG_YEL, FG_CYA, domain['banner-http'], FG_RST)

		if 'banner-smtp' in domain:
			info += '%sSMTP:%s"%s"%s ' % (FG_YEL, FG_CYA, domain['banner-smtp'], FG_RST)

		if 'whois-created' in domain and 'whois-updated' in domain and (domain['whois-created'] != None or domain['whois-updated'] != None):
			if domain['whois-created'] == domain['whois-updated']:
				info += '%sCreated/Updated:%s%s%s ' % (FG_YEL, FG_CYA, domain['whois-created'], FG_RST)
			else:
				if 'whois-created' in domain:
					info += '%sCreated:%s%s%s ' % (FG_YEL, FG_CYA, domain['whois-created'], FG_RST)
				if 'whois-updated' in domain:
					info += '%sUpdated:%s%s%s ' % (FG_YEL, FG_CYA, domain['whois-updated'], FG_RST)

		if 'ssdeep-score' in domain:
			if domain['ssdeep-score'] > 0:
				info += '%sSSDEEP:%d%%%s ' % (FG_YEL, domain['ssdeep-score'], FG_RST)

		info = info.strip()

		if not info:
			info = '-'

		output += '%s%s%s %s %s\n' % (FG_BLU, domain['fuzzer'].ljust(width_fuzzer), FG_RST, domain['domain-name'].ljust(width_domain), info)

	return output

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
		bye(-1)
	else:
		raise error


def dnstwist(domain,all=False,banners=False,dictionary=None,geoip=False,mxcheck=False,registered=False,ssdeep=False,threadcount=THREAD_COUNT_DEFAULT,whois=False,tld=None,nameservers=None,port=53,useragent=None,cli=False,format="cli"):
	# When args are parsed in from the cli, they create a Namespace object
	# this object is essentially just strings that are parsed out to objects at time of use
	# most are bool or string, so nbd, but namespaces can take a list... kind of
	# it's expecting a comma separated list, not an actual list() object
	#
	# uses the same params as main() with the exception of format which is assumed to be json
	global args
	if isinstance(nameservers, list):
		nameservers = ",".join(nameservers)
	args = argparse.Namespace(**locals())

	signal.signal(signal.SIGINT, sigint_handler)
	
	if args.threadcount < 1:
		args.threadcount = THREAD_COUNT_DEFAULT

	try:
		url = UrlParser(args.domain)
	except ValueError as err:
		write_error(ValueError('Error: %s\n' % err),cli)
		raise

	dfuzz = DomainFuzz(url.domain)
	dfuzz.generate()
	domains = dfuzz.domains

	if args.dictionary:
		if not path.exists(args.dictionary):
			write_error(FileNotFoundError('Error: Dictionary not found: %s\n' % args.dictionary),cli)
		ddict = DomainDict(url.domain)
		ddict.load_dict(args.dictionary)
		ddict.generate()
		domains += ddict.domains

	if args.tld:
		if not path.exists(args.tld):
			write_error(FileNotFoundError('Error: Dictionary not found: %s\n' % args.tld),cli)
		tlddict = TldDict(url.domain)
		tlddict.load_dict(args.tld)
		tlddict.generate()
		domains += tlddict.domains

	if args.format == 'idle' and cli:
		sys.stdout.write(generate_idle(domains))
		bye(0)

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

	if MODULE_WHOIS and args.whois:
		write_warning('Notice: Disabled multithreading in order to query WHOIS servers\n',cli)
		args.threadcount = 1

	if args.ssdeep and MODULE_SSDEEP and MODULE_REQUESTS:
		write_log('Fetching content from: ' + url.get_full_uri() + ' ... ',cli)
		try:
			req = requests.get(url.get_full_uri(), timeout=REQUEST_TIMEOUT_HTTP, headers={'User-Agent': args.useragent})
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
			write_log('%d %s (%.1f Kbytes)\n' % (req.status_code, req.reason, float(len(req.text))/1000),cli)
			if req.status_code / 100 == 2:
				#ssdeep_orig = ssdeeplib.hash(req.text.replace(' ', '').replace('\n', ''))
				ssdeep_orig = ssdeeplib.hash(req.text)
			else:
				args.ssdeep = False

	write_log('Processing %d domain variants ' % len(domains))

	jobs = queue.Queue()

	global threads
	threads = []

	for i in range(len(domains)):
		jobs.put(domains[i])

	for i in range(args.threadcount):
		worker = DomainThread(jobs)
		worker.setDaemon(True)

		worker.uri_scheme = url.scheme
		worker.uri_path = url.path
		worker.uri_query = url.query

		worker.domain_orig = url.domain

		if MODULE_DNSPYTHON:
			worker.option_extdns = True
		if MODULE_WHOIS and args.whois:
			worker.option_whois = True
		if MODULE_GEOIP and args.geoip:
			worker.option_geoip = True
		if args.banners:
			worker.option_banners = True
		if args.ssdeep and MODULE_REQUESTS and MODULE_SSDEEP and 'ssdeep_orig' in locals():
			worker.option_ssdeep = True
			worker.ssdeep_orig = ssdeep_orig
		if args.mxcheck:
			worker.option_mxcheck = True

		worker.start()
		threads.append(worker)

	qperc = 0
	while not jobs.empty():
		if cli:
			p_cli('.')
		qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
		if qcurr - 15 >= qperc:
			qperc = qcurr
			write_log('%u%%' % qperc,cli)
		time.sleep(1)

	for worker in threads:
		worker.stop()
		worker.join()

	hits_total = sum('dns-ns' in d or 'dns-a' in d for d in domains)
	hits_percent = 100 * hits_total / len(domains)
	write_log(' %d hits (%d%%)\n\n' % (hits_total, hits_percent),cli)

	if args.registered:
		domains[:] = [d for d in domains if 'dns-a' in d and len(d['dns-a']) > 0]

	if domains:
		if not cli:
			return json.loads(generate_json(domains))
		else:
			if args.format == 'csv':
				p_csv(generate_csv(domains))
			if args.format == 'json':
				p_json(generate_json(domains))
			else:
				p_cli(generate_cli(domains))
			bye(0)



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
	parser.add_argument('-g', '--geoip', action='store_true', help='Lookup for GeoIP location')
	parser.add_argument('-m', '--mxcheck', action='store_true', help='Check if MX can be used to intercept emails')
	parser.add_argument('-f', '--format', type=str, choices=['cli', 'csv', 'json', 'idle'], default='cli', help='Output format (default: cli)')
	parser.add_argument('-r', '--registered', action='store_true', help='Show only registered domain names')
	parser.add_argument('-s', '--ssdeep', action='store_true', help='Fetch web pages and compare their fuzzy hashes to evaluate similarity')
	parser.add_argument('-t', '--threadcount', type=int, metavar='NUMBER', default=THREAD_COUNT_DEFAULT, help='Start specified NUMBER of threads (default: %d)' % THREAD_COUNT_DEFAULT)
	parser.add_argument('-w', '--whois', action='store_true', help='Lookup for WHOIS creation/update time (slow!)')
	parser.add_argument('--tld', type=str, metavar='FILE', help='Generate more domains by swapping TLD from FILE')
	parser.add_argument('--nameservers', type=str, metavar='LIST', help='DNS servers to query (separated with commas)')
	parser.add_argument('--port', type=int, metavar='PORT', default=53, help='DNS server port number (default: 53)')
	parser.add_argument('--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnstwist/%s' % __version__, help='User-Agent STRING to send with HTTP requests (default: Mozilla/5.0 dnstwist/%s)' % __version__)

	if len(sys.argv) < 2:
		sys.stdout.write('%sdnstwist %s by <%s>%s\n\n' % (ST_BRI, __version__, __email__, ST_RST))
		parser.print_help()
		bye(0)

	argNamespace = parser.parse_args()
	args = vars(argNamespace)


	dnstwist(**args,cli=True)


if __name__ == '__main__':
	main()