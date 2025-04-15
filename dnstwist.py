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
__version__ = '20250130'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket
socket.setdefaulttimeout(12.0)
import signal
import time
import argparse
import threading
import os
import json
import queue
import urllib.request
import urllib.parse
import gzip
from io import BytesIO
from datetime import datetime

def _debug(msg):
	if 'DEBUG' in os.environ:
		if isinstance(msg, Exception):
			print('{}:{} {}'.format(__file__, msg.__traceback__.tb_lineno, str(msg)), file=sys.stderr, flush=True)
		else:
			print(str(msg), file=sys.stderr, flush=True)

try:
	from PIL import Image
	MODULE_PIL = True
except ImportError as e:
	_debug(e)
	MODULE_PIL = False

try:
	from selenium import webdriver
	MODULE_SELENIUM = True
except ImportError as e:
	_debug(e)
	MODULE_SELENIUM = False

try:
	from dns.resolver import Resolver, NXDOMAIN, NoNameservers
	import dns.rdatatype
	from dns.exception import DNSException
	MODULE_DNSPYTHON = True
except ImportError as e:
	_debug(e)
	MODULE_DNSPYTHON = False

GEOLITE2_MMDB = os.environ.get('GEOLITE2_MMDB' , os.path.join(os.path.dirname(__file__), 'GeoLite2-Country.mmdb'))
try:
	import geoip2.database
	_ = geoip2.database.Reader(GEOLITE2_MMDB)
except Exception as e:
	_debug(e)
	try:
		import GeoIP
		_ = GeoIP.new(-1)
	except Exception as e:
		_debug(e)
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
	import ssdeep
	MODULE_SSDEEP = True
except ImportError as e:
	_debug(e)
	try:
		import ppdeep as ssdeep
		MODULE_SSDEEP = True
	except ImportError as e:
		_debug(e)
		MODULE_SSDEEP = False

try:
	import tlsh
	MODULE_TLSH = True
except ImportError as e:
	_debug(e)
	MODULE_TLSH = False

try:
	import idna
except ImportError as e:
	_debug(e)
	class idna:
		@staticmethod
		def decode(domain):
			return domain.encode().decode('idna')
		@staticmethod
		def encode(domain):
			return domain.encode('idna')


VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)', re.IGNORECASE)

USER_AGENT_STRING = 'Mozilla/5.0 ({} {}-bit) dnstwist/{}'.format(sys.platform, sys.maxsize.bit_length() + 1, __version__)
THREAD_COUNT_DEFAULT = min(32, os.cpu_count() + 4)

# adjustable with environment variables
for env, typ, val in [
	('REQUEST_TIMEOUT_DNS', float, 2.5),
	('REQUEST_RETRIES_DNS', int, 2),
	('REQUEST_TIMEOUT_HTTP', float, 5),
	('REQUEST_TIMEOUT_SMTP', float, 5),
	('WEBDRIVER_PAGELOAD_TIMEOUT', float, 12.0)
	]:
	try:
		globals()[env] = typ(os.environ.get(env, val))
	except ValueError:
		globals()[env] = val

if sys.platform != 'win32' and sys.stdout.isatty():
	FG_RND = '\x1b[3{}m'.format(int(time.time())%8+1)
	FG_YEL = '\x1b[33m'
	FG_CYA = '\x1b[36m'
	FG_BLU = '\x1b[34m'
	FG_RST = '\x1b[39m'
	ST_BRI = '\x1b[1m'
	ST_CLR = '\x1b[1K'
	ST_RST = '\x1b[0m'
else:
	FG_RND = FG_YEL = FG_CYA = FG_BLU = FG_RST = ST_BRI = ST_CLR = ST_RST = ''

devnull = os.devnull


def domain_tld(domain):
	try:
		from tld import parse_tld
	except ImportError:
		ctld = ['org', 'com', 'net', 'gov', 'edu', 'co', 'mil', 'nom', 'ac', 'info', 'biz', 'ne']
		d = domain.rsplit('.', 3)
		if len(d) < 2:
			return '', d[0], ''
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


class Whois():
	WHOIS_IANA = 'whois.iana.org'
	TIMEOUT = 2.0
	WHOIS_TLD = {
		'com': 'whois.verisign-grs.com',
		'net': 'whois.verisign-grs.com',
		'org': 'whois.pir.org',
		'info': 'whois.afilias.net',
		'pl': 'whois.dns.pl',
		'us': 'whois.nic.us',
		'co': 'whois.nic.co',
		'cn': 'whois.cnnic.cn',
		'ru': 'whois.tcinet.ru',
		'in': 'whois.registry.in',
		'eu': 'whois.eu',
		'uk': 'whois.nic.uk',
		'de': 'whois.denic.de',
		'nl': 'whois.domain-registry.nl',
		'br': 'whois.registro.br',
		'jp': 'whois.jprs.jp',
	}

	def __init__(self):
		self.whois_tld = self.WHOIS_TLD

	def _brute_datetime(self, s):
		formats = ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S%z', '%Y-%m-%d %H:%M', '%Y.%m.%d %H:%M',
			'%Y.%m.%d %H:%M:%S', '%d.%m.%Y %H:%M:%S', '%a %b %d %Y', '%d-%b-%Y', '%Y-%m-%d')
		for f in formats:
			try:
				dt = datetime.strptime(s, f)
				return dt
			except ValueError:
				pass
		return None

	def _extract(self, response):
		fields = {
			'registrar': (r'[\r\n]registrar[ .]*:\s+(?:name:\s)?(?P<registrar>[^\r\n]+)', str),
			'creation_date': (r'[\r\n](?:created(?: on)?|creation date|registered(?: on)?)[ .]*:\s+(?P<creation_date>[^\r\n]+)', self._brute_datetime),
		}
		result = {'text': response}
		response_reduced = '\r\n'.join([x.strip() for x in response.splitlines() if not x.startswith('%')])
		for field, (pattern, func) in fields.items():
			match = re.search(pattern, response_reduced, re.IGNORECASE | re.MULTILINE)
			if match:
				result[field] = func(match.group(1))
			else:
				result[field] = None
		return result

	def query(self, query, server=None):
		_, _, tld = domain_tld(query)
		server = server or self.whois_tld.get(tld, self.WHOIS_IANA)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(self.TIMEOUT)
		response = b''
		try:
			sock.connect((server, 43))
			sock.send(query.encode() + b'\r\n')
			while True:
				buf = sock.recv(4096)
				if not buf:
					break
				response += buf
			if server and server != self.WHOIS_IANA and tld not in self.whois_tld:
				self.whois_tld[tld] = server
		except (socket.timeout, socket.gaierror):
			return ''
		finally:
			sock.close()
		response = response.decode('utf-8', errors='ignore')
		refer = re.search(r'refer:\s+(?P<server>[-.a-z0-9]+)', response, re.IGNORECASE | re.MULTILINE)
		if refer:
			return self.query(query, refer.group('server'))
		return response

	def whois(self, domain, server=None):
		return self._extract(self.query(domain, server))


class UrlOpener():
	def __init__(self, url, timeout=REQUEST_TIMEOUT_HTTP, headers={}, verify=True):
		http_headers = {'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
			'accept-encoding': 'gzip,identity',
			'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8'}
		for h, v in headers.items():
			# do not override accepted encoding - only gzip,identity is supported
			if h.lower() != 'accept-encoding':
				http_headers[h.lower()] = v
		if verify:
			ctx = urllib.request.ssl.create_default_context()
		else:
			ctx = urllib.request.ssl._create_unverified_context()
		request = urllib.request.Request(url, headers=http_headers)
		with urllib.request.urlopen(request, timeout=timeout, context=ctx) as r:
			self.headers = r.headers
			self.code = r.code
			self.reason = r.reason
			self.url = r.url
			self.content = r.read()
		if self.content[:3] == b'\x1f\x8b\x08':
			self.content = gzip.decompress(self.content)
		if 64 < len(self.content) < 1024:
			try:
				meta_url = re.search(r'<meta[^>]*?url=(https?://[\w.,?!:;/*#@$&+=[\]()%~-]*?)"', self.content.decode(), re.IGNORECASE)
			except Exception:
				pass
			else:
				if meta_url:
					self.__init__(meta_url.group(1), timeout=timeout, headers=http_headers, verify=verify)
		self.normalized_content = self._normalize()

	def _normalize(self):
		content = b' '.join(self.content.split())
		mapping = dict({
			b'(action|src|href)=".+"': lambda m: m.group(0).split(b'=')[0] + b'=""',
			b'url(.+)': b'url()',
			})
		for pattern, repl in mapping.items():
			content = re.sub(pattern, repl, content, flags=re.IGNORECASE)
		return content


class UrlParser():
	def __init__(self, url):
		if not url:
			raise TypeError('argument has to be non-empty string')
		u = urllib.parse.urlparse(url if '://' in url else '//' + url, scheme='http')
		self.scheme = u.scheme.lower()
		if self.scheme not in ('http', 'https'):
			raise ValueError('invalid scheme') from None
		self.domain = u.hostname.lower()
		try:
			self.domain = idna.encode(self.domain).decode()
		except Exception:
			raise ValueError('invalid domain name') from None
		if not self._validate_domain(self.domain):
			raise ValueError('invalid domain name') from None
		self.username = u.username
		self.password = u.password
		self.port = u.port
		self.path = u.path
		self.query = u.query
		self.fragment = u.fragment

	def _validate_domain(self, domain):
		if len(domain) < 1 or len(domain) > 253:
			return False
		if VALID_FQDN_REGEX.match(domain):
			try:
				_ = idna.decode(domain)
			except Exception:
				return False
			else:
				return True
		return False

	def full_uri(self, domain=None):
		uri = '{}://'.format(self.scheme)
		if self.username:
			uri += self.username
			if self.password:
				uri += ':{}'.format(self.password)
			uri += '@'
		uri += self.domain if not domain else domain
		if self.port:
			uri += ':{}'.format(self.port)
		if self.path:
			uri += self.path
		if self.query:
			uri += '?{}'.format(self.query)
		if self.fragment:
			uri += '#{}'.format(self.fragment)
		return uri


class Permutation(dict):
	def __getattr__(self, item):
		if item in self:
			return self[item]
		raise AttributeError("object has no attribute '{}'".format(item)) from None

	__setattr__ = dict.__setitem__

	def __init__(self, **kwargs):
		super(dict, self).__init__()
		self['fuzzer'] = kwargs.pop('fuzzer', '')
		self['domain'] = kwargs.pop('domain', '')
		for k, v in kwargs.items():
			self[k] = v

	def __hash__(self):
		return hash(self['domain'])

	def __eq__(self, other):
		return self['domain'] == other['domain']

	def __lt__(self, other):
		if self['fuzzer'] == other['fuzzer']:
			if len(self) > 2 and len(other) > 2:
				return self.get('dns_a', [''])[0] + self['domain'] < other.get('dns_a', [''])[0] + other['domain']
			else:
				return self['domain'] < other['domain']
		return self['fuzzer'] < other['fuzzer']

	def is_registered(self):
		return len(self) > 2

	def copy(self):
		return Permutation(**self)


class pHash():
	def __init__(self, image, hsize=8):
		img = Image.open(image).convert('L').resize((hsize, hsize), Image.LANCZOS)
		pixels = list(img.getdata())
		avg = sum(pixels) / len(pixels)
		self.hash = ''.join('1' if p > avg else '0' for p in pixels)

	def __sub__(self, other):
		bc = len(self.hash)
		ham = sum(x != y for x, y in list(zip(self.hash, other.hash)))
		e = 2.718281828459045
		sub = int((1 + e**((bc - ham) / bc) - e) * 100)
		return sub if sub > 0 else 0

	def __repr__(self):
		return '{:x}'.format(int(self.hash, base=2))

	def __int__(self):
		return int(self.hash, base=2)


class HeadlessBrowser():
	WEBDRIVER_TIMEOUT = WEBDRIVER_PAGELOAD_TIMEOUT
	WEBDRIVER_ARGUMENTS = (
		'--disable-dev-shm-usage',
		'--ignore-certificate-errors',
		'--headless',
		'--incognito',
		'--no-sandbox',
		'--disable-gpu',
		'--disable-extensions',
		'--disk-cache-size=0',
		'--aggressive-cache-discard',
		'--disable-notifications',
		'--disable-remote-fonts',
		'--disable-sync',
		'--window-size=1366,768',
		'--hide-scrollbars',
		'--disable-audio-output',
		'--dns-prefetch-disable',
		'--no-default-browser-check',
		'--disable-background-networking',
		'--enable-features=NetworkService,NetworkServiceInProcess',
		'--disable-background-timer-throttling',
		'--disable-backgrounding-occluded-windows',
		'--disable-breakpad',
		'--disable-client-side-phishing-detection',
		'--disable-component-extensions-with-background-pages',
		'--disable-default-apps',
		'--disable-features=TranslateUI',
		'--disable-hang-monitor',
		'--disable-ipc-flooding-protection',
		'--disable-prompt-on-repost',
		'--disable-renderer-backgrounding',
		'--force-color-profile=srgb',
		'--metrics-recording-only',
		'--no-first-run',
		'--password-store=basic',
		'--use-mock-keychain',
		'--disable-blink-features=AutomationControlled',
		)

	def __init__(self, useragent=None):
		chrome_options = webdriver.ChromeOptions()
		for opt in self.WEBDRIVER_ARGUMENTS:
			chrome_options.add_argument(opt)
		proxies = urllib.request.getproxies()
		if proxies:
			proxy_string = ';'.join(['{}={}'.format(scheme, url) for scheme, url in proxies.items()])
			chrome_options.add_argument('--proxy-server={}'.format(proxy_string))
		chrome_options.add_experimental_option('excludeSwitches', ['enable-automation'])
		chrome_options.add_experimental_option('useAutomationExtension', False)
		self.driver = webdriver.Chrome(options=chrome_options)
		self.driver.set_page_load_timeout(self.WEBDRIVER_TIMEOUT)
		self.driver.execute_cdp_cmd('Network.setUserAgentOverride', {'userAgent':
			useragent or self.driver.execute_script('return navigator.userAgent').replace('Headless', '')
			})
		self.get = self.driver.get
		self.screenshot = self.driver.get_screenshot_as_png

	def stop(self):
		try:
			self.driver.close()
			self.driver.quit()
		except Exception:
			pass
		try:
			pid = True
			while pid:
				pid, status = os.waitpid(-1, os.WNOHANG)
		except ChildProcessError:
			pass

	def __del__(self):
		self.stop()


class Fuzzer():
	glyphs_idn_by_tld = {
		**dict.fromkeys(['ad', 'cz', 'sk', 'uk', 'co.uk', 'nl', 'edu', 'us'], {
			# IDN not supported by the corresponding registry
		}),
		**dict.fromkeys(['jp', 'co.jp', 'ad.jp', 'ne.jp'], {
		}),
		**dict.fromkeys(['cn', 'com.cn', 'tw', 'com.tw', 'net.tw'], {
		}),
		**dict.fromkeys(['info'], {
			'a': ('á', 'ä', 'å', 'ą'),
			'c': ('ć', 'č'),
			'e': ('é', 'ė', 'ę'),
			'i': ('í', 'į'),
			'l': ('ł',),
			'n': ('ñ', 'ń'),
			'o': ('ó', 'ö', 'ø', 'ő'),
			's': ('ś', 'š'),
			'u': ('ú', 'ü', 'ū', 'ű', 'ų'),
			'z': ('ź', 'ż', 'ž'),
			'ae': ('æ',),
		}),
		**dict.fromkeys(['br', 'com.br'], {
			'a': ('à', 'á', 'â', 'ã'),
			'c': ('ç',),
			'e': ('é', 'ê'),
			'i': ('í',),
			'o': ('ó', 'ô', 'õ'),
			'u': ('ú', 'ü'),
			'y': ('ý', 'ÿ'),
		}),
		**dict.fromkeys(['dk'], {
			'a': ('ä', 'å'),
			'e': ('é',),
			'o': ('ö', 'ø'),
			'u': ('ü',),
			'ae': ('æ',),
		}),
		**dict.fromkeys(['eu', 'de', 'pl'], {
			'a': ('á', 'à', 'ă', 'â', 'å', 'ä', 'ã', 'ą', 'ā'),
			'c': ('ć', 'ĉ', 'č', 'ċ', 'ç'),
			'd': ('ď', 'đ'),
			'e': ('é', 'è', 'ĕ', 'ê', 'ě', 'ë', 'ė', 'ę', 'ē'),
			'g': ('ğ', 'ĝ', 'ġ', 'ģ'),
			'h': ('ĥ', 'ħ'),
			'i': ('í', 'ì', 'ĭ', 'î', 'ï', 'ĩ', 'į', 'ī'),
			'j': ('ĵ',),
			'k': ('ķ', 'ĸ'),
			'l': ('ĺ', 'ľ', 'ļ', 'ł'),
			'n': ('ń', 'ň', 'ñ', 'ņ'),
			'o': ('ó', 'ò', 'ŏ', 'ô', 'ö', 'ő', 'õ', 'ø', 'ō'),
			'r': ('ŕ', 'ř', 'ŗ'),
			's': ('ś', 'ŝ', 'š', 'ş'),
			't': ('ť', 'ţ', 'ŧ'),
			'u': ('ú', 'ù', 'ŭ', 'û', 'ů', 'ü', 'ű', 'ũ', 'ų', 'ū'),
			'w': ('ŵ',),
			'y': ('ý', 'ŷ', 'ÿ'),
			'z': ('ź', 'ž', 'ż'),
			'ae': ('æ',),
			'oe': ('œ',),
		}),
		**dict.fromkeys(['fi'], {
			'3': ('ʒ',),
			'a': ('á', 'ä', 'å', 'â'),
			'c': ('č',),
			'd': ('đ',),
			'g': ('ǧ', 'ǥ'),
			'k': ('ǩ',),
			'n': ('ŋ',),
			'o': ('õ', 'ö'),
			's': ('š',),
			't': ('ŧ',),
			'z': ('ž',),
		}),
		**dict.fromkeys(['no'], {
			'a': ('á', 'à', 'ä', 'å'),
			'c': ('č', 'ç'),
			'e': ('é', 'è', 'ê'),
			'i': ('ï',),
			'n': ('ŋ', 'ń', 'ñ'),
			'o': ('ó', 'ò', 'ô', 'ö', 'ø'),
			's': ('š',),
			't': ('ŧ',),
			'u': ('ü',),
			'z': ('ž',),
			'ae': ('æ',),
		}),
		**dict.fromkeys(['be', 'fr', 're', 'yt', 'pm', 'wf', 'tf', 'ch', 'li'], {
			'a': ('à', 'á', 'â', 'ã', 'ä', 'å'),
			'c': ('ç',),
			'e': ('è', 'é', 'ê', 'ë'),
			'i': ('ì', 'í', 'î', 'ï'),
			'n': ('ñ',),
			'o': ('ò', 'ó', 'ô', 'õ', 'ö'),
			'u': ('ù', 'ú', 'û', 'ü'),
			'y': ('ý', 'ÿ'),
			'ae': ('æ',),
			'oe': ('œ',),
		}),
		**dict.fromkeys(['ca'], {
			'a': ('à', 'â'),
			'c': ('ç',),
			'e': ('è', 'é', 'ê', 'ë'),
			'i': ('î', 'ï'),
			'o': ('ô',),
			'u': ('ù', 'û', 'ü'),
			'y': ('ÿ',),
			'ae': ('æ',),
			'oe': ('œ',),
		}),
	}

	glyphs_unicode = {
		'2': ('ƻ',),
		'3': ('ʒ',),
		'5': ('ƽ',),
		'a': ('ạ', 'ă', 'ȧ', 'ɑ', 'å', 'ą', 'â', 'ǎ', 'á', 'ə', 'ä', 'ã', 'ā', 'à'),
		'b': ('ḃ', 'ḅ', 'ƅ', 'ʙ', 'ḇ', 'ɓ'),
		'c': ('č', 'ᴄ', 'ċ', 'ç', 'ć', 'ĉ', 'ƈ'),
		'd': ('ď', 'ḍ', 'ḋ', 'ɖ', 'ḏ', 'ɗ', 'ḓ', 'ḑ', 'đ'),
		'e': ('ê', 'ẹ', 'ę', 'è', 'ḛ', 'ě', 'ɇ', 'ė', 'ĕ', 'é', 'ë', 'ē', 'ȩ'),
		'f': ('ḟ', 'ƒ'),
		'g': ('ǧ', 'ġ', 'ǵ', 'ğ', 'ɡ', 'ǥ', 'ĝ', 'ģ', 'ɢ'),
		'h': ('ȟ', 'ḫ', 'ḩ', 'ḣ', 'ɦ', 'ḥ', 'ḧ', 'ħ', 'ẖ', 'ⱨ', 'ĥ'),
		'i': ('ɩ', 'ǐ', 'í', 'ɪ', 'ỉ', 'ȋ', 'ɨ', 'ï', 'ī', 'ĩ', 'ị', 'î', 'ı', 'ĭ', 'į', 'ì'),
		'j': ('ǰ', 'ĵ', 'ʝ', 'ɉ'),
		'k': ('ĸ', 'ǩ', 'ⱪ', 'ḵ', 'ķ', 'ᴋ', 'ḳ'),
		'l': ('ĺ', 'ł', 'ɫ', 'ļ', 'ľ'),
		'm': ('ᴍ', 'ṁ', 'ḿ', 'ṃ', 'ɱ'),
		'n': ('ņ', 'ǹ', 'ń', 'ň', 'ṅ', 'ṉ', 'ṇ', 'ꞑ', 'ñ', 'ŋ'),
		'o': ('ö', 'ó', 'ȯ', 'ỏ', 'ô', 'ᴏ', 'ō', 'ò', 'ŏ', 'ơ', 'ő', 'õ', 'ọ', 'ø'),
		'p': ('ṗ', 'ƿ', 'ƥ', 'ṕ'),
		'q': ('ʠ',),
		'r': ('ʀ', 'ȓ', 'ɍ', 'ɾ', 'ř', 'ṛ', 'ɽ', 'ȑ', 'ṙ', 'ŗ', 'ŕ', 'ɼ', 'ṟ'),
		's': ('ṡ', 'ș', 'ŝ', 'ꜱ', 'ʂ', 'š', 'ś', 'ṣ', 'ş'),
		't': ('ť', 'ƫ', 'ţ', 'ṭ', 'ṫ', 'ț', 'ŧ'),
		'u': ('ᴜ', 'ų', 'ŭ', 'ū', 'ű', 'ǔ', 'ȕ', 'ư', 'ù', 'ů', 'ʉ', 'ú', 'ȗ', 'ü', 'û', 'ũ', 'ụ'),
		'v': ('ᶌ', 'ṿ', 'ᴠ', 'ⱴ', 'ⱱ', 'ṽ'),
		'w': ('ᴡ', 'ẇ', 'ẅ', 'ẃ', 'ẘ', 'ẉ', 'ⱳ', 'ŵ', 'ẁ'),
		'x': ('ẋ', 'ẍ'),
		'y': ('ŷ', 'ÿ', 'ʏ', 'ẏ', 'ɏ', 'ƴ', 'ȳ', 'ý', 'ỿ', 'ỵ'),
		'z': ('ž', 'ƶ', 'ẓ', 'ẕ', 'ⱬ', 'ᴢ', 'ż', 'ź', 'ʐ'),
		'ae': ('æ',),
		'oe': ('œ',),
	}

	glyphs_ascii = {
		'0': ('o',),
		'1': ('l', 'i'),
		'3': ('8',),
		'6': ('9',),
		'8': ('3',),
		'9': ('6',),
		'b': ('d', 'lb'),
		'c': ('e',),
		'd': ('b', 'cl', 'dl'),
		'e': ('c',),
		'g': ('q',),
		'h': ('lh',),
		'i': ('1', 'l'),
		'k': ('lc',),
		'l': ('1', 'i'),
		'm': ('n', 'nn', 'rn'),
		'n': ('m', 'r'),
		'o': ('0',),
		'q': ('g',),
		'u': ('v',),
		'v': ('u',),
		'w': ('vv',),
		'rn': ('m',),
		'cl': ('d',),
	}

	latin_to_cyrillic = {
		'a': 'а', 'b': 'ь', 'c': 'с', 'd': 'ԁ', 'e': 'е', 'g': 'ԍ', 'h': 'һ',
		'i': 'і', 'j': 'ј', 'k': 'к', 'l': 'ӏ', 'm': 'м', 'o': 'о', 'p': 'р',
		'q': 'ԛ', 's': 'ѕ', 't': 'т', 'v': 'ѵ', 'w': 'ԝ', 'x': 'х', 'y': 'у',
	}

	qwerty = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
	}
	qwertz = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
	}
	azerty = {
		'1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
		'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
		'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
	}
	keyboards = [qwerty, qwertz, azerty]

	def __init__(self, domain, dictionary=[], tld_dictionary=[]):
		self.subdomain, self.domain, self.tld = domain_tld(domain)
		self.domain = idna.decode(self.domain)
		self.dictionary = list(dictionary)
		self.tld_dictionary = list(tld_dictionary)
		self.domains = set()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		return

	def _bitsquatting(self):
		masks = [1, 2, 4, 8, 16, 32, 64, 128]
		chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
		for i, c in enumerate(self.domain):
			for mask in masks:
				b = chr(ord(c) ^ mask)
				if b in chars:
					yield self.domain[:i] + b + self.domain[i+1:]

	def _cyrillic(self):
		cdomain = self.domain
		for l, c in self.latin_to_cyrillic.items():
			cdomain = cdomain.replace(l, c)
		for c, l in zip(cdomain, self.domain):
			if c == l:
				return []
		return [cdomain]

	def _homoglyph(self):
		md = lambda a, b: {k: set(a.get(k, [])) | set(b.get(k, [])) for k in set(a.keys()) | set(b.keys())}
		glyphs = md(self.glyphs_ascii, self.glyphs_idn_by_tld.get(self.tld, self.glyphs_unicode))
		def mix(domain):
			for i, c in enumerate(domain):
				for g in glyphs.get(c, []):
					yield domain[:i] + g + domain[i+1:]
			for i in range(len(domain)-1):
				win = domain[i:i+2]
				for c in {win[0], win[1], win}:
					for g in glyphs.get(c, []):
						yield domain[:i] + win.replace(c, g) + domain[i+2:]
		result1 = set(mix(self.domain))
		result2 = set()
		for r in result1:
			result2.update(set(mix(r)))
		return result1 | result2

	def _hyphenation(self):
		return {self.domain[:i] + '-' + self.domain[i:] for i in range(1, len(self.domain))}

	def _insertion(self):
		result = set()
		for i in range(0, len(self.domain)-1):
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

	def _plural(self):
		for i in range(2, len(self.domain)-2):
			yield self.domain[:i+1] + ('es' if self.domain[i] in ('s', 'x', 'z') else 's') + self.domain[i+1:]


	def _addition(self):
		result = set()
		if '-' in self.domain:
			parts = self.domain.split('-')
			result = {'-'.join(parts[:p]) + chr(i) + '-' + '-'.join(parts[p:]) for i in (*range(48, 58), *range(97, 123)) for p in range(1, len(parts))}
		result.update({self.domain + chr(i) for i in (*range(48, 58), *range(97, 123))})
		return result


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
		if '-' in self.domain:
			parts = self.domain.split('-')
			for word in self.dictionary:
				result.update({
					'-'.join(parts[:-1]) + '-' + word,
					word + '-' + '-'.join(parts[1:])
				})
		return result

	def _tld(self):
		if self.tld in self.tld_dictionary:
			self.tld_dictionary.remove(self.tld)
		return set(self.tld_dictionary)

	def generate(self, fuzzers=[]):
		self.domains = set()
		if not fuzzers or '*original' in fuzzers:
			self.domains.add(Permutation(fuzzer='*original', domain='.'.join(filter(None, [self.subdomain, self.domain, self.tld]))))
		for f_name in fuzzers or [
			'addition', 'bitsquatting', 'cyrillic', 'homoglyph', 'hyphenation',
			'insertion', 'omission', 'plural', 'repetition', 'replacement',
			'subdomain', 'transposition', 'vowel-swap', 'dictionary',
		]:
			try:
				f = getattr(self, '_' + f_name.replace('-', '_'))
			except AttributeError:
				pass
			else:
				for domain in f():
					self.domains.add(Permutation(fuzzer=f_name, domain='.'.join(filter(None, [self.subdomain, domain, self.tld]))))
		if not fuzzers or 'tld-swap' in fuzzers:
			for tld in self._tld():
				self.domains.add(Permutation(fuzzer='tld-swap', domain='.'.join(filter(None, [self.subdomain, self.domain, tld]))))
		if not fuzzers or 'various' in fuzzers:
			if '.' in self.tld:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain, self.tld.split('.')[-1]]))))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + self.tld]))))
			if '.' not in self.tld:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + self.tld, self.tld]))))
			if self.tld != 'com' and '.' not in self.tld:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + '-' + self.tld, 'com']))))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join(filter(None, [self.subdomain, self.domain + self.tld, 'com']))))
			if self.subdomain:
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain + self.domain, self.tld])))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain.replace('.', '') + self.domain, self.tld])))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain + '-' + self.domain, self.tld])))
				self.domains.add(Permutation(fuzzer='various', domain='.'.join([self.subdomain.replace('.', '-') + '-' + self.domain, self.tld])))
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

	def permutations(self, registered=False, unregistered=False, dns_all=False, unicode=False):
		if (registered and not unregistered):
			domains = [x.copy() for x in self.domains if x.is_registered()]
		elif (unregistered and not registered):
			domains = [x.copy() for x in self.domains if not x.is_registered()]
		else:
			domains = [x.copy() for x in self.domains]
		if not dns_all:
			def _cutdns(x):
				if x.is_registered():
					for k in ('dns_ns', 'dns_a', 'dns_aaaa', 'dns_mx'):
						if k in x:
							x[k] = x[k][:1]
				return x
			domains = map(_cutdns, domains)
		if unicode:
			def _punydecode(x):
				x.domain = idna.decode(x.domain)
				return x
			domains = map(_punydecode, domains)
		return sorted(domains)


class Scanner(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self._stop_event = threading.Event()
		self.daemon = True
		self.id = 0
		self.jobs = queue
		self.lsh_init = ''
		self.lsh_effective_url = ''
		self.phash_init = None
		self.screenshot_dir = None
		self.url = None
		self.option_extdns = False
		self.option_geoip = False
		self.option_lsh = None
		self.option_phash = False
		self.option_banners = False
		self.option_mxcheck = False
		self.nameservers = []
		self.useragent = ''

	@staticmethod
	def _send_recv_tcp(host, port, data=b'', timeout=2.0, recv_bytes=1024):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		resp = b''
		try:
			sock.connect((host, port))
			if data:
				sock.send(data)
			resp = sock.recv(recv_bytes)
		except Exception as e:
			_debug(e)
		finally:
			sock.close()
		return resp.decode('utf-8', errors='ignore')

	def _banner_http(self, ip, vhost):
		response = self._send_recv_tcp(ip, 80,
			'HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n\r\n'.format(vhost, self.useragent).encode())
		if not response:
			return ''
		headers = response.splitlines()
		for field in headers:
			if field.lower().startswith('server: '):
				return field[8:]
		return ''

	def _banner_smtp(self, mx):
		response = self._send_recv_tcp(mx, 25)
		if not response:
			return ''
		hello = response.splitlines()[0]
		if hello.startswith('220'):
			return hello[4:].strip()
		return ''

	def _mxcheck(self, mxhost, domain_from, domain_rcpt):
		r'''
		Detects potential email honey pots waiting for mistyped emails to arrive.
		Note: Some mail servers only pretend to accept incorrectly addressed
		emails - this technique is used to prevent "directory harvesting attack".
		'''
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(REQUEST_TIMEOUT_SMTP)
			sock.connect((mxhost, 25))
		except Exception:
			return False
		for cmd in [
			'EHLO {}\r\n'.format(mxhost),
			'MAIL FROM: randombob1986@{}\r\n'.format(domain_from),
			'RCPT TO: randomalice1986@{}\r\n'.format(domain_rcpt),
			# And that's how the cookie crumbles
		]:
			try:
				resp = sock.recv(512)
			except Exception:
				break
			if not resp:
				break
			if resp[0] != 0x32: # status code != 2xx
				break
			sock.send(cmd.encode())
		else:
			sock.close()
			return True
		sock.close()
		return False

	def stop(self):
		self._stop_event.set()

	def is_stopped(self):
		return self._stop_event.is_set()

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
			resolv.rotate = True

			if hasattr(resolv, 'resolve'):
				resolve = resolv.resolve
			else:
				resolve = resolv.query

		if self.option_geoip:
			geo = geoip()

		if self.option_phash:
			browser = HeadlessBrowser(useragent=self.useragent)

		_answer_to_list = lambda ans: sorted([str(x).split(' ')[-1].rstrip('.') for x in ans])

		while not self.is_stopped():
			try:
				task = self.jobs.get(block=False)
			except queue.Empty:
				self.stop()
				return

			domain = task.get('domain')

			dns_a = False
			dns_aaaa = False
			if self.option_extdns:
				nxdomain = False
				dns_ns = False
				dns_mx = False

				try:
					task['dns_ns'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.NS))
					dns_ns = True
				except NXDOMAIN:
					nxdomain = True
				except NoNameservers:
					task['dns_ns'] = ['!ServFail']
				except DNSException as e:
					_debug(e)

				if nxdomain is False:
					try:
						task['dns_a'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.A))
						dns_a = True
					except NoNameservers:
						task['dns_a'] = ['!ServFail']
					except DNSException as e:
						_debug(e)

					try:
						task['dns_aaaa'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.AAAA))
						dns_aaaa = True
					except NoNameservers:
						task['dns_aaaa'] = ['!ServFail']
					except DNSException as e:
						_debug(e)

				if nxdomain is False and dns_ns is True:
					try:
						task['dns_mx'] = _answer_to_list(resolve(domain, rdtype=dns.rdatatype.MX))
						dns_mx = True
					except NoNameservers:
						task['dns_mx'] = ['!ServFail']
					except DNSException as e:
						_debug(e)
			else:
				try:
					addrinfo = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
				except socket.gaierror as e:
					if e.errno == -3:
						task['dns_a'] = ['!ServFail']
				except Exception as e:
					_debug(e)
				else:
					for _, _, _, _, sa in addrinfo:
						ip = sa[0]
						if '.' in ip:
							if 'dns_a' not in task:
								task['dns_a'] = set()
								dns_a = True
							task['dns_a'].add(ip)
						if ':' in ip:
							if 'dns_aaaa' not in task:
								task['dns_aaaa'] = set()
								dns_aaaa = True
							task['dns_aaaa'].add(ip)
					if 'dns_a' in task:
						task['dns_a'] = list(task['dns_a'])
					if 'dns_aaaa' in task:
						task['dns_aaaa'] = list(task['dns_aaaa'])

			if self.option_mxcheck:
				if dns_mx is True:
					if domain != self.url.domain:
						if self._mxcheck(task['dns_mx'][0], self.url.domain, domain):
							task['mx_spy'] = True

			if self.option_geoip:
				if dns_a is True:
					try:
						country = geo.country_by_addr(task['dns_a'][0])
					except Exception as e:
						_debug(e)
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

			if self.option_phash or self.screenshot_dir:
				if dns_a or dns_aaaa:
					try:
						browser.get(self.url.full_uri(domain))
						screenshot = browser.screenshot()
					except Exception as e:
						_debug(e)
					else:
						if self.option_phash:
							phash = pHash(BytesIO(screenshot))
							task['phash'] = self.phash_init - phash
						if self.screenshot_dir:
							filename = os.path.join(self.screenshot_dir, '{:08x}_{}.png'.format(self.id, domain))
							try:
								with open(filename, 'wb') as f:
									f.write(screenshot)
							except Exception as e:
								_debug(e)

			if self.option_lsh:
				if dns_a is True or dns_aaaa is True:
					try:
						r = UrlOpener(self.url.full_uri(domain),
							timeout=REQUEST_TIMEOUT_HTTP,
							headers={'user-agent': self.useragent},
							verify=False)
					except Exception as e:
						_debug(e)
					else:
						if r.url.split('?')[0] != self.lsh_effective_url:
							if self.option_lsh == 'ssdeep':
								lsh_curr = ssdeep.hash(r.normalized_content)
								if lsh_curr not in (None, '3::'):
									task['ssdeep'] = ssdeep.compare(self.lsh_init, lsh_curr)
							elif self.option_lsh == 'tlsh':
								lsh_curr = tlsh.hash(r.normalized_content)
								if lsh_curr not in (None, '', 'TNULL'):
									task['tlsh'] = int(100 - (min(tlsh.diff(self.lsh_init, lsh_curr), 300)/3))

			self.jobs.task_done()


class Format():
	def __init__(self, domains=[]):
		self.domains = domains

	def json(self, indent=4, sort_keys=True):
		return json.dumps(self.domains, indent=indent, sort_keys=sort_keys)

	def csv(self):
		cols = ['fuzzer', 'domain']
		for domain in self.domains:
			for k in domain.keys() - cols:
				cols.append(k)
		cols = cols[:2] + sorted(cols[2:])
		csv = [','.join(cols)]
		for domain in self.domains:
			row = []
			for val in [domain.get(c, '') for c in cols]:
				if isinstance(val, str):
					if ',' in val:
						row.append('"{}"'.format(val))
					else:
						row.append(val)
				elif isinstance(val, list):
					row.append(';'.join(val))
				elif isinstance(val, int):
					row.append(str(val))
			csv.append(','.join(row))
		return '\n'.join(csv)

	def list(self):
		return '\n'.join([x.get('domain') for x in sorted(self.domains)])

	def cli(self):
		cli = []
		domains = list(self.domains)
		if sys.stdout.encoding.lower() == 'utf-8':
			for domain in domains:
				domain.update(domain=idna.decode(domain.get('domain')))
		wfuz = max([len(x.get('fuzzer', '')) for x in domains]) + 1
		wdom = max([len(x.get('domain', '')) for x in domains]) + 1
		kv = lambda k, v: FG_YEL + k + FG_CYA + v + FG_RST if k else FG_CYA + v + FG_RST
		for domain in domains:
			inf = []
			if 'dns_a' in domain:
				inf.append(';'.join(domain['dns_a']) + (kv('/', domain['geoip'].replace(' ', '')) if 'geoip' in domain else ''))
			if 'dns_aaaa' in domain:
				inf.append(';'.join(domain['dns_aaaa']))
			if 'dns_ns' in domain:
				inf.append(kv('NS:', ';'.join(domain['dns_ns'])))
			if 'dns_mx' in domain:
				inf.append(kv('SPYING-MX:' if domain.get('mx_spy') else 'MX:', ';'.join(domain['dns_mx'])))
			if 'banner_http' in domain:
				inf.append(kv('HTTP:', domain['banner_http']))
			if 'banner_smtp' in domain:
				inf.append(kv('SMTP:', domain['banner_smtp']))
			if 'whois_registrar' in domain:
				inf.append(kv('REGISTRAR:', domain['whois_registrar']))
			if 'whois_created' in domain:
				inf.append(kv('CREATED:', domain['whois_created']))
			if domain.get('ssdeep', 0) > 0:
				inf.append(kv('SSDEEP:', '{}%'.format(domain['ssdeep'])))
			if domain.get('tlsh', 0) > 0:
				inf.append(kv('TLSH:', '{}%'.format(domain['tlsh'])))
			if domain.get('phash', 0) > 0:
				inf.append(kv('PHASH:', '{}%'.format(domain['phash'])))
			cli.append('{}{[fuzzer]:<{}}{} {[domain]:<{}} {}'.format(FG_BLU, domain, wfuz, FG_RST, domain, wdom, ' '.join(inf or ['-'])))
		return '\n'.join(cli)


def cleaner(func):
	def wrapper(*args, **kwargs):
		result = func(*args, **kwargs)
		if threading.current_thread() is threading.main_thread():
			for sig in (signal.SIGINT, signal.SIGTERM):
				signal.signal(sig, signal.default_int_handler)
		sys.argv = sys.argv[0:1]
		return result
	return wrapper


@cleaner
def run(**kwargs):
	parser = argparse.ArgumentParser(
		usage='%s [OPTION]... DOMAIN' % sys.argv[0],
		add_help=False,
		description=
		'''Domain name permutation engine for detecting homograph phishing attacks, '''
		'''typosquatting, fraud and brand impersonation.''',
		formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=30)
		)

	parser.add_argument('domain', help='Domain name or URL to scan')
	parser.add_argument('-a', '--all', action='store_true', help='Print all DNS records instead of the first ones')
	parser.add_argument('-b', '--banners', action='store_true', help='Determine HTTP and SMTP service banners')
	parser.add_argument('-d', '--dictionary', type=str, metavar='FILE', help='Generate more domains using dictionary FILE')
	parser.add_argument('-f', '--format', type=str, default='cli', help='Output format: cli, csv, json, list (default: cli)')
	parser.add_argument('--fuzzers', type=str, metavar='LIST', help='Use only selected fuzzing algorithms (separated with commas)')
	parser.add_argument('-g', '--geoip', action='store_true', help='Lookup for GeoIP location')
	parser.add_argument('--lsh', metavar='LSH', nargs='?', const='ssdeep', choices=['ssdeep', 'tlsh'],
		help='Evaluate web page similarity with LSH algorithm: ssdeep, tlsh (default: ssdeep)')
	parser.add_argument('--lsh-url', metavar='URL', help='Override URL to fetch the original web page from')
	parser.add_argument('-m', '--mxcheck', action='store_true', help='Check if MX host can be used to intercept emails')
	parser.add_argument('-o', '--output', type=str, metavar='FILE', help='Save output to FILE')
	parser.add_argument('-r', '--registered', action='store_true', help='Show only registered domain names')
	parser.add_argument('-u', '--unregistered', action='store_true', help='Show only unregistered domain names')
	parser.add_argument('-p', '--phash', action='store_true', help='Render web pages and evaluate visual similarity')
	parser.add_argument('--phash-url', metavar='URL', help='Override URL to render the original web page from')
	parser.add_argument('--screenshots', metavar='DIR', help='Save web page screenshots into DIR')
	parser.add_argument('-s', '--ssdeep', action='store_true', help=argparse.SUPPRESS)
	parser.add_argument('--ssdeep-url', help=argparse.SUPPRESS)
	parser.add_argument('-t', '--threads', type=int, metavar='NUM', default=THREAD_COUNT_DEFAULT,
		help='Start specified NUM of threads (default: %s)' % THREAD_COUNT_DEFAULT)
	parser.add_argument('-w', '--whois', action='store_true', help='Lookup WHOIS database for creation date and registrar')
	parser.add_argument('--tld', type=str, metavar='FILE', help='Swap TLD for the original domain from FILE')
	parser.add_argument('--nameservers', type=str, metavar='LIST', help='DNS or DoH servers to query (separated with commas)')
	parser.add_argument('--useragent', type=str, metavar='STRING', default=USER_AGENT_STRING,
		help='Set User-Agent STRING (default: %s)' % USER_AGENT_STRING)
	parser.add_argument('--version', action='version', version='dnstwist {}'.format(__version__), help=argparse.SUPPRESS)

	if kwargs:
		sys.argv = ['']
		for k, v in kwargs.items():
			if k in ('domain',):
				sys.argv.append(v)
			else:
				if v is not False:
					sys.argv.append('--' + k.replace('_', '-'))
				if not isinstance(v, bool):
					sys.argv.append(str(v))
		def _parser_error(msg):
			raise Exception(msg) from None
		parser.error = _parser_error

	if not sys.argv[1:] or '-h' in sys.argv or '--help' in sys.argv:
		print('{}dnstwist {} by <{}>{}\n'.format(ST_BRI, __version__, __email__, ST_RST))
		parser.print_help()
		return

	args = parser.parse_args()

	threads = []
	jobs = queue.Queue()

	def p_cli(text):
		if args.format == 'cli' and sys.stdout.isatty(): print(text, end='', flush=True)
	def p_err(text):
		print(str(text), file=sys.stderr, flush=True)

	def signal_handler(signal, frame):
		if threads:
			print('\nstopping threads... ', file=sys.stderr, flush=True)
			jobs.queue.clear()
			for worker in threads:
				worker.stop()
			threads.clear()
		sys.tracebacklimit = 0
		raise KeyboardInterrupt

	if args.registered and args.unregistered:
		parser.error('arguments --registered and --unregistered are mutually exclusive')

	if args.ssdeep:
		p_err('WARNING: argument --ssdeep is deprecated, use --lsh ssdeep instead')
		args.lsh = 'ssdeep'
	if args.ssdeep_url:
		p_err('WARNING: argument --ssdeep-url is deprecated, use --lsh-url instead')
		args.lsh_url = args.ssdeep_url

	if not args.lsh and args.lsh_url:
		parser.error('argument --lsh-url requires --lsh')

	if not args.phash:
		if args.phash_url:
			parser.error('argument --phash-url requires --phash')
		if args.screenshots:
			parser.error('argument --screenshots requires --phash')

	if not kwargs and args.format not in ('cli', 'csv', 'json', 'list'):
		parser.error('invalid output format (choose from cli, csv, json, list)')

	if args.threads < 1:
		parser.error('number of threads must be greater than zero')

	fuzzers = []
	if args.fuzzers:
		fuzzers = [x.strip().lower() for x in set(args.fuzzers.split(','))]
		if args.dictionary and 'dictionary' not in fuzzers:
			parser.error('argument --dictionary cannot be used with selected fuzzing algorithms (consider enabling fuzzer: dictionary)')
		if args.tld and 'tld-swap' not in fuzzers:
			parser.error('argument --tld cannot be used with selected fuzzing algorithms (consider enabling fuzzer: tld-swap)')
		# important: this should enable all available fuzzers
		with Fuzzer('example.domain', ['foo'], ['bar']) as fuzz:
			fuzz.generate()
			all_fuzzers = sorted({x.get('fuzzer') for x in fuzz.permutations()})
			if not set(fuzzers).issubset(all_fuzzers):
				parser.error('argument --fuzzers takes a comma-separated list with at least one of the following: {}'.format(' '.join(all_fuzzers)))
			del all_fuzzers

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
		re_subd = re.compile(r'^(?:(?:xn--)[a-z0-9-]{3,59}|[a-z0-9-]{1,63})$')
		try:
			with open(args.dictionary, encoding='utf-8') as f:
				dictionary = [x for x in set(f.read().lower().splitlines()) if re_subd.match(x)]
		except UnicodeDecodeError:
			parser.error('UTF-8 decode error when reading: {}'.format(args.dictionary))
		except OSError as err:
			parser.error('unable to open {} ({})'.format(args.dictionary, err.strerror.lower()))

	tld = []
	if args.tld:
		re_tld = re.compile(r'^[a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})?$')
		try:
			with open(args.tld, encoding='utf-8') as f:
				tld = [x for x in set(f.read().lower().splitlines()) if re_tld.match(x)]
		except UnicodeDecodeError:
			parser.error('UTF-8 decode error when reading: {}'.format(args.tld))
		except OSError as err:
			parser.error('unable to open {} ({})'.format(args.tld, err.strerror.lower()))

	if args.output:
		sys._stdout = sys.stdout
		try:
			sys.stdout = open(args.output, 'w' if args.output == os.devnull else 'x')
		except OSError as err:
			parser.error('unable to open {} ({})'.format(args.output, err.strerror.lower()))


	lsh_url = None
	if args.lsh:
		if args.lsh == 'ssdeep' and not MODULE_SSDEEP:
			parser.error('missing ssdeep library')
		if args.lsh == 'tlsh' and not MODULE_TLSH:
			parser.error('missing py-tlsh library')
		if args.lsh_url:
			try:
				lsh_url = UrlParser(args.lsh_url)
			except ValueError:
				parser.error('invalid domain name: ' + args.lsh_url)

	phash_url = None
	if args.phash or args.screenshots:
		if not MODULE_PIL:
			parser.error('missing Python Imaging Library (PIL)')
		if not MODULE_SELENIUM:
			parser.error('missing Selenium Webdriver')
		try:
			_ = HeadlessBrowser()
		except Exception as e:
			parser.error(str(e))
		if args.screenshots:
			if not os.access(args.screenshots, os.W_OK | os.X_OK):
				parser.error('insufficient access permissions: %s' % args.screenshots)
		if args.phash_url:
			try:
				phash_url = UrlParser(args.phash_url)
			except ValueError:
				parser.error('invalid domain name: ' + args.phash_url)

	if args.geoip:
		if not MODULE_GEOIP:
			parser.error('missing geoip2 library or database file (check $GEOLITE2_MMDB environment variable)')

	try:
		url = UrlParser(args.domain)
	except Exception:
		parser.error('invalid domain name: ' + args.domain)

	if threading.current_thread() is threading.main_thread():
		for sig in (signal.SIGINT, signal.SIGTERM):
			signal.signal(sig, signal_handler)

	fuzz = Fuzzer(url.domain, dictionary=dictionary, tld_dictionary=tld)
	fuzz.generate(fuzzers=fuzzers)
	domains = fuzz.domains

	if not domains:
		parser.error('selected fuzzing algorithms do not generate any permutations for provided input domain')

	if args.format == 'list':
		print(Format(domains).list())
		if hasattr(sys, '_stdout'):
			sys.stdout = sys._stdout
		return list(map(dict, domains)) if kwargs else None

	if not MODULE_DNSPYTHON:
		p_err('WARNING: DNS features are limited due to lack of DNSPython library')

	p_cli(FG_RND + ST_BRI +
r'''     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}

''' % __version__ + FG_RST + ST_RST)

	if args.lsh or args.phash:
		proxies = urllib.request.getproxies()
		if proxies:
			p_cli('using proxy: {}\n'.format(' '.join(set(proxies.values()))))

	lsh_init = str()
	lsh_effective_url = str()
	if args.lsh:
		request_url = lsh_url.full_uri() if lsh_url else url.full_uri()
		p_cli('fetching content from: {} '.format(request_url))
		try:
			r = UrlOpener(request_url,
				timeout=REQUEST_TIMEOUT_HTTP,
				headers={'User-Agent': args.useragent},
				verify=True)
		except Exception as e:
			if kwargs:
				raise
			p_err(e)
			sys.exit(1)
		else:
			p_cli('> {} [{:.1f} KB]\n'.format(r.url.split('?')[0], len(r.content)/1024))
			if args.lsh == 'ssdeep':
				lsh_init = ssdeep.hash(r.normalized_content)
			elif args.lsh == 'tlsh':
				lsh_init = tlsh.hash(r.normalized_content)
			lsh_effective_url = r.url.split('?')[0]
			# hash blank if content too short or insufficient entropy
			if lsh_init in (None, '', 'TNULL', '3::'):
				args.lsh = None

	if args.phash:
		request_url = phash_url.full_uri() if phash_url else url.full_uri()
		p_cli('rendering web page: {}\n'.format(request_url))
		browser = HeadlessBrowser(useragent=args.useragent)
		try:
			browser.get(request_url)
			screenshot = browser.screenshot()
		except Exception as e:
			if kwargs:
				raise
			p_err(e)
			sys.exit(1)
		else:
			phash = pHash(BytesIO(screenshot))
			browser.stop()

	for task in domains:
		jobs.put(task)

	sid = int.from_bytes(os.urandom(4), sys.byteorder)
	for _ in range(args.threads):
		worker = Scanner(jobs)
		worker.id = sid
		worker.url = url
		worker.option_extdns = MODULE_DNSPYTHON
		if args.geoip:
			worker.option_geoip = True
		if args.banners:
			worker.option_banners = True
		if args.lsh and lsh_init:
			worker.option_lsh = args.lsh
			worker.lsh_init = lsh_init
			worker.lsh_effective_url = lsh_effective_url
		if args.phash:
			worker.option_phash = True
			worker.phash_init = phash
			worker.screenshot_dir = args.screenshots
		if args.mxcheck:
			worker.option_mxcheck = True
		if args.nameservers:
			worker.nameservers = nameservers
		worker.useragent = args.useragent
		worker.start()
		threads.append(worker)

	p_cli('started {} scanner threads\n'.format(args.threads))

	ttime = 0
	ival = 0.2
	while True:
		time.sleep(ival)
		ttime += ival
		dlen = len(domains)
		comp = dlen - jobs.qsize()
		if not comp:
			continue
		rate = int(comp / ttime) + 1
		eta = jobs.qsize() // rate
		found = sum([1 for x in domains if x.is_registered()])
		p_cli(ST_CLR + '\rpermutations: {:.2%} of {} | found: {} | eta: {:d}m {:02d}s | speed: {:d} qps'.format(comp/dlen,
			dlen, found, eta//60, eta%60, rate))
		if jobs.empty():
			break
		if sum([1 for x in threads if x.is_alive()]) == 0:
			break
	p_cli('\n')

	for worker in threads:
		worker.stop()
	for worker in threads:
		worker.join()

	domains = fuzz.permutations(registered=args.registered, unregistered=args.unregistered, dns_all=args.all)

	if args.whois:
		total = sum([1 for x in domains if x.is_registered()])
		whois = Whois()
		for i, domain in enumerate([x for x in domains if x.is_registered()]):
			p_cli(ST_CLR + '\rWHOIS: {} ({:.2%})'.format(domain['domain'], (i+1)/total))
			try:
				wreply = whois.whois('.'.join(domain_tld(domain['domain'])[1:]))
			except Exception as e:
				_debug(e)
			else:
				if wreply.get('creation_date'):
					domain['whois_created'] = wreply.get('creation_date').strftime('%Y-%m-%d')
				if wreply.get('registrar'):
					domain['whois_registrar'] = wreply.get('registrar')
		p_cli('\n')

	p_cli('\n')

	if domains:
		if args.format == 'csv':
			print(Format(domains).csv())
		elif args.format == 'json':
			print(Format(domains).json())
		elif args.format == 'cli':
			print(Format(domains).cli())

	if hasattr(sys, '_stdout'):
		sys.stdout = sys._stdout

	if kwargs:
		return list(map(dict, domains))


if __name__ == '__main__':
	try:
		run()
	except BrokenPipeError:
		pass
