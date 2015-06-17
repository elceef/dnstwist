#!/usr/bin/env python
#
# dnstwist by marcin@ulikowski.pl
# Generate and resolve domain variations to detect typo squatting, phishing and corporate espionage.
#
#
# dnstwist is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# dnstwist is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with dnstwist.  If not, see <http://www.gnu.org/licenses/>.

__author__ = 'Marcin Ulikowski'
__version__ = '20150617'
__email__ = 'marcin@ulikowski.pl'

import sys
import socket
import signal
try:
	import dns.resolver
	module_dnspython = True
except:
	module_dnspython = False
	pass
try:
	import GeoIP
	module_geoip = True
except:
	module_geoip = False
	pass

def sigint_handler(signal, frame):
	print('You pressed Ctrl+C!')
	sys.exit(0)

def bitsquatting(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	masks = [1, 2, 4, 8, 16, 32, 64, 128]
	for i in range(0, len(dom)):
		c = dom[i]
		for j in range(0, len(masks)):
			b = chr(ord(c) ^ masks[j])
			o = ord(b)
			if (o >= 48 and o <= 57) or (o >= 97 and o <= 122):
				out.append(dom[:i] + b + dom[i+1:] + '.' + tld)
	return out

def homoglyph(domain):
	glyphs = { 'd':['b', 'cl'], 'm':['n', 'rn'], 'l':['1', 'i'], 'o':['0'], 'w':['vv'], 'n':['m'], 'b':['d'], 'i':['l'] }
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	for ws in range(0, len(dom)):
		for i in range(0, len(dom)-ws):
			win = dom[i:i+ws]
			j = 0
			while j < ws:
				c = win[j]
				if c in glyphs:
					for g in range(0, len(glyphs[c])):
						win = win[:j] + glyphs[c][g] + win[j+1:]
						if len(glyphs[c][g]) > 1:
							j += len(glyphs[c][g]) - 1
						out.append(dom[:i] + win + dom[i+ws:] + '.' + tld)
				j += 1
	return list(set(out))

def repetition(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	for i in range(0, len(dom)):
		if dom[i].isalpha():
			out.append(dom[:i] + dom[i] + dom[i] + dom[i+1:] + '.' + tld)
	return out

def transposition(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	for i in range(0, len(dom)-1):
		out.append(dom[:i] + dom[i+1] + dom[i] + dom[i+2:] + '.' + tld)
	return out

def replacement(domain):
	keys = {
	'1':'2q', '2':'3wq1', '3':'4ew2', '4':'5re3', '5':'6tr4', '6':'7yt5', '7':'8uy6', '8':'9iu7', '9':'0oi8', '0':'po9',
	'q':'12wa', 'w':'3esaq2', 'e':'4rdsw3', 'r':'5tfde4', 't':'6ygfr5', 'y':'7uhgt6', 'u':'8ijhy7', 'i':'9okju8', 'o':'0plki9', 'p':'lo0',
	'a':'qwsz', 's':'edxzaw', 'd':'rfcxse', 'f':'tgvcdr', 'g':'yhbvft', 'h':'ujnbgy', 'j':'ikmnhu', 'k':'olmji', 'l':'kop',
	'z':'asx', 'x':'zsdc', 'c':'xdfv', 'v':'cfgb', 'b':'vghn', 'n':'bhjm', 'm':'njk'
	}
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	for i in range(0, len(dom)):
		if dom[i] in keys:
			for c in range(0, len(keys[dom[i]])):
				out.append(dom[:i] + keys[dom[i]][c] + dom[i+1:] + '.' + tld)
	return out


def omission(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	for i in range(0, len(dom)):
		out.append(dom[:i] + dom[i+1:] + '.' + tld)
	return out

def insertion(domain):
	keys = {
	'1':'2q', '2':'3wq1', '3':'4ew2', '4':'5re3', '5':'6tr4', '6':'7yt5', '7':'8uy6', '8':'9iu7', '9':'0oi8', '0':'po9',
	'q':'12wa', 'w':'3esaq2', 'e':'4rdsw3', 'r':'5tfde4', 't':'6ygfr5', 'y':'7uhgt6', 'u':'8ijhy7', 'i':'9okju8', 'o':'0plki9', 'p':'lo0',
	'a':'qwsz', 's':'edxzaw', 'd':'rfcxse', 'f':'tgvcdr', 'g':'yhbvft', 'h':'ujnbgy', 'j':'ikmnhu', 'k':'olmji', 'l':'kop',
	'z':'asx', 'x':'zsdc', 'c':'xdfv', 'v':'cfgb', 'b':'vghn', 'n':'bhjm', 'm':'njk'
	}
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(1, len(dom)-1):
		if dom[i] in keys:
			for c in range(0, len(keys[dom[i]])):
				out.append(dom[:i] + keys[dom[i]][c] + dom[i] + dom[i+1:] + '.' + tld)
				out.append(dom[:i] + dom[i] + keys[dom[i]][c] + dom[i+1:] + '.' + tld)
	return out

def fuzz_domain(domain):
	domains = []

	for i in bitsquatting(sys.argv[1]):
		domains.append({ 'type':'Bitsquatting', 'domain':i })
	for i in homoglyph(sys.argv[1]):
		domains.append({ 'type':'Homoglyph', 'domain':i })
	for i in repetition(sys.argv[1]):
		domains.append({ 'type':'Repetition', 'domain':i })
	for i in transposition(sys.argv[1]):
		domains.append({ 'type':'Transposition', 'domain':i})
	for i in replacement(sys.argv[1]):
		domains.append({ 'type':'Replacement', 'domain':i })
	for i in omission(sys.argv[1]):
		domains.append({'type':'Omission', 'domain':i })
	for i in insertion(sys.argv[1]):
		domains.append({'type':'Insertion', 'domain':i })

	return domains

def main():
	if len(sys.argv) == 3:
		output_csv = True
	else:
		output_csv = False

	if not output_csv:
		print('dnstwist (' + __version__ + ') by ' + __email__)

		if len(sys.argv) < 2:
			print('Usage: ' + sys.argv[0] + ' example.com [csv]')
			sys.exit()

	domains = fuzz_domain(sys.argv[1])

	if not module_dnspython:
		sys.stderr.write('NOTICE: missing dnspython module - DNS functionality is limited !\n')
		sys.stderr.flush()

	if not module_geoip:
		sys.stderr.write('NOTICE: missing GeoIP module - geographical location not available !\n')
		sys.stderr.flush()

	if not output_csv:
		sys.stdout.write('Processing ' + str(len(domains)) + ' domains ')
		sys.stdout.flush()

	signal.signal(signal.SIGINT, sigint_handler)

	for i in range(0, len(domains)):
		try:
			ip = socket.getaddrinfo(domains[i]['domain'], 80)
		except:
			pass
		else:
			for j in ip:
				if '.' in j[4][0]:
					domains[i]['a'] = j[4][0]
					break
			for j in ip:
				if ':' in j[4][0]:
					domains[i]['aaaa'] = j[4][0]
					break

		if module_dnspython:
			try:
				ns = dns.resolver.query(domains[i]['domain'], 'NS')
				domains[i]['ns'] = str(ns[0])[:-1]
			except:
				pass

			if 'ns' in domains[i]:
				try:
					mx = dns.resolver.query(domains[i]['domain'], 'MX')
					domains[i]['mx'] = str(mx[0].exchange)[:-1]
				except:
					pass

		if module_geoip:
			gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
			try:
				country = gi.country_name_by_addr(domains[i]['a'])
			except:
				pass
			else:
				if country:
					domains[i]['country'] = country

		if not output_csv:
			if 'a' in domains[i] or 'ns' in domains[i]:
				sys.stdout.write('!')
				sys.stdout.flush()
			else:
				sys.stdout.write('.')
				sys.stdout.flush()

	if not output_csv:
		sys.stdout.write('\n\n')

	for i in domains:
		if not output_csv:
			zone = ''

			if 'a' in i:
				zone += i['a']
				if 'country' in i:
					zone += '/' + i['country']
			elif 'ns' in i:
				zone += 'NS:' + i['ns']
			if 'aaaa' in i:
				zone += ' ' + i['aaaa']
			if 'mx' in i:
				zone += ' MX:' + i['mx']
			if not zone:
				zone = '-'

			sys.stdout.write('%-15s %-15s %s\n' % (i['type'], i['domain'], zone))
			sys.stdout.flush()
		else:
			print(i.get('type') + ',' + i.get('domain') + ',' + i.get('a', '') + ',' + i.get('aaaa', '') + ',' + i.get('mx', '') + ',' + i.get('ns', '') + ',' + i.get('country', ''))

	return 0

if __name__ == '__main__':
	main()
