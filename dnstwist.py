#!/usr/bin/env python
#
# dnstwist by marcin@ulikowski.pl
# Generate and resolve domain variations to detect typo squatting,
# phishing and corporate espionage.
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
__version__ = '20150726'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket
import signal
import argparse
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
try:
	import whois
	module_whois = True
except:
	module_whois = False
	pass

def sigint_handler(signal, frame):
	sys.exit(0)

# Internationalized domains not supported
def validate_domain(domain):
	if len(domain) > 255:
		return False
	if domain[-1] == '.':
		domain = domain[:-1]
	allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
	return allowed.match(domain)

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
			if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
				out.append(dom[:i] + b + dom[i+1:] + '.' + tld)

	return out

def homoglyph(domain):
	glyphs = {
	'd':['b', 'cl'], 'm':['n', 'rn'], 'l':['1', 'i'], 'o':['0'],
	'w':['vv'], 'n':['m'], 'b':['d'], 'i':['l'], 'g':['q'], 'q':['g']
	}
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for ws in range(0, len(dom)):
		for i in range(0, (len(dom)-ws)+1):
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
		if dom[i+1] != dom[i]:
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

def hyphenation(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(1, len(dom)):
		if dom[i] not in ['-', '.'] and dom[i-1] not in ['-', '.']:
			out.append(dom[:i] + '-' + dom[i:] + '.' + tld)

	return out

def dotification(domain):
        out = []
        dom = domain.rsplit('.', 1)[0]
        tld = domain.rsplit('.', 1)[1]

        for i in range(1, len(dom)):
                if dom[i] != '.' and dom[i-1] != '.':
                        out.append(dom[:i] + '.' + dom[i:] + '.' + tld)

        return out

def subdomain(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]

	for i in range(1, len(dom)-4):
		if dom[i] != '.' and dom[i-1] != '.':
			out.append(dom[:i] + '.' + dom[i:] + '.' + tld)

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

	for i in bitsquatting(domain):
		domains.append({ 'type':'Bitsquatting', 'domain':i })
	for i in homoglyph(domain):
		domains.append({ 'type':'Homoglyph', 'domain':i })
	for i in repetition(domain):
		domains.append({ 'type':'Repetition', 'domain':i })
	for i in transposition(domain):
		domains.append({ 'type':'Transposition', 'domain':i })
	for i in replacement(domain):
		domains.append({ 'type':'Replacement', 'domain':i })
	for i in omission(domain):
		domains.append({ 'type':'Omission', 'domain':i })
	for i in hyphenation(domain):
		domains.append({ 'type':'Hyphenation', 'domain':i })
	for i in dotification(domain):
                domains.append({ 'type':'Dotification', 'domain':i })
	for i in insertion(domain):
		domains.append({ 'type':'Insertion', 'domain':i })
	for i in subdomain(domain):
		domains.append({ 'type':'Subdomain', 'domain':i })

	return domains

def main():
	parser = argparse.ArgumentParser(
	description='''Find similar-looking domains that adversaries can use to attack you.  
	Can detect fraud, phishing attacks and corporate espionage. Useful as an additional 
	source of targeted threat intelligence.''',
	epilog='''Questions? Complaints? You can reach the author at <marcin@ulikowski.pl>'''
	)

	parser.add_argument('domain', help='domain name to check (e.g., ulikowski.pl)')
	parser.add_argument('-c', '--csv', action='store_true', help='print output in CSV format')
	parser.add_argument('-r', '--registered', action='store_true', help='show only registered domain names')
	parser.add_argument('-w', '--whois', action='store_true', help='perform WHOIS lookup for creation/modification date (slow)')

	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(0)

	args = parser.parse_args()

	if not args.csv:
		sys.stdout.write('dnstwist (' + __version__ + ') by ' + __email__ + '\n\n')
	
	if not validate_domain(args.domain):
		sys.stderr.write('ERROR: invalid domain name!\n')
		sys.exit(-1)

	domains = fuzz_domain(args.domain.lower())

	if not module_dnspython:
		sys.stderr.write('NOTICE: missing dnspython module - DNS functionality is limited!\n')
		sys.stderr.flush()

	if not module_geoip:
		sys.stderr.write('NOTICE: missing GeoIP module - geographical location not available!\n')
		sys.stderr.flush()

	if not module_whois and args.whois:
		sys.stderr.write('NOTICE: missing whois module - WHOIS database not available!\n')
		sys.stderr.flush()

	if module_whois and args.whois and not args.csv:
		sys.stderr.write('Be advised: some WHOIS servers limit the number of queries and a longer fun with this tool may end up with a temporary ban to the service.\n\n')
		sys.stderr.flush()

	if not args.csv:
		sys.stdout.write('Processing ' + str(len(domains)) + ' domains ')
		sys.stdout.flush()

	signal.signal(signal.SIGINT, sigint_handler)

	total_hits = 0

	for i in range(0, len(domains)):
		if module_dnspython:
			resolv = dns.resolver.Resolver()
			resolv.lifetime = 1
			resolv.timeout = 1

			try:
				ns = resolv.query(domains[i]['domain'], 'NS')
				domains[i]['ns'] = str(ns[0])[:-1]
			except:
				pass

			if 'ns' in domains[i]:
				try:
					ns = resolv.query(domains[i]['domain'], 'A')
					domains[i]['a'] = str(ns[0])
				except:
					pass
	
				try:
					ns = resolv.query(domains[i]['domain'], 'AAAA')
					domains[i]['aaaa'] = str(ns[0])
				except:
					pass

				try:
					mx = resolv.query(domains[i]['domain'], 'MX')
					domains[i]['mx'] = str(mx[0].exchange)[:-1]
				except:
					pass
		else:
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

		if module_whois and args.whois:
			if 'ns' in domains[i] or 'a' in domains[i]:
				try:
					whoisdb = whois.query(domains[i]['domain'])
					domains[i]['created'] = str(whoisdb.creation_date).replace(' ', 'T')
					domains[i]['updated'] = str(whoisdb.last_updated).replace(' ', 'T')
				except:
					pass

		if module_geoip:
			if 'a' in domains[i]:
				gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
				try:
					country = gi.country_name_by_addr(domains[i]['a'])
				except:
					pass
				else:
					if country:
						domains[i]['country'] = country

		if not args.csv:
			if 'a' in domains[i] or 'ns' in domains[i]:
				sys.stdout.write('!')
				sys.stdout.flush()
				total_hits += 1
			else:
				sys.stdout.write('.')
				sys.stdout.flush()

	if not args.csv:
		sys.stdout.write(' ' + str(total_hits) + ' hit(s)\n\n')

	for i in domains:
		info = ''

		if 'a' in i:
			info += i['a']
			if 'country' in i:
				info += '/' + i['country']
		elif 'ns' in i:
			info += 'NS:' + i['ns']
		if 'aaaa' in i:
			info += ' ' + i['aaaa']
		if 'mx' in i:
			info += ' MX:' + i['mx']
		if 'created' in i and 'updated' in i and i['created'] == i['updated']:
				info += ' Created/Updated:' + i['created']
		else:
			if 'created' in i:
				info += ' Created:' + i['created']
			if 'updated' in i:
				info += ' Updated:' + i['updated']

		if not info:
			info = '-'

		if (args.registered and info != '-') or not args.registered:
			if not args.csv:
				sys.stdout.write('%-15s %-15s %s\n' % (i['type'], i['domain'], info))
				sys.stdout.flush()
			else:
				print(
				'%s,%s,%s,%s,%s,%s,%s,%s,%s' % (i.get('type'), i.get('domain'), i.get('a', ''),
				i.get('aaaa', ''), i.get('mx', ''), i.get('ns', ''), i.get('country', ''),
				i.get('created', ''), i.get('updated', ''))
				)

	return 0

if __name__ == '__main__':
	main()
