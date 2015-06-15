#!/usr/bin/env python
"""
dnstwist by marcin@ulikowski.pl

Generate and resolve domain variations to detect typo squatting, phishing and corporate espionage.

"""

__author__ = 'Marcin Ulikowski'
__version__ = '20150615'
__email__ = 'marcin@ulikowski.pl'


import sys
import socket
import signal
import pygeoip


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
			if (b.isalpha() and b.lower() == b):
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
							j += 1
							#print len(glyphs[c][g])
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


def replacement(domain):
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	for i in range(0, len(dom)-1):
		out.append(dom[:i] + dom[i+1] + dom[i] + dom[i+2:] + '.' + tld)
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


print('dnstwist (' + __version__ + ') by marcin@ulikowski.pl')
if len(sys.argv) < 2:
	print('Usage: ' + sys.argv[0] + ' <domain>')
	sys.exit()

domains = []

for i in bitsquatting(sys.argv[1]):
	domains.append({'type':'Bitsquatting', 'domain':i, 'ipaddr':'-', 'country':'-'})
for i in homoglyph(sys.argv[1]):
	domains.append({'type':'Homoglyph', 'domain':i, 'ipaddr':'-','country':'-'})
for i in repetition(sys.argv[1]):
	domains.append({'type':'Repetition', 'domain':i, 'ipaddr':'-', 'country':'-'})
for i in replacement(sys.argv[1]):
	domains.append({'type':'Replacement', 'domain':i, 'ipaddr':'-', 'country':'-'})
for i in omission(sys.argv[1]):
	domains.append({'type':'Omission', 'domain':i, 'ipaddr':'-', 'country':'-'})
for i in insertion(sys.argv[1]):
	domains.append({'type':'Insertion', 'domain':i, 'ipaddr':'-', 'country':'-'})

sys.stdout.write('Processing ' + str(len(domains)) + ' domains ')
sys.stdout.flush()

signal.signal(signal.SIGINT, sigint_handler)

geoips = pygeoip.GeoIP('GeoIP.dat')

for i in range(0, len(domains)):
	try:
		ipaddr = socket.gethostbyname(domains[i]['domain'])
		domains[i]['ipaddr'] = ipaddr
		domains[i]['country'] = geoips.country_name_by_addr(ipaddr)
	except:
		sys.stdout.write('.')
		sys.stdout.flush()
		pass
	else:
		sys.stdout.write('!')
		sys.stdout.flush()

sys.stdout.write('\n\n')

for d in domains:
	print("%-20s %-20s %-20s %-20s" % (d['type'], d['domain'], d['ipaddr'], d['country']))
