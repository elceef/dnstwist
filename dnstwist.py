#!/usr/bin/env python
"""
dnstwist by marcin@ulikowski.pl

Generate and resolve domain variations to detect typo squatting,
phishing and corporate espionage.

"""

__version__ = '20150610'


import sys
import socket
import signal


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
	glyphs = { 'd':'b', 'n':'m', 'o':'0', 'l':'1', 'l':'i', 'm':'rn', 'd':'cl', 'w':'vv' }
	glyphs_inv = {v: k for k, v in glyphs.items()}
	homoglyphs = dict(glyphs.items() + glyphs_inv.items())
	out = []
	dom = domain.rsplit('.', 1)[0]
	tld = domain.rsplit('.', 1)[1]
	for i in range(0, len(dom)):
		c = dom[i]
		for j, k in homoglyphs.iteritems():
			n = c.replace(j, k)
			if (c != n):
				out.append(dom[:i] + n + dom[i+1:] + '.' + tld)
	return out


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


print 'dnstwist (' + __version__ + ') by marcin@ulikowski.pl'
if len(sys.argv) < 2:
	print 'Usage: ' + sys.argv[0] + ' <domain>'
	sys.exit()

domains = []

for i in bitsquatting(sys.argv[1]):
	domains.append({'type':'Bitsquatting', 'domain':i, 'ipaddr':'-'})
for i in homoglyph(sys.argv[1]):
	domains.append({'type':'Homoglyph', 'domain':i, 'ipaddr':'-'})
for i in repetition(sys.argv[1]):
	domains.append({'type':'Repetition', 'domain':i, 'ipaddr':'-'})
for i in replacement(sys.argv[1]):
	domains.append({'type':'Replacement', 'domain':i, 'ipaddr':'-'})
for i in omission(sys.argv[1]):
	domains.append({'type':'Omission', 'domain':i, 'ipaddr':'-'})
for i in insertion(sys.argv[1]):
	domains.append({'type':'Insertion', 'domain':i, 'ipaddr':'-'})

sys.stdout.write('Processing ' + str(len(domains)) + ' domains ')
sys.stdout.flush()

signal.signal(signal.SIGINT, sigint_handler)

for i in range(0, len(domains)):
	try:
		domains[i]['ipaddr'] = socket.gethostbyname(domains[i]['domain'])
	except:
		sys.stdout.write('.')
		sys.stdout.flush()
		pass
	else:
		sys.stdout.write('!')
		sys.stdout.flush()

sys.stdout.write('\n\n')

for d in domains:
	print "%-20s %-20s %-20s" % (d['type'], d['domain'], d['ipaddr'])
