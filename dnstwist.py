#!/usr/bin/env python
#
# dnstwist
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
__version__ = '1.0b'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket
import signal
import time
import argparse
import threading
from random import randint
from os import path

try:
	import queue
except ImportError:
	import Queue as queue

try:
	import dns.resolver
	module_dnspython = True
except ImportError:
	module_dnspython = False
	pass
try:
	import GeoIP
	module_geoip = True
except ImportError:
	module_geoip = False
	pass

geoip_db = path.exists("/usr/share/GeoIP/GeoIP.dat")

try:
	import whois
	module_whois = True
except ImportError:
	module_whois = False
	pass
try:
	import ssdeep
	module_ssdeep = True
except ImportError:
	module_ssdeep = False
try:
	import requests
	module_requests = True
except ImportError:
	module_requests = False
	pass

REQUEST_TIMEOUT_DNS = 5
REQUEST_TIMEOUT_HTTP = 5
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
	FG_RND = ''
	FG_RED = ''
	FG_YEL = ''
	FG_GRE = ''
	FG_MAG = ''
	FG_CYA = ''
	FG_BLU = ''
	FG_RST = ''
	ST_BRI = ''
	ST_RST = ''

def p_out(data):
	global args
	if not args.csv:
		sys.stdout.write(data)
		sys.stdout.flush()

def p_err(data):
	global args
	if not args.csv:
		sys.stderr.write(data)
		sys.stderr.flush()

def p_csv(data):
	global args
	if args.csv:
		sys.stdout.write(data)

def sigint_handler(signal, frame):
	sys.stdout.write(FG_RST + ST_RST)
	sys.stdout.write('\nStopping threads... ')
	sys.stdout.flush()
	for worker in threads:
		worker.stop()
	time.sleep(1)
	sys.stdout.write('Done\n')
	sys.exit(0)

class fuzz_domain():
	def __init__(self, domain):
		if not self.__validate_domain(domain):
			raise Exception('Invalid domain name')
		self.domain, self.tld = self.__parse_domain(domain)
		self.domains = []

	def __validate_domain(self, domain):
		if len(domain) > 255:
			return False
		if domain[-1] == '.':
			domain = domain[:-1]
		allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
		return allowed.match(domain)

	def __parse_domain(self, domain):
		domain = domain.rsplit('.', 2)
	
		if len(domain) == 2:
			return domain
	
		# Source: https://publicsuffix.org/list/effective_tld_names.dat
		# Parsed with the following regexp: ^[a-z]{2,3}\.[a-z]{2}$
	
		ac_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		ad_sld = ['nom']
		ae_sld = ['ac', 'co', 'gov', 'mil', 'net', 'org', 'sch']
		af_sld = ['com', 'edu', 'gov', 'net', 'org']
		ag_sld = ['co', 'com', 'net', 'nom', 'org']
		ai_sld = ['com', 'net', 'off', 'org']
		al_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		an_sld = ['com', 'edu', 'net', 'org']
		ao_sld = ['co', 'ed', 'gv', 'it', 'og', 'pb']
		ar_sld = ['com', 'edu', 'gob', 'gov', 'int', 'mil', 'net', 'org', 'tur']
		as_sld = ['gov']
		at_sld = ['ac', 'biz', 'co', 'gv', 'or']
		au_sld = ['act', 'asn', 'com', 'edu', 'gov', 'id', 'net', 'nsw', 'nt', 'org', 'oz', 'qld', 'sa', 'tas', 'vic', 'wa']
		aw_sld = ['com']
		az_sld = ['biz', 'com', 'edu', 'gov', 'int', 'mil', 'net', 'org', 'pp', 'pro']
		ba_sld = ['co', 'com', 'edu', 'gov', 'mil', 'net', 'org', 'rs']
		bb_sld = ['biz', 'co', 'com', 'edu', 'gov', 'net', 'org', 'tv']
		be_sld = ['ac']
		bf_sld = ['gov']
		bh_sld = ['com', 'edu', 'gov', 'net', 'org']
		bi_sld = ['co', 'com', 'edu', 'or', 'org']
		bm_sld = ['com', 'edu', 'gov', 'net', 'org']
		bo_sld = ['com', 'edu', 'gob', 'gov', 'int', 'mil', 'net', 'org', 'tv']
		br_sld = ['adm', 'adv', 'agr', 'am', 'arq', 'art', 'ato', 'bio', 'bmd', 'cim', 'cng', 'cnt', 'com', 'ecn', 'eco', 'edu', 'emp', 'eng', 'esp', 'etc', 'eti', 'far', 'fm', 'fnd', 'fot', 'fst', 'ggf', 'gov', 'imb', 'ind', 'inf', 'jor', 'jus', 'leg', 'lel', 'mat', 'med', 'mil', 'mp', 'mus', 'net', 'not', 'ntr', 'odo', 'org', 'ppg', 'pro', 'psc', 'psi', 'qsl', 'rec', 'slg', 'srv', 'teo', 'tmp', 'trd', 'tur', 'tv', 'vet', 'zlg']
		bs_sld = ['com', 'edu', 'gov', 'net', 'org']
		bt_sld = ['com', 'edu', 'gov', 'net', 'org']
		bw_sld = ['co', 'org']
		by_sld = ['com', 'gov', 'mil', 'of']
		bz_sld = ['com', 'edu', 'gov', 'net', 'org', 'za']
		ca_sld = ['ab', 'bc', 'co', 'gc', 'mb', 'nb', 'nf', 'nl', 'ns', 'nt', 'nu', 'on', 'pe', 'qc', 'sk', 'yk']
		cd_sld = ['gov']
		ci_sld = ['ac', 'co', 'com', 'ed', 'edu', 'go', 'int', 'md', 'net', 'or', 'org']
		cl_sld = ['co', 'gob', 'gov', 'mil']
		cm_sld = ['co', 'com', 'gov', 'net']
		cn_sld = ['ac', 'ah', 'bj', 'com', 'cq', 'edu', 'fj', 'gd', 'gov', 'gs', 'gx', 'gz', 'ha', 'hb', 'he', 'hi', 'hk', 'hl', 'hn', 'jl', 'js', 'jx', 'ln', 'mil', 'mo', 'net', 'nm', 'nx', 'org', 'qh', 'sc', 'sd', 'sh', 'sn', 'sx', 'tj', 'tw', 'xj', 'xz', 'yn', 'zj']
		co_sld = ['com', 'edu', 'gov', 'int', 'mil', 'net', 'nom', 'org', 'rec', 'web']
		cr_sld = ['ac', 'co', 'ed', 'fi', 'go', 'or', 'sa']
		cu_sld = ['com', 'edu', 'gov', 'inf', 'net', 'org']
		cw_sld = ['com', 'edu', 'net', 'org']
		cx_sld = ['ath', 'gov']
		cy_sld = ['ac', 'biz', 'com', 'gov', 'ltd', 'net', 'org', 'pro', 'tm']
		de_sld = ['com']
		dm_sld = ['com', 'edu', 'gov', 'net', 'org']
		do_sld = ['art', 'com', 'edu', 'gob', 'gov', 'mil', 'net', 'org', 'sld', 'web']
		dz_sld = ['art', 'com', 'edu', 'gov', 'net', 'org', 'pol']
		ec_sld = ['com', 'edu', 'fin', 'gob', 'gov', 'med', 'mil', 'net', 'org', 'pro']
		ee_sld = ['aip', 'com', 'edu', 'fie', 'gov', 'lib', 'med', 'org', 'pri']
		eg_sld = ['com', 'edu', 'eun', 'gov', 'mil', 'net', 'org', 'sci']
		es_sld = ['com', 'edu', 'gob', 'nom', 'org']
		et_sld = ['biz', 'com', 'edu', 'gov', 'net', 'org']
		fi_sld = ['iki']
		fr_sld = ['cci', 'com', 'nom', 'prd', 'tm']
		ge_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org', 'pvt']
		gg_sld = ['co', 'net', 'org']
		gh_sld = ['com', 'edu', 'gov', 'mil', 'org']
		gi_sld = ['com', 'edu', 'gov', 'ltd', 'mod', 'org']
		gl_sld = ['co', 'com', 'edu', 'net', 'org']
		gn_sld = ['ac', 'com', 'edu', 'gov', 'net', 'org']
		gp_sld = ['com', 'edu', 'net', 'org']
		gr_sld = ['com', 'edu', 'gov', 'net', 'org']
		gt_sld = ['com', 'edu', 'gob', 'ind', 'mil', 'net', 'org']
		gy_sld = ['co', 'com', 'net']
		hk_sld = ['com', 'edu', 'gov', 'idv', 'inc', 'ltd', 'net', 'org']
		hn_sld = ['com', 'edu', 'gob', 'mil', 'net', 'org']
		hr_sld = ['com', 'iz']
		ht_sld = ['art', 'com', 'edu', 'med', 'net', 'org', 'pol', 'pro', 'rel']
		hu_sld = ['co', 'org', 'sex', 'tm']
		id_sld = ['ac', 'biz', 'co', 'go', 'mil', 'my', 'net', 'or', 'sch', 'web']
		ie_sld = ['gov']
		im_sld = ['ac', 'co', 'com', 'net', 'org', 'tt', 'tv']
		in_sld = ['ac', 'co', 'edu', 'gen', 'gov', 'ind', 'mil', 'net', 'nic', 'org', 'res']
		io_sld = ['com', 'nid']
		iq_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		ir_sld = ['ac', 'co', 'gov', 'id', 'net', 'org', 'sch']
		is_sld = ['com', 'edu', 'gov', 'int', 'net', 'org']
		it_sld = ['abr', 'ag', 'al', 'an', 'ao', 'ap', 'aq', 'ar', 'at', 'av', 'ba', 'bas', 'bg', 'bi', 'bl', 'bn', 'bo', 'br', 'bs', 'bt', 'bz', 'ca', 'cal', 'cam', 'cb', 'ce', 'ch', 'ci', 'cl', 'cn', 'co', 'cr', 'cs', 'ct', 'cz', 'edu', 'emr', 'en', 'fc', 'fe', 'fg', 'fi', 'fm', 'fr', 'fvg', 'ge', 'go', 'gov', 'gr', 'im', 'is', 'kr', 'laz', 'lc', 'le', 'lig', 'li', 'lo', 'lom', 'lt', 'lu', 'mar', 'mb', 'mc', 'me', 'mi', 'mn', 'mo', 'mol', 'ms', 'mt', 'na', 'no', 'nu', 'og', 'or', 'ot', 'pa', 'pc', 'pd', 'pe', 'pg', 'pi', 'pmn', 'pn', 'po', 'pr', 'pt', 'pug', 'pu', 'pv', 'pz', 'ra', 'rc', 're', 'rg', 'ri', 'rm', 'rn', 'ro', 'sa', 'sar', 'sic', 'si', 'so', 'sp', 'sr', 'ss', 'sv', 'taa', 'ta', 'te', 'tn', 'to', 'tos', 'tp', 'tr', 'ts', 'tv', 'ud', 'umb', 'va', 'vao', 'vb', 'vc', 'vda', 've', 'ven', 'vi', 'vr', 'vs', 'vt', 'vv']
		je_sld = ['co', 'net', 'org']
		jo_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org', 'sch']
		jp_sld = ['ac', 'ad', 'co', 'ed', 'go', 'gr', 'lg', 'mie', 'ne', 'or']
		kg_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		ki_sld = ['biz', 'com', 'edu', 'gov', 'net', 'org']
		km_sld = ['ass', 'com', 'edu', 'gov', 'mil', 'nom', 'org', 'prd', 'tm']
		kn_sld = ['edu', 'gov', 'net', 'org']
		kp_sld = ['com', 'edu', 'gov', 'org', 'rep', 'tra']
		kr_sld = ['ac', 'co', 'es', 'go', 'hs', 'kg', 'mil', 'ms', 'ne', 'or', 'pe', 're', 'sc']
		ky_sld = ['com', 'edu', 'gov', 'net', 'org']
		kz_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		la_sld = ['com', 'edu', 'gov', 'int', 'net', 'org', 'per']
		lb_sld = ['com', 'edu', 'gov', 'net', 'org']
		lc_sld = ['co', 'com', 'edu', 'gov', 'net', 'org']
		lk_sld = ['ac', 'com', 'edu', 'gov', 'grp', 'int', 'ltd', 'net', 'ngo', 'org', 'sch', 'soc', 'web']
		lr_sld = ['com', 'edu', 'gov', 'net', 'org']
		ls_sld = ['co', 'org']
		lt_sld = ['gov']
		lv_sld = ['asn', 'com', 'edu', 'gov', 'id', 'mil', 'net', 'org']
		ly_sld = ['com', 'edu', 'gov', 'id', 'med', 'net', 'org', 'plc', 'sch']
		ma_sld = ['ac', 'co', 'gov', 'net', 'org']
		mc_sld = ['tm']
		me_sld = ['ac', 'co', 'edu', 'gov', 'its', 'net', 'org']
		mg_sld = ['co', 'com', 'edu', 'gov', 'mil', 'nom', 'org', 'prd', 'tm']
		mk_sld = ['com', 'edu', 'gov', 'inf', 'net', 'org']
		ml_sld = ['com', 'edu', 'gov', 'net', 'org']
		mn_sld = ['edu', 'gov', 'nyc', 'org']
		mo_sld = ['com', 'edu', 'gov', 'net', 'org']
		mr_sld = ['gov']
		ms_sld = ['com', 'edu', 'gov', 'net', 'org']
		mt_sld = ['com', 'edu', 'net', 'org']
		mu_sld = ['ac', 'com', 'co', 'gov', 'net', 'org', 'or']
		mv_sld = ['biz', 'com', 'edu', 'gov', 'int', 'mil', 'net', 'org', 'pro']
		mw_sld = ['ac', 'biz', 'com', 'co', 'edu', 'gov', 'int', 'net', 'org']
		mx_sld = ['com', 'edu', 'gob', 'net', 'org']
		my_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		na_sld = ['ca', 'cc', 'com', 'co', 'dr', 'in', 'mx', 'org', 'or', 'pro', 'tv', 'us', 'ws']
		nf_sld = ['com', 'net', 'per', 'rec', 'web']
		ng_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org', 'sch']
		nl_sld = ['bv', 'co']
		no_sld = ['aa', 'ah', 'al', 'bu', 'co', 'dep', 'eid', 'fet', 'fhs', 'fla', 'fm', 'gol', 'ha', 'hl', 'hm', 'hof', 'hol', 'lom', 'mil', 'mr', 'nl', 'nt', 'of', 'ol', 'rl', 'sel', 'sf', 'ski', 'st', 'tm', 'tr', 'va', 'vf', 'vgs', 'vik']
		nr_sld = ['biz', 'com', 'edu', 'gov', 'net', 'org']
		nz_sld = ['ac', 'co', 'cri', 'gen', 'iwi', 'mil', 'net', 'org']
		om_sld = ['com', 'co', 'edu', 'gov', 'med', 'net', 'org', 'pro']
		pa_sld = ['abo', 'ac', 'com', 'edu', 'gob', 'ing', 'med', 'net', 'nom', 'org', 'sld']
		pe_sld = ['com', 'edu', 'gob', 'mil', 'net', 'nom', 'org']
		pf_sld = ['com', 'edu', 'org']
		ph_sld = ['com', 'edu', 'gov', 'mil', 'net', 'ngo', 'org']
		pk_sld = ['biz', 'com', 'edu', 'fam', 'gob', 'gok', 'gon', 'gop', 'gos', 'gov', 'net', 'org', 'web']
		pl_sld = ['aid', 'art', 'atm', 'biz', 'com', 'co', 'edu', 'elk', 'gda', 'gov', 'gsm', 'med', 'mil', 'net', 'nom', 'org', 'pc', 'rel', 'sex', 'sos', 'tm', 'waw']
		pn_sld = ['co', 'edu', 'gov', 'net', 'org']
		pr_sld = ['ac', 'biz', 'com', 'edu', 'est', 'gov', 'net', 'org', 'pro']
		ps_sld = ['com', 'edu', 'gov', 'net', 'org', 'plo', 'sec']
		pt_sld = ['com', 'edu', 'gov', 'int', 'net', 'org']
		pw_sld = ['co', 'ed', 'go', 'ne', 'or']
		py_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		qa_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org', 'sch']
		re_sld = ['com', 'nom']
		ro_sld = ['com', 'nom', 'nt', 'org', 'rec', 'tm', 'www']
		rs_sld = ['ac', 'co', 'edu', 'gov', 'in', 'org']
		ru_sld = ['ac', 'bir', 'cbg', 'cmw', 'com', 'edu', 'gov', 'int', 'jar', 'khv', 'kms', 'mil', 'msk', 'net', 'nkz', 'nov', 'nsk', 'org', 'pp', 'ptz', 'rnd', 'snz', 'spb', 'stv', 'tom', 'tsk', 'udm', 'vrn']
		rw_sld = ['ac', 'com', 'co', 'edu', 'gov', 'int', 'mil', 'net']
		sa_sld = ['com', 'edu', 'gov', 'med', 'net', 'org', 'pub', 'sch']
		sb_sld = ['com', 'edu', 'gov', 'net', 'org']
		sc_sld = ['com', 'edu', 'gov', 'net', 'org']
		sd_sld = ['com', 'edu', 'gov', 'med', 'net', 'org', 'tv']
		se_sld = ['ac', 'bd', 'com', 'fh', 'fhv', 'org', 'pp', 'tm']
		sg_sld = ['com', 'edu', 'gov', 'net', 'org', 'per']
		sh_sld = ['com', 'gov', 'mil', 'net', 'org']
		sl_sld = ['com', 'edu', 'gov', 'net', 'org']
		sn_sld = ['art', 'com', 'edu', 'org']
		so_sld = ['com', 'net', 'org']
		st_sld = ['com', 'co', 'edu', 'gov', 'mil', 'net', 'org']
		su_sld = ['msk', 'nov', 'spb']
		sv_sld = ['com', 'edu', 'gob', 'org', 'red']
		sx_sld = ['gov']
		sy_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		sz_sld = ['ac', 'co', 'org']
		th_sld = ['ac', 'co', 'go', 'in', 'mi', 'net', 'or']
		tj_sld = ['ac', 'biz', 'com', 'co', 'edu', 'go', 'gov', 'int', 'mil', 'net', 'nic', 'org', 'web']
		tl_sld = ['gov']
		tm_sld = ['com', 'co', 'edu', 'gov', 'mil', 'net', 'nom', 'org']
		tn_sld = ['com', 'ens', 'fin', 'gov', 'ind', 'nat', 'net', 'org', 'rns', 'rnu']
		to_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		tr_sld = ['av', 'bbs', 'bel', 'biz', 'com', 'dr', 'edu', 'gen', 'gov', 'kep', 'mil', 'nc', 'net', 'org', 'pol', 'tel', 'tv', 'web']
		tt_sld = ['biz', 'com', 'co', 'edu', 'gov', 'int', 'net', 'org', 'pro']
		tw_sld = ['com', 'edu', 'gov', 'idv', 'mil', 'net', 'org']
		tz_sld = ['ac', 'co', 'go', 'me', 'mil', 'ne', 'or', 'sc', 'tv']
		ua_sld = ['biz', 'ck', 'cn', 'com', 'co', 'cr', 'cv', 'dn', 'dp', 'edu', 'gov', 'if', 'in', 'kh', 'km', 'kr', 'ks', 'kv', 'lg', 'lt', 'lv', 'mk', 'net', 'od', 'org', 'pl', 'pp', 'rv', 'sb', 'sm', 'te', 'uz', 'vn', 'zp', 'zt']
		ug_sld = ['ac', 'com', 'co', 'go', 'ne', 'org', 'or', 'sc']
		uk_sld = ['ac', 'co', 'gov', 'ltd', 'me', 'net', 'nhs', 'org', 'plc']
		us_sld = ['ak', 'al', 'ar', 'as', 'az', 'ca', 'co', 'ct', 'dc', 'de', 'dni', 'fed', 'fl', 'ga', 'gu', 'hi', 'ia', 'id', 'il', 'in', 'isa', 'ks', 'ky', 'la', 'ma', 'md', 'me', 'mi', 'mn', 'mo', 'ms', 'mt', 'nc', 'nd', 'ne', 'nh', 'nj', 'nm', 'nsn', 'nv', 'ny', 'oh', 'ok', 'or', 'pa', 'pr', 'ri', 'sc', 'sd', 'tn', 'tx', 'ut', 'va', 'vi', 'vt', 'wa', 'wi', 'wv', 'wy']
		uy_sld = ['com', 'edu', 'gub', 'mil', 'net', 'org']
		uz_sld = ['com', 'co', 'net', 'org']
		vc_sld = ['com', 'edu', 'gov', 'mil', 'net', 'org']
		ve_sld = ['com', 'co', 'edu', 'gob', 'gov', 'int', 'mil', 'net', 'org', 'rec', 'tec', 'web']
		vi_sld = ['com', 'co', 'net', 'org']
		vn_sld = ['ac', 'biz', 'com', 'edu', 'gov', 'int', 'net', 'org', 'pro']
		vu_sld = ['com', 'edu', 'net', 'org']
		ws_sld = ['com', 'edu', 'gov', 'net', 'org']
		za_sld = ['ac', 'alt', 'co', 'edu', 'gov', 'law', 'mil', 'net', 'ngo', 'nis', 'nom', 'org', 'tm', 'web']
	
		cc_tld = {
		'ac': ac_sld, 'ad': ad_sld, 'ae': ae_sld, 'af': af_sld, 'ag': ag_sld, 'ai': ai_sld, 'al': al_sld, 'an': an_sld, 'ao': ao_sld,
		'ar': ar_sld, 'as': as_sld, 'at': at_sld, 'au': au_sld, 'aw': aw_sld, 'az': az_sld, 'ba': ba_sld, 'bb': bb_sld, 'be': be_sld,
		'bf': bf_sld, 'bh': bh_sld, 'bi': bi_sld, 'bm': bm_sld, 'bo': bo_sld, 'br': br_sld, 'bs': bs_sld, 'bt': bt_sld, 'bw': bw_sld,
		'by': by_sld, 'bz': bz_sld, 'ca': ca_sld, 'cd': cd_sld, 'ci': ci_sld, 'cl': cl_sld, 'cm': cm_sld, 'cn': cn_sld, 'co': co_sld,
		'cr': cr_sld, 'cu': cu_sld, 'cw': cw_sld, 'cx': cx_sld, 'cy': cy_sld, 'de': de_sld, 'dm': dm_sld, 'do': do_sld, 'dz': dz_sld,
		'ec': ec_sld, 'ee': ee_sld, 'eg': eg_sld, 'es': es_sld, 'et': et_sld, 'fi': fi_sld, 'fr': fr_sld, 'ge': ge_sld, 'gg': gg_sld,
		'gh': gh_sld, 'gi': gi_sld, 'gl': gl_sld, 'gn': gn_sld, 'gp': gp_sld, 'gr': gr_sld, 'gt': gt_sld, 'gy': gy_sld, 'hk': hk_sld,
		'hn': hn_sld, 'hr': hr_sld, 'ht': ht_sld, 'hu': hu_sld, 'id': id_sld, 'ie': ie_sld, 'im': im_sld, 'in': in_sld, 'io': io_sld,
		'iq': iq_sld, 'ir': ir_sld, 'is': is_sld, 'it': it_sld, 'je': je_sld, 'jo': jo_sld, 'jp': jp_sld, 'kg': kg_sld, 'ki': ki_sld,
		'km': km_sld, 'kn': kn_sld, 'kp': kp_sld, 'kr': kr_sld, 'ky': ky_sld, 'kz': kz_sld, 'la': la_sld, 'lb': lb_sld, 'lc': lc_sld,
		'lk': lk_sld, 'lr': lr_sld, 'ls': ls_sld, 'lt': lt_sld, 'lv': lv_sld, 'ly': ly_sld, 'ma': ma_sld, 'mc': mc_sld, 'me': me_sld,
		'mg': mg_sld, 'mk': mk_sld, 'ml': ml_sld, 'mn': mn_sld, 'mo': mo_sld, 'mr': mr_sld, 'ms': ms_sld, 'mt': mt_sld, 'mu': mu_sld,
		'mv': mv_sld, 'mw': mw_sld, 'mx': mx_sld, 'my': my_sld, 'na': na_sld, 'nf': nf_sld, 'ng': ng_sld, 'nl': nl_sld, 'no': no_sld,
		'nr': nr_sld, 'nz': nz_sld, 'om': om_sld, 'pa': pa_sld, 'pe': pe_sld, 'pf': pf_sld, 'ph': ph_sld, 'pk': pk_sld, 'pl': pl_sld,
		'pn': pn_sld, 'pr': pr_sld, 'ps': ps_sld, 'pt': pt_sld, 'pw': pw_sld, 'py': py_sld, 'qa': qa_sld, 're': re_sld, 'ro': ro_sld,
		'rs': rs_sld, 'ru': ru_sld, 'rw': rw_sld, 'sa': sa_sld, 'sb': sb_sld, 'sc': sc_sld, 'sd': sd_sld, 'se': se_sld, 'sg': sg_sld,
		'sh': sh_sld, 'sl': sl_sld, 'sn': sn_sld, 'so': so_sld, 'st': st_sld, 'su': su_sld, 'sv': sv_sld, 'sx': sx_sld, 'sy': sy_sld,
		'sz': sz_sld, 'th': th_sld, 'tj': tj_sld, 'tl': tl_sld, 'tm': tm_sld, 'tn': tn_sld, 'to': to_sld, 'tr': tr_sld, 'tt': tt_sld,
		'tw': tw_sld, 'tz': tz_sld, 'ua': ua_sld, 'ug': ug_sld, 'uk': uk_sld, 'us': us_sld, 'uy': uy_sld, 'uz': uz_sld, 'vc': vc_sld,
		've': ve_sld, 'vi': vi_sld, 'vn': vn_sld, 'vu': vu_sld, 'ws': ws_sld, 'za': za_sld
		}
	
		sld_tld = cc_tld.get(domain[2])
		if sld_tld:
			if domain[1] in sld_tld:
				return [domain[0], domain[1] + '.' + domain[2]]
	
		return [domain[0] + '.' + domain[1], domain[2]]

	def __filter_domains(self):
		seen = set()
		filtered = []

		for d in self.domains:
			if self.__validate_domain(d['domain']) and d['domain'] not in seen:
				seen.add(d['domain'])
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
		'd': ['b', 'cl'], 'm': ['n', 'nn', 'rn'], 'l': ['1', 'i'], 'o': ['0'],
		'w': ['vv'], 'n': ['m'], 'b': ['d'], 'i': ['1', 'l'], 'g': ['q'], 'q': ['g']
		}
		result = []

		for ws in range(0, len(self.domain)):
			for i in range(0, (len(self.domain)-ws)+1):
				win = self.domain[i:i+ws]

				j = 0
				while j < ws:
					c = win[j]
					if c in glyphs:
						win_copy = win
						for g in glyphs[c]:
							win = win[:j] + g + win[j+1:]
							result.append(self.domain[:i] + win + self.domain[i+ws:])
							win = win_copy
					j += 1

		return list(set(result))

	def __hyphenation(self):
		result = []

		for i in range(1, len(self.domain)):
			if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
				result.append(self.domain[:i] + '-' + self.domain[i:])

		return result

	def __insertion(self):
		keys = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
		}
		result = []

		for i in range(1, len(self.domain)-1):
			if self.domain[i] in keys:
				for c in range(0, len(keys[self.domain[i]])):
					result.append(self.domain[:i] + keys[self.domain[i]][c] + self.domain[i] + self.domain[i+1:])
					result.append(self.domain[:i] + self.domain[i] + keys[self.domain[i]][c] + self.domain[i+1:])

		return result

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
		keys = {
		'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
		'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
		'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
		'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
		}
		result = []

		for i in range(0, len(self.domain)):
			if self.domain[i] in keys:
				for c in range(0, len(keys[self.domain[i]])):
					result.append(self.domain[:i] + keys[self.domain[i]][c] + self.domain[i+1:])

		return result

	def __subdomain(self):
		result = []

		for i in range(1, len(self.domain)):
			if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
				result.append(self.domain[:i] + '.' + self.domain[i:])

		return result

	def __transposition(self):
		result = []

		for i in range(0, len(self.domain)-1):
			if self.domain[i+1] != self.domain[i]:
				result.append(self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:])

		return result

	def fuzz(self):
		self.domains.append({ 'fuzzer': 'Original*', 'domain': self.domain + '.' + self.tld })

		for domain in self.__bitsquatting():
			self.domains.append({ 'fuzzer': 'Bitsquatting', 'domain': domain + '.' + self.tld })
		for domain in self.__homoglyph():
			self.domains.append({ 'fuzzer': 'Homoglyph', 'domain': domain + '.' + self.tld })
		for domain in self.__hyphenation():
			self.domains.append({ 'fuzzer': 'Hyphenation', 'domain': domain + '.' + self.tld })
		for domain in self.__insertion():
			self.domains.append({ 'fuzzer': 'Insertion', 'domain': domain + '.' + self.tld })
		for domain in self.__omission():
			self.domains.append({ 'fuzzer': 'Omission', 'domain': domain + '.' + self.tld })
		for domain in self.__repetition():
			self.domains.append({ 'fuzzer': 'Repetition', 'domain': domain + '.' + self.tld })
		for domain in self.__replacement():
			self.domains.append({ 'fuzzer': 'Replacement', 'domain': domain + '.' + self.tld })
		for domain in self.__subdomain():
			self.domains.append({ 'fuzzer': 'Subdomain', 'domain': domain + '.' + self.tld })
		for domain in self.__transposition():
			self.domains.append({ 'fuzzer': 'Transposition', 'domain': domain + '.' + self.tld })

		self.__filter_domains()

	def get(self):
		return self.domains

class thread_domain(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.jobs = queue
		self.kill_received = False
		self.orig_domain_ssdeep = ''

	def __banner_http(self, ip, vhost):
		try:
			http = socket.socket()
			http.settimeout(1)
			http.connect((ip, 80))
			http.send('HEAD / HTTP/1.1\r\nHost: %s\r\nUser-agent: Mozilla/5.0\r\n\r\n' % str(vhost))
			response = http.recv(1024)
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
				return 'HTTP %s' % headers[0].split(' ')[1]

	def __banner_smtp(self, mx):
		try:
			smtp = socket.socket()
			smtp.settimeout(1)
			smtp.connect((mx, 25))
			response = smtp.recv(1024)
			smtp.close()
		except Exception:
			pass
		else:
			sep = '\r\n' if '\r\n' in response else '\n'
			hello = response.split(sep)[0]
			if hello.startswith('220'):
				return hello[4:].strip()
			return hello[:40]

	def orig_ssdeep(self, hash):
		self.orig_domain_ssdeep = hash

	def stop(self):
		self.kill_received = True

	def run(self):
		while not self.kill_received:
			domain = self.jobs.get()
			if module_dnspython:
				resolv = dns.resolver.Resolver()
				resolv.lifetime = REQUEST_TIMEOUT_DNS
				resolv.timeout = REQUEST_TIMEOUT_DNS

				try:
					ns = resolv.query(domain['domain'], 'NS')
					domain['ns'] = str(ns[0])[:-1].lower()
				except Exception:
					pass

				if 'ns' in domain:
					try:
						ns = resolv.query(domain['domain'], 'A')
						domain['a'] = str(ns[0])
					except Exception:
						pass
	
					try:
						ns = resolv.query(domain['domain'], 'AAAA')
						domain['aaaa'] = str(ns[0])
					except Exception:
						pass

					try:
						mx = resolv.query(domain['domain'], 'MX')
						domain['mx'] = str(mx[0].exchange)[:-1].lower()
					except Exception:
						pass
			else:
				try:
					ip = socket.getaddrinfo(domain['domain'], 80)
				except Exception:
					pass
				else:
					for j in ip:
						if '.' in j[4][0]:
							domain['a'] = j[4][0]
							break
					for j in ip:
						if ':' in j[4][0]:
							domain['aaaa'] = j[4][0]
							break

			if module_whois and args.whois:
				if 'ns' in domain and 'a' in domain:
					try:
						whoisdb = whois.query(domain['domain'])
						domain['created'] = str(whoisdb.creation_date).replace(' ', 'T')
						domain['updated'] = str(whoisdb.last_updated).replace(' ', 'T')
					except Exception:
						pass

			if module_geoip and geoip_db and args.geoip:
				if 'a' in domain:
					gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
					try:
						country = gi.country_name_by_addr(domain['a'])
					except Exception:
						pass
					else:
						if country:
							domain['country'] = country

			if args.banners:
				if 'a' in domain:
					banner = self.__banner_http(domain['a'], domain['domain'])
					if banner:
						domain['banner-http'] = banner
				if 'mx' in domain:
					banner = self.__banner_smtp(domain['mx'])
					if banner:
						domain['banner-smtp'] = banner

			if args.ssdeep and module_requests and module_ssdeep and self.orig_domain_ssdeep:
				if 'a' in domain:
					try:
						req = requests.get('http://' + domain['domain'], timeout=REQUEST_TIMEOUT_HTTP)
						fuzz_domain_ssdeep = ssdeep.hash(req.text)
					except Exception:
						pass
					else:
						domain['ssdeep'] = ssdeep.compare(self.orig_domain_ssdeep, fuzz_domain_ssdeep)

			self.jobs.task_done()

def main():
	parser = argparse.ArgumentParser(
	description='''Find similar-looking domain names that adversaries can use to attack you.  
	Can detect typosquatting, phishing attacks, fraud and corporate espionage. Useful as an
	additional source of targeted threat intelligence.'''
	)

	parser.add_argument('domain', help='domain name to check')
	parser.add_argument('-c', '--csv', action='store_true', help='print output in CSV format')
	parser.add_argument('-r', '--registered', action='store_true', help='show only registered domain names')
	parser.add_argument('-w', '--whois', action='store_true', help='perform lookup for WHOIS creation/update time (slow)')
	parser.add_argument('-g', '--geoip', action='store_true', help='perform lookup for GeoIP location')
	parser.add_argument('-b', '--banners', action='store_true', help='determine HTTP and SMTP service banners')
	parser.add_argument('-s', '--ssdeep', action='store_true', help='fetch web pages and compare their fuzzy hashes to evaluate similarity')
	parser.add_argument('-t', '--threads', type=int, default=THREAD_COUNT_DEFAULT, help='number of threads to run (default: %d)' % THREAD_COUNT_DEFAULT)

	if len(sys.argv) < 2:
		sys.stdout.write('%sdnstwist %s by <%s>%s\n\n' % (ST_BRI, __version__, __email__, ST_RST))
		parser.print_help()
		sys.exit(0)

	global args
	args = parser.parse_args()

	args.domain = args.domain.lower()

	if args.threads < 1 or args.threads > 100:
		args.threads = THREAD_COUNT_DEFAULT

	p_out(ST_BRI + FG_RND +
'''     _           _            _     _   
  __| |_ __  ___| |___      _(_)___| |_ 
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_ 
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}

''' % __version__ + FG_RST)

	try:
		fuzzer = fuzz_domain(args.domain)
	except Exception:
		p_err(FG_RED + 'ERROR: invalid domain name!\n\n' + FG_RST)
		sys.exit(-1)

	signal.signal(signal.SIGINT, sigint_handler)

	fuzzer.fuzz()
	domains = fuzzer.get()

	if not module_dnspython:
		p_out(FG_YEL + 'NOTICE: Missing module: dnspython - DNS features limited!\n\n' + FG_RST)
	if not module_geoip and args.geoip:
		p_out(FG_YEL + 'NOTICE: Missing module: GeoIP - geographical location not available!\n\n' + FG_RST)
	if not geoip_db and args.geoip:
		p_out(FG_YEL + 'NOTICE: Missing file: /usr/share/GeoIP/geoIP.dat - geographical location not available!\n\n' + FG_RST)
	if not module_whois and args.whois:
		p_out(FG_YEL + 'NOTICE: Missing module: whois - database not accessible!\n\n' + FG_RST)
	if not module_ssdeep and args.ssdeep:
		p_out(FG_YEL + 'NOTICE: Missing module: ssdeep - fuzzy hashes not available!\n\n' + FG_RST)
	if not module_requests and args.ssdeep:
		p_out(FG_YEL + 'NOTICE: Missing module: Requests - web page downloads not possible!\n\n' + FG_RST)
	if module_whois and args.whois:
		p_out(FG_YEL + 'NOTICE: Reducing the number of threads to 1 in order to query WHOIS server\n\n' + FG_RST)
		args.threads = 1

	if args.ssdeep and module_ssdeep and module_requests:
		p_out('Fetching content from: http://' + args.domain + '/ ... ')
		try:
			req = requests.get('http://' + args.domain, timeout=REQUEST_TIMEOUT_HTTP)
		except Exception:
			p_out('Failed!\n')
			args.ssdeep = False
			pass
		else:
			p_out('%d %s (%d bytes)\n' % (req.status_code, req.reason, len(req.text)))
			orig_domain_ssdeep = ssdeep.hash(req.text)

	p_out('Processing %d domains ' % len(domains))

	jobs = queue.Queue()

	global threads
	threads = []

	for i in range(args.threads):
		worker = thread_domain(jobs)
		worker.setDaemon(True)
		if 'orig_domain_ssdeep' in locals():
			worker.orig_ssdeep(orig_domain_ssdeep)
		worker.start()
		threads.append(worker)
	
	for i in range(len(domains)):
		jobs.put(domains[i])

	while not jobs.empty():
		p_out('.')
		time.sleep(1)

	for worker in threads:
		worker.stop()

	p_out(' %d hit(s)\n\n' % sum('ns' in d or 'a' in d for d in domains))
	time.sleep(1)

	p_csv('Fuzzer,Domain,A,AAAA,MX,NS,Country,Created,Updated,SSDEEP\n')

	width_fuzz = max([len(d['fuzzer']) for d in domains]) + 2
	width_domain = max([len(d['domain']) for d in domains]) + 2

	for domain in domains:
		info = ''

		if 'a' in domain:
			info += domain['a']
			if 'country' in domain:
				info += FG_CYA + '/' + domain['country'] + FG_RST
			if 'banner-http' in domain:
				info += ' %sHTTP:%s"%s"%s' % (FG_GRE, FG_CYA, domain['banner-http'], FG_RST)
		elif 'ns' in domain:
			info += '%sNS:%s%s%s' % (FG_GRE, FG_CYA, domain['ns'], FG_RST)

		if 'aaaa' in domain:
			info += ' ' + domain['aaaa']

		if 'mx' in domain:
			info += ' %sMX:%s%s%s' % (FG_GRE, FG_CYA, domain['mx'], FG_RST)
			if 'banner-smtp' in domain:
				info += ' %sSMTP:%s"%s"%s' % (FG_GRE, FG_CYA, domain['banner-smtp'], FG_RST)

		if 'created' in domain and 'updated' in domain and domain['created'] == domain['updated']:
			info += ' %sCreated/Updated:%s%s%s' % (FG_GRE, FG_CYA, domain['created'], FG_RST)
		else:
			if 'created' in domain:
				info += ' %sCreated:%s%s%s' % (FG_GRE, FG_CYA, domain['created'], FG_RST)
			if 'updated' in domain:
				info += ' %sUpdated:%s%s%s' % (FG_GRE, FG_CYA, domain['updated'], FG_RST)

		if 'ssdeep' in domain:
			if domain['ssdeep'] > 0:
				info += ' %sSSDEEP:%s%d%%%s' % (FG_GRE, FG_CYA, domain['ssdeep'], FG_RST)

		if not info:
			info = '-'

		if (args.registered and info != '-') or not args.registered:
			p_out('%s%s%s %s %s\n' % (FG_BLU, domain['fuzzer'].ljust(width_fuzz), FG_RST, domain['domain'].ljust(width_domain), info))

			p_csv(
			'%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' % (domain.get('fuzzer'), domain.get('domain'), domain.get('a', ''),
			domain.get('aaaa', ''), domain.get('mx', ''), domain.get('ns', ''), domain.get('country', ''),
			domain.get('created', ''), domain.get('updated', ''), str(domain.get('ssdeep', '')))
			)

	p_out(FG_RST + ST_RST)

	return 0

if __name__ == '__main__':
	main()
