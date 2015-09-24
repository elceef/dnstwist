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
__version__ = '20150920'
__email__ = 'marcin@ulikowski.pl'

import re
import sys
import socket
import signal
import argparse
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

if sys.platform != 'win32' and sys.stdout.isatty():
	FG_RED = '\x1b[31m'
	FG_YELLOW = '\x1b[33m'
	FG_GREEN = '\x1b[32m'
	FG_MAGENTA = '\x1b[35m'
	FG_CYAN = '\x1b[36m'
	FG_BLUE = '\x1b[34m'
	FG_RESET = '\x1b[39m'

	ST_BRIGHT = '\x1b[1m'
	ST_RESET = '\x1b[0m'
else:
	FG_RED = ''
	FG_YELLOW = ''
	FG_GREEN = ''
	FG_MAGENTA = ''
	FG_CYAN = ''
	FG_BLUE = ''
	FG_RESET = ''

	ST_BRIGHT = ''
	ST_RESET = ''

def display(text):
	global args
	if not args.csv:
		sys.stdout.write(text)
		sys.stdout.flush()

def display_csv(text):
	global args
	if args.csv:
		sys.stdout.write(text)

def sigint_handler(signal, frame):
	sys.stdout.write(FG_RESET + ST_RESET)
	sys.exit(0)

# Internationalized domains not supported
def validate_domain(domain):
	if len(domain) > 255:
		return False
	if domain[-1] == '.':
		domain = domain[:-1]
	allowed = re.compile('\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z', re.IGNORECASE)
	return allowed.match(domain)

def parse_domain(domain):
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
	br_sld = ['adm', 'adv', 'agr', 'am', 'arq', 'art', 'ato', 'b', 'bio', 'bmd', 'cim', 'cng', 'cnt', 'com', 'ecn', 'eco', 'edu', 'emp', 'eng', 'esp', 'etc', 'eti', 'far', 'fm', 'fnd', 'fot', 'fst', 'ggf', 'gov', 'imb', 'ind', 'inf', 'jor', 'jus', 'leg', 'lel', 'mat', 'med', 'mil', 'mp', 'mus', 'net', 'not', 'ntr', 'odo', 'org', 'ppg', 'pro', 'psc', 'psi', 'qsl', 'rec', 'slg', 'srv', 'teo', 'tmp', 'trd', 'tur', 'tv', 'vet', 'zlg']
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
	la_sld = ['c', 'com', 'edu', 'gov', 'int', 'net', 'org', 'per']
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

def http_banner(ip, vhost):
	try:
		http = socket.socket()
		http.settimeout(1)
		http.connect((ip, 80))
		http.send('HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n' % str(vhost))
		response = http.recv(1024)
		http.close()
	except Exception:
		pass
	else:
		if '\r\n' in response: sep = '\r\n'
		else: sep = '\n'
		headers = response.split(sep)
		for field in headers:
			if field.startswith('Server: '):
				return field[8:]
		return 'HTTP %s' % headers[0].split(' ')[1]

def smtp_banner(mx):
	try:
		smtp = socket.socket()
		smtp.settimeout(1)
		smtp.connect((mx, 25))
		response = smtp.recv(1024)
		smtp.close()
	except Exception:
		pass
	else:
		if '\r\n' in response: sep = '\r\n'
		else: sep = '\n'
		hello = response.split(sep)[0]
		if hello.startswith('220'):
			return hello[4:].strip()
		return hello[:40]

def bitsquatting(domain):
	out = []
	dom, tld = parse_domain(domain)
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
	'd':['b', 'cl'], 'm':['n', 'nn', 'rn'], 'l':['1', 'i'], 'o':['0'],
	'w':['vv'], 'n':['m'], 'b':['d'], 'i':['1', 'l'], 'g':['q'], 'q':['g']
	}
	out = []
	dom, tld = parse_domain(domain)

	for ws in range(0, len(dom)):
		for i in range(0, (len(dom)-ws)+1):
			win = dom[i:i+ws]

			j = 0
			while j < ws:
				c = win[j]
				if c in glyphs:
					for g in glyphs[c]:
						win = win[:j] + g + win[j+1:]

						if len(g) > 1:
							j += len(g) - 1
						out.append(dom[:i] + win + dom[i+ws:] + '.' + tld)

				j += 1

	return list(set(out))

def repetition(domain):
	out = []
	dom, tld = parse_domain(domain)

	for i in range(0, len(dom)):
		if dom[i].isalpha():
			out.append(dom[:i] + dom[i] + dom[i] + dom[i+1:] + '.' + tld)

	return list(set(out))

def transposition(domain):
	out = []
	dom, tld = parse_domain(domain)

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
	dom, tld = parse_domain(domain)

	for i in range(0, len(dom)):
		if dom[i] in keys:
			for c in range(0, len(keys[dom[i]])):
				out.append(dom[:i] + keys[dom[i]][c] + dom[i+1:] + '.' + tld)

	return out

def omission(domain):
	out = []
	dom, tld = parse_domain(domain)

	for i in range(0, len(dom)):
		out.append(dom[:i] + dom[i+1:] + '.' + tld)

	n = re.sub(r'(.)\1+', r'\1', dom) + '.' + tld
	
	if n not in out:
		out.append(n) 

	return list(set(out))

def hyphenation(domain):
	out = []
	dom, tld = parse_domain(domain)

	for i in range(1, len(dom)):
		if dom[i] not in ['-', '.'] and dom[i-1] not in ['-', '.']:
			out.append(dom[:i] + '-' + dom[i:] + '.' + tld)

	return out

def subdomain(domain):
	out = []
	dom, tld = parse_domain(domain)

	for i in range(1, len(dom)):
		if dom[i] not in ['-', '.'] and dom[i-1] not in ['-', '.']:
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
	dom, tld = parse_domain(domain)

	for i in range(1, len(dom)-1):
		if dom[i] in keys:
			for c in range(0, len(keys[dom[i]])):
				out.append(dom[:i] + keys[dom[i]][c] + dom[i] + dom[i+1:] + '.' + tld)
				out.append(dom[:i] + dom[i] + keys[dom[i]][c] + dom[i+1:] + '.' + tld)

	return out

def fuzz_domain(domain):
	domains = []

	domains.append({ 'type':'Original*', 'domain':domain })

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
	for i in insertion(domain):
		domains.append({ 'type':'Insertion', 'domain':i })
	for i in subdomain(domain):
		domains.append({ 'type':'Subdomain', 'domain':i })

	domains[:] = [x for x in domains if validate_domain(x['domain'])]

	return domains

def main():
	parser = argparse.ArgumentParser(
	description='''Find similar-looking domains that adversaries can use to attack you.  
	Can detect fraud, phishing attacks and corporate espionage. Useful as an additional 
	source of targeted threat intelligence.''',
	epilog='''Questions? Complaints? You can reach the author at <marcin@ulikowski.pl>'''
	)

	parser.add_argument('domain', help='domain name to check')
	parser.add_argument('-c', '--csv', action='store_true', help='print output in CSV format')
	parser.add_argument('-r', '--registered', action='store_true', help='show only registered domain names')
	parser.add_argument('-w', '--whois', action='store_true', help='perform lookup for WHOIS creation/modification date (slow)')
	parser.add_argument('-g', '--geoip', action='store_true', help='perform lookup for GeoIP location')
	parser.add_argument('-b', '--banners', action='store_true', help='determine HTTP and SMTP service banners')
	parser.add_argument('-s', '--ssdeep', action='store_true', help='fetch web pages and compare fuzzy hashes to evaluate similarity')

	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(0)

	global args
	args = parser.parse_args()

	display(ST_BRIGHT + FG_MAGENTA + 
'''     _           _            _     _   
  __| |_ __  ___| |___      _(_)___| |_ 
 / _` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_ 
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}

''' % __version__ + FG_RESET)
	
	if not validate_domain(args.domain):
		sys.stderr.write('ERROR: invalid domain name!\n')
		sys.exit(-1)

	domains = fuzz_domain(args.domain.lower())

	if not module_dnspython:
		display(FG_RED + 'NOTICE: Missing module: dnspython - DNS features limited!\n' + FG_RESET)
	if not module_geoip and args.geoip:
		display(FG_RED + 'NOTICE: Missing module: GeoIP - geographical location not available!\n' + FG_RESET)
	if not module_whois and args.whois:
		display(FG_RED + 'NOTICE: Missing module: whois - database not accessible!\n' + FG_RESET)
	if not module_ssdeep and args.ssdeep:
		display(FG_RED + 'NOTICE: Missing module: ssdeep - fuzzy hashes not available!\n' + FG_RESET)
	if not module_requests and args.ssdeep:
		display(FG_RED + 'NOTICE: Missing module: Requests - web page downloads not possible!\n' + FG_RESET)

	if args.ssdeep and module_ssdeep and module_requests:
		display('Fetching content from: http://' + args.domain.lower() + '/ [following redirects] ... ')
		try:
			req = requests.get('http://' + args.domain.lower(), timeout=2)
		except Exception:
			display('Failed!\n')
			args.ssdeep = False			
			pass
		else:
			display('%d %s (%d bytes)\n' % (req.status_code, req.reason, len(req.text)))
			orig_domain_ssdeep = ssdeep.hash(req.text)

	display('Processing %d domains ' % len(domains))

	signal.signal(signal.SIGINT, sigint_handler)

	total_hits = 0

	for i in range(0, len(domains)):
		if module_dnspython:
			resolv = dns.resolver.Resolver()
			resolv.lifetime = 1
			resolv.timeout = 1

			try:
				ns = resolv.query(domains[i]['domain'], 'NS')
				domains[i]['ns'] = str(ns[0])[:-1].lower()
			except Exception:
				pass

			if 'ns' in domains[i]:
				try:
					ns = resolv.query(domains[i]['domain'], 'A')
					domains[i]['a'] = str(ns[0])
				except Exception:
					pass
	
				try:
					ns = resolv.query(domains[i]['domain'], 'AAAA')
					domains[i]['aaaa'] = str(ns[0])
				except Exception:
					pass

				try:
					mx = resolv.query(domains[i]['domain'], 'MX')
					domains[i]['mx'] = str(mx[0].exchange)[:-1].lower()
				except Exception:
					pass
		else:
			try:
				ip = socket.getaddrinfo(domains[i]['domain'], 80)
			except Exception:
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
				except Exception:
					pass

		if module_geoip and args.geoip:
			if 'a' in domains[i]:
				gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
				try:
					country = gi.country_name_by_addr(domains[i]['a'])
				except Exception:
					pass
				else:
					if country:
						domains[i]['country'] = country

		if args.banners:
			if 'a' in domains[i]:
				banner = http_banner(domains[i]['a'], domains[i]['domain'])
				if banner:
					domains[i]['banner-http'] = banner
			if 'mx' in domains[i]:
				banner = smtp_banner(domains[i]['mx'])
				if banner:
					domains[i]['banner-smtp'] = banner

		if module_ssdeep and module_requests and args.ssdeep:
			if 'a' in domains[i]:
				try:
					req = requests.get('http://' + domains[i]['domain'], timeout=1)
					fuzz_domain_ssdeep = ssdeep.hash(req.text)
				except Exception:
					pass
				else:
					domains[i]['ssdeep'] = ssdeep.compare(orig_domain_ssdeep, fuzz_domain_ssdeep)

		if 'a' in domains[i] or 'ns' in domains[i]:
			display(FG_YELLOW + '!' + FG_RESET)
			total_hits += 1
		else:
			display('.')

	display(' %d hit(s)\n\n' % total_hits)

	display_csv('Generator,Domain,A,AAAA,MX,NS,Country,Created,Updated,SSDEEP\n')

	for i in domains:
		info = ''

		if 'a' in i:
			info += i['a']
			if 'country' in i:
				info += FG_CYAN + '/' + i['country'] + FG_RESET
			if 'banner-http' in i:
				info += ' %sHTTP:%s"%s"%s' % (FG_GREEN, FG_CYAN, i['banner-http'], FG_RESET)
		elif 'ns' in i:
			info += '%sNS:%s%s%s' % (FG_GREEN, FG_CYAN, i['ns'], FG_RESET)

		if 'aaaa' in i:
			info += ' ' + i['aaaa']

		if 'mx' in i:
			info += ' %sMX:%s%s%s' % (FG_GREEN, FG_CYAN, i['mx'], FG_RESET)
			if 'banner-smtp' in i:
				info += ' %sSMTP:%s"%s"%s' % (FG_GREEN, FG_CYAN, i['banner-smtp'], FG_RESET)

		if 'created' in i and 'updated' in i and i['created'] == i['updated']:
			info += ' %sCreated/Updated:%s%s%s' % (FG_GREEN, FG_CYAN, i['created'], FG_RESET)
		else:
			if 'created' in i:
				info += ' %sCreated:%s%s%s' % (FG_GREEN, FG_CYAN, i['created'], FG_RESET)
			if 'updated' in i:
				info += ' %sUpdated:%s%s%s' % (FG_GREEN, FG_CYAN, i['updated'], FG_RESET)

		if 'ssdeep' in i:
			if i['ssdeep'] > 0:
				info += ' %sSSDEEP:%s%d%%%s' % (FG_GREEN, FG_CYAN, i['ssdeep'], FG_RESET)

		if not info:
			info = '-'

		if (args.registered and info != '-') or not args.registered:
			display('%s%-15s%s %-15s %s\n' % (FG_BLUE, i['type'], FG_RESET, i['domain'], info))
			display_csv(
			'%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' % (i.get('type'), i.get('domain'), i.get('a', ''),
			i.get('aaaa', ''), i.get('mx', ''), i.get('ns', ''), i.get('country', ''),
			i.get('created', ''), i.get('updated', ''), str(i.get('ssdeep', '')))
			)

	display(FG_RESET + ST_RESET)

	return 0

if __name__ == '__main__':
	main()
