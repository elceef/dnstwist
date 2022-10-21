#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from queue import Queue
from uuid import uuid4
from time import time

from flask import Flask, request, jsonify, send_from_directory

import dnstwist

try:
	import idna.codec
except ImportError:
	pass


PORT = int(os.environ.get('PORT', 8000))
HOST= os.environ.get('HOST', '127.0.0.1')
THREADS = int(os.environ.get('THREADS', dnstwist.THREAD_COUNT_DEFAULT))
NAMESERVER = os.environ.get('NAMESERVER')
SESSION_TTL = int(os.environ.get('SESSION_TTL', 300))
SESSION_MAX = int(os.environ.get('SESSION_MAX', 20))
WEBAPP_HTML = os.environ.get('WEBAPP_HTML', 'webapp.html')
WEBAPP_DIR = os.environ.get('WEBAPP_DIR', os.path.dirname(__file__))

DICTIONARY = ('auth', 'account', 'confirm', 'connect', 'enroll', 'http', 'https', 'info', 'login', 'mail', 'my',
	'online', 'payment', 'portal', 'recovery', 'register', 'ssl', 'safe', 'secure', 'signin', 'signup', 'support',
	'update', 'user', 'verify', 'verification', 'web', 'www')
TLD_DICTIONARY = ('com', 'net', 'org', 'info', 'cn', 'co', 'eu', 'de', 'uk', 'pw', 'ga', 'gq', 'tk', 'ml', 'cf',
	'app', 'biz', 'top', 'xyz', 'online', 'site', 'live')


sessions = []
app = Flask(__name__)


class Session():
	def __init__(self, url, nameserver=None, thread_count=THREADS):
		self.id = str(uuid4())
		self.timestamp = int(time())
		self.url = dnstwist.UrlParser(url)
		self.nameserver = nameserver
		self.thread_count = thread_count
		self.jobs = Queue()
		self.threads = []
		fuzz = dnstwist.Fuzzer(self.url.domain, dictionary=DICTIONARY, tld_dictionary=TLD_DICTIONARY)
		fuzz.generate()
		self.permutations = fuzz.permutations()

	def scan(self):
		for domain in self.permutations:
			self.jobs.put(domain)
		for _ in range(self.thread_count):
			worker = dnstwist.Scanner(self.jobs)
			worker.daemon = True
			worker.option_extdns = True
			worker.option_geoip = True
			if self.nameserver:
				worker.nameservers = [self.nameserver]
			worker.start()
			self.threads.append(worker)

	def stop(self):
		self.jobs.queue.clear()
		for worker in self.threads:
			worker.stop()
		for worker in self.threads:
			worker.join()
		self.threads.clear()

	def domains(self):
		domains = [x for x in self.permutations.copy() if x.is_registered()]
		def _idna(item):
			try:
				item['domain'] = item['domain'].encode().decode('idna')
			except Exception:
				pass
			return item
		return sorted(map(_idna, domains))

	def status(self):
		if self.jobs.empty():
			self.stop()
		total = len(self.permutations)
		remaining = max(self.jobs.qsize(), len(self.threads))
		complete = total - remaining
		registered = sum([1 for x in self.permutations if x.is_registered()])
		return {
			'id': self.id,
			'timestamp': self.timestamp,
			'url': self.url.full_uri(),
			'total': total,
			'complete': complete,
			'remaining': remaining,
			'registered': registered
			}

	def csv(self):
		return dnstwist.Format([x for x in self.permutations if x.is_registered()]).csv()

	def json(self):
		return dnstwist.Format([x for x in self.permutations if x.is_registered()]).json()

	def list(self):
		return dnstwist.Format(self.permutations).list()


@app.route('/')
def root():
	return send_from_directory(WEBAPP_DIR, WEBAPP_HTML)


@app.route('/api/scans', methods=['POST'])
def api_scan():
	for s in sessions:
		status = s.status()
		if status['remaining'] == 0 and (status['timestamp'] + SESSION_TTL) < time():
			sessions.remove(s)
	if len(sessions) >= SESSION_MAX:
		return jsonify({'message': 'Too many scan sessions - please retry in a minute'}), 500
	if 'url' not in request.json:
		return jsonify({'message': 'Invalid request'}), 400
	_, domain, _ = dnstwist.domain_tld(request.json['url'])
	if len(domain) > 15:
		return jsonify({'message': 'Domain name is too long'}), 400
	try:
		session = Session(request.json.get('url'), nameserver=NAMESERVER)
	except Exception as err:
		return jsonify({'message': 'Invalid domain name'}), 400
	else:
		session.scan()
		sessions.append(session)
	return jsonify(session.status()), 201


@app.route('/api/scans/<sid>')
def api_status(sid):
	for s in sessions:
		if s.id == sid:
			return jsonify(s.status())
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/domains')
def api_domains(sid):
	for s in sessions:
		if s.id == sid:
			return jsonify(s.domains())
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/csv')
def api_csv(sid):
	for s in sessions:
		if s.id == sid:
			return s.csv(), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=dnstwist.csv'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/json')
def api_json(sid):
	for s in sessions:
		if s.id == sid:
			return s.json(), 200, {'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename=dnstwist.json'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/list')
def api_list(sid):
	for s in sessions:
		if s.id == sid:
			return s.list(), 200, {'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=dnstwist.txt'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/stop', methods=['POST'])
def api_stop(sid):
	for s in sessions:
		if s.id == sid:
			s.stop()
			return jsonify({})
	return jsonify({'message': 'Scan session not found'}), 404


if __name__ == '__main__':
	app.run(host=HOST, port=PORT)
