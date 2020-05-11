#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import environ
from queue import Queue

from flask import Flask, request, jsonify, send_from_directory

from dnstwist import UrlParser, DomainFuzz, DomainThread, THREAD_COUNT_DEFAULT


API_PORT = int(environ.get('HTTP_PORT', 8000))
API_HOST= environ.get('API_HOST', '127.0.0.1')
THREAD_COUNT = int(environ.get('THREADS', THREAD_COUNT_DEFAULT))
NAMESERVER = environ.get('NAMESERVER')
WEBAPP_HTML = 'webapp.html'


session = None
app = Flask(__name__)


class Session():
	def __init__(self, url, nameserver=None, thread_count=THREAD_COUNT):
		self.url = UrlParser(url)
		self.nameserver = nameserver
		self.thread_count = thread_count
		self.jobs = Queue()
		self.threads = []
		fuzz = DomainFuzz(self.url.domain)
		fuzz.generate()
		self.permutations = fuzz.domains

	def scan(self):
		for i in range(len(self.permutations)):
			self.jobs.put(self.permutations[i])
		for _ in range(self.thread_count):
			worker = DomainThread(self.jobs)
			worker.setDaemon(True)
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

	def status(self):
		total = len(self.permutations)
		remaining = self.jobs.qsize()
		complete = total - remaining
		return {
			'url': self.url.full_uri(),
			'total': total,
			'complete': complete,
			'remaining': remaining
			}

	def domains(self):
		return [x for x in self.permutations if len(x) > 2]


@app.route('/')
def root():
	return send_from_directory('.', WEBAPP_HTML)


@app.route('/api/scan', methods=['POST'])
def api_scan():
	global session
	if session:
		if session.status().get('remaining', 0) > 0:
			return jsonify({'message': 'Another scan session is running'}), 500
	if 'url' not in request.json:
		return jsonify({'message': 'Invalid request'}), 400

	try:
		session = Session(request.json.get('url'), nameserver=NAMESERVER, thread_count=THREAD_COUNT)
	except Exception as err:
		return jsonify({'message': 'Invalid domain name'}), 400

	session.scan()

	return jsonify({})


@app.route('/api/status')
def api_status():
	return jsonify(session.status() if session else {})


@app.route('/api/domains')
def api_domains():
	return jsonify(session.domains() if session else [])


@app.route('/api/stop', methods=['POST'])
def api_stop():
	if session:
		session.stop()
	return jsonify({})


if __name__ == '__main__':
	app.run(host=API_HOST, port=API_PORT)
