#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Tests for the deferred scan queue (Phase 1) in webapp.py.

Background dispatcher/janitor threads are disabled (WEBAPP_START_THREADS=0) so
promotion can be driven deterministically via dispatch_once(). Session.scan is
replaced with a fake that avoids real DNS while still exercising the state
machine and capacity accounting.
'''

import os

os.environ['WEBAPP_START_THREADS'] = '0'

import pytest

import webapp


class DummyWorker:
	'''Stands in for a dnstwist.Scanner thread so Session.stop() works offline.'''
	def stop(self):
		pass

	def join(self):
		pass


def fake_scan(self):
	'''Mark the session running without touching the network.'''
	self.state = 'running'
	self.threads = [DummyWorker()]


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
	webapp.sessions.clear()
	webapp.pending.clear()
	monkeypatch.setattr(webapp.Session, 'scan', fake_scan)
	yield
	webapp.sessions.clear()
	webapp.pending.clear()


@pytest.fixture
def client():
	webapp.app.config['TESTING'] = True
	return webapp.app.test_client()


def _enqueue(url='example.com'):
	'''Create + enqueue a session the way api_scan does, without HTTP.'''
	s = webapp.Session(url)
	with webapp.lock:
		webapp.sessions.append(s)
		webapp.pending.append(s)
	return s


# --- backward compatibility -------------------------------------------------

def test_queued_status_reports_no_progress():
	s = webapp.Session('example.com')
	st = s.status()
	assert st['state'] == 'queued'
	assert st['total'] > 0
	assert st['complete'] == 0
	assert st['remaining'] == st['total']
	# Existing clients rely on these keys; they must all still be present.
	for key in ('id', 'timestamp', 'url', 'domain', 'total', 'complete', 'remaining', 'registered'):
		assert key in st


def test_post_enqueues_without_starting_scan(client):
	resp = client.post('/api/scans', json={'url': 'example.com'})
	assert resp.status_code == 201
	body = resp.get_json()
	assert body['state'] == 'queued'
	assert len(webapp.pending) == 1
	assert len(webapp.sessions) == 1
	# Not started: no worker threads yet.
	assert webapp.sessions[0].threads == []


# --- capacity / dispatcher --------------------------------------------------

def test_dispatch_promotes_up_to_capacity_fifo(monkeypatch):
	monkeypatch.setattr(webapp, 'MAX_CONCURRENT', 3)
	created = [_enqueue('example.com') for _ in range(5)]

	webapp.dispatch_once()

	running = [s for s in webapp.sessions if s.state == 'running']
	queued = list(webapp.pending)
	assert len(running) == 3
	assert len(queued) == 2
	# FIFO: the first three created were promoted, the last two remain queued.
	assert running == created[:3]
	assert queued == created[3:]


def test_dispatch_never_exceeds_capacity(monkeypatch):
	monkeypatch.setattr(webapp, 'MAX_CONCURRENT', 2)
	for _ in range(4):
		_enqueue('example.com')

	webapp.dispatch_once()
	webapp.dispatch_once()  # idempotent while at capacity

	assert sum(1 for s in webapp.sessions if s.state == 'running') == 2
	assert len(webapp.pending) == 2


def test_finished_scan_frees_a_slot(monkeypatch):
	monkeypatch.setattr(webapp, 'MAX_CONCURRENT', 2)
	for _ in range(3):
		_enqueue('example.com')

	webapp.dispatch_once()
	assert len(webapp.pending) == 1

	# Complete one running scan; a slot should free up for the queued one.
	running = next(s for s in webapp.sessions if s.state == 'running')
	running.stop()
	assert running.state == 'done'

	webapp.dispatch_once()
	assert sum(1 for s in webapp.sessions if s.state == 'running') == 2
	assert len(webapp.pending) == 0


# --- state transitions ------------------------------------------------------

def test_stopped_while_queued_is_not_resurrected(monkeypatch):
	monkeypatch.setattr(webapp, 'MAX_CONCURRENT', 5)
	s = _enqueue('example.com')
	# Stop it before the dispatcher ever promotes it.
	s.stop()
	assert s.state == 'done'

	webapp.dispatch_once()

	# It must not be promoted back to running.
	assert s.state == 'done'
	assert s.threads == []


def test_state_transitions_queued_running_done(monkeypatch):
	monkeypatch.setattr(webapp, 'MAX_CONCURRENT', 1)
	s = _enqueue('example.com')
	assert s.state == 'queued'

	webapp.dispatch_once()
	assert s.state == 'running'

	s.stop()
	assert s.state == 'done'


# --- backpressure -----------------------------------------------------------

def test_burst_never_returns_500_and_429_past_max_queue(client, monkeypatch):
	monkeypatch.setattr(webapp, 'MAX_QUEUE', 3)
	# Threads are disabled, so nothing drains: the queue fills to MAX_QUEUE.
	statuses = [client.post('/api/scans', json={'url': 'example.com'}).status_code for _ in range(3)]
	assert statuses == [201, 201, 201]
	assert 500 not in statuses

	resp = client.post('/api/scans', json={'url': 'example.com'})
	assert resp.status_code == 429
	assert resp.headers.get('Retry-After') == '60'
	assert resp.get_json()['message']


def test_bad_request_still_validated(client):
	assert client.post('/api/scans', json={}).status_code == 400
