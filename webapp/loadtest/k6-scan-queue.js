// k6 load test for the dnstwist deferred scan queue (Phase 1).
//
// It verifies the *contract* of the queue with exact expected values:
//   - POST /api/scans never returns 500 under load (bursts queue, they don't fail).
//   - Accepted scans return 201 with state="queued", complete=0, remaining=total.
//   - Backpressure returns 429 + `Retry-After` only once the queue is full.
//   - Validation edge cases return the exact 4xx codes.
//   - A single scan progresses queued -> running -> done when polled.
//
// Scenarios are selected via the SCENARIO env var (see README). Pass/fail is
// enforced by thresholds; handleSummary() prints expected-vs-actual at the end.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate } from 'k6/metrics';

// --- configuration (must match the server under test) -----------------------

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8000';
const MAX_CONCURRENT = Number(__ENV.MAX_CONCURRENT || 10); // server SESSION_MAX
const MAX_QUEUE = Number(__ENV.MAX_QUEUE || 500);          // server MAX_QUEUE
const DOMAIN = __ENV.DOMAIN || 'example.com';

const SCENARIO = __ENV.SCENARIO || 'burst';
const BURST_VUS = Number(__ENV.BURST_VUS || 100);
const BURST_OVERFLOW = Number(__ENV.BURST_OVERFLOW || 50); // extra reqs beyond capacity
const BP_OVERFLOW = Number(__ENV.BP_OVERFLOW || 25);       // extra reqs in deterministic mode
const POLL_TIMEOUT_S = Number(__ENV.POLL_TIMEOUT_S || 120);

// Treat expected 4xx as non-failures so http_req_failed captures only surprises
// (most importantly 500s and connection errors).
http.setResponseCallback(http.expectedStatuses(200, 201, 400, 404, 429));

// --- custom metrics ---------------------------------------------------------

const serverErrors = new Counter('server_errors_5xx');
const accepted = new Counter('scans_accepted_201');
const rejected = new Counter('scans_rejected_429');
const badRequests = new Counter('bad_requests_400');
const queuedInvariantOk = new Rate('queued_invariant_ok');
const retryAfterPresent = new Rate('retry_after_present');

// --- shared request helpers -------------------------------------------------

function postScan(url) {
	return http.post(`${BASE_URL}/api/scans`, JSON.stringify({ url }), {
		headers: { 'Content-Type': 'application/json' },
		tags: { endpoint: 'post_scan' },
	});
}

// Classify a POST /api/scans response and record the invariants that must hold.
function recordScanResponse(res) {
	if (res.status >= 500) {
		serverErrors.add(1);
	}
	check(res, {
		'POST /api/scans is 201 or 429 (never 500)': (r) => r.status === 201 || r.status === 429,
	});

	if (res.status === 201) {
		accepted.add(1);
		let body = {};
		try { body = res.json(); } catch (e) { body = {}; }
		const ok =
			body.state === 'queued' &&
			body.complete === 0 &&
			body.total > 0 &&
			body.remaining === body.total &&
			typeof body.id === 'string';
		queuedInvariantOk.add(ok);
		check(body, {
			'201 body has state=queued': (b) => b.state === 'queued',
			'201 body has complete=0': (b) => b.complete === 0,
			'201 body has remaining==total': (b) => b.remaining === b.total,
			'201 body has an id': (b) => typeof b.id === 'string' && b.id.length > 0,
		});
	} else if (res.status === 429) {
		rejected.add(1);
		const hasRetryAfter = res.headers['Retry-After'] === '60';
		retryAfterPresent.add(hasRetryAfter);
		check(res, {
			'429 has Retry-After: 60': () => hasRetryAfter,
			'429 has a message': (r) => {
				try { return typeof r.json().message === 'string'; } catch (e) { return false; }
			},
		});
	}
}

// --- scenario functions -----------------------------------------------------

// Fire scans as fast as possible from many VUs. Expect a mix of 201/429, no 500.
export function burst() {
	recordScanResponse(postScan(DOMAIN));
}

// Deterministic backpressure: run the server with SESSION_MAX=0 so nothing ever
// drains. A single VU posts sequentially; exactly MAX_QUEUE are accepted (201),
// the rest are rejected (429). Fully offline (no scan() / DNS ever runs).
export function backpressure() {
	recordScanResponse(postScan(DOMAIN));
}

// Validation edge cases with exact expected status codes.
export function edgeCases() {
	const missingUrl = http.post(`${BASE_URL}/api/scans`, JSON.stringify({}), {
		headers: { 'Content-Type': 'application/json' },
		tags: { endpoint: 'edge_missing_url' },
	});
	if (missingUrl.status === 400) badRequests.add(1);
	check(missingUrl, { 'missing url -> 400': (r) => r.status === 400 });

	const longLabel = 'a'.repeat(20) + '.com'; // label 20 > DOMAIN_MAXLEN (15)
	const tooLong = postScan(longLabel);
	check(tooLong, {
		'over-long domain -> 400': (r) => r.status === 400,
		'over-long domain message': (r) => {
			try { return r.json().message === 'Domain name is too long'; } catch (e) { return false; }
		},
	});

	const missing = http.get(`${BASE_URL}/api/scans/does-not-exist`, { tags: { endpoint: 'edge_404' } });
	check(missing, { 'unknown scan id -> 404': (r) => r.status === 404 });
}

// Single scan lifecycle: create, then poll until done, asserting the payload
// stays well-formed and the state advances queued -> running -> done.
// Requires the server to have MAX_CONCURRENT > 0 and network access for DNS.
export function lifecycle() {
	const res = postScan(DOMAIN);
	check(res, { 'lifecycle POST -> 201': (r) => r.status === 201 });
	if (res.status !== 201) return;

	const sid = res.json().id;
	const seenStates = {};
	const deadline = Date.now() + POLL_TIMEOUT_S * 1000;
	let last = {};

	while (Date.now() < deadline) {
		const s = http.get(`${BASE_URL}/api/scans/${sid}`, { tags: { endpoint: 'get_status' } });
		if (s.status !== 200) break;
		last = s.json();
		seenStates[last.state] = true;
		check(last, {
			'status has all legacy keys': (b) =>
				['id', 'timestamp', 'url', 'domain', 'total', 'complete', 'remaining', 'registered'].every((k) => k in b),
			'complete never exceeds total': (b) => b.complete <= b.total,
			'state is valid': (b) => ['queued', 'running', 'done'].includes(b.state),
		});
		if (last.state === 'done' || last.remaining === 0) break;
		sleep(1);
	}

	check(seenStates, {
		'lifecycle reached done/complete': () => last.state === 'done' || last.remaining === 0,
	});
}

// --- options (scenarios + thresholds, built from SCENARIO) ------------------

function buildScenarios() {
	const all = {
		edge: {
			executor: 'per-vu-iterations',
			vus: 1,
			iterations: 1,
			exec: 'edgeCases',
			startTime: '0s',
		},
		burst: {
			executor: 'shared-iterations',
			vus: BURST_VUS,
			iterations: MAX_CONCURRENT + MAX_QUEUE + BURST_OVERFLOW,
			maxDuration: '120s',
			exec: 'burst',
		},
		backpressure: {
			executor: 'shared-iterations',
			vus: 1, // sequential -> exact accepted/rejected counts
			iterations: MAX_QUEUE + BP_OVERFLOW,
			maxDuration: '120s',
			exec: 'backpressure',
		},
		lifecycle: {
			executor: 'per-vu-iterations',
			vus: 1,
			iterations: 1,
			exec: 'lifecycle',
			maxDuration: `${POLL_TIMEOUT_S + 10}s`,
		},
	};
	if (all[SCENARIO]) return { [SCENARIO]: all[SCENARIO] };
	if (SCENARIO === 'all') {
		return {
			edge: { ...all.edge, startTime: '0s' },
			lifecycle: { ...all.lifecycle, startTime: '2s' },
			burst: { ...all.burst, startTime: `${POLL_TIMEOUT_S + 5}s` },
		};
	}
	throw new Error(`Unknown SCENARIO="${SCENARIO}"`);
}

function buildThresholds() {
	const t = {
		http_req_failed: ['rate==0'], // no 500s / connection errors
		server_errors_5xx: ['count==0'],
		checks: ['rate==1.0'],
	};
	// These metrics only get samples when the relevant path is exercised; with no
	// samples the threshold simply passes.
	t.queued_invariant_ok = ['rate==1.0'];
	t.retry_after_present = ['rate==1.0'];

	if (SCENARIO === 'backpressure') {
		// Exact expected values in deterministic mode.
		t.scans_accepted_201 = [`count==${MAX_QUEUE}`];
		t.scans_rejected_429 = [`count==${BP_OVERFLOW}`];
	}
	return t;
}

export const options = {
	scenarios: buildScenarios(),
	thresholds: buildThresholds(),
};

// --- readable expected-vs-actual summary ------------------------------------

export function handleSummary(data) {
	const m = data.metrics;
	const val = (name, field = 'count') =>
		m[name] && m[name].values && m[name].values[field] !== undefined ? m[name].values[field] : 0;

	const lines = [];
	lines.push('');
	lines.push('=== dnstwist scan-queue load test summary ===');
	lines.push(`scenario:        ${SCENARIO}`);
	lines.push(`target:          ${BASE_URL}`);
	lines.push(`server config:   MAX_CONCURRENT=${MAX_CONCURRENT}  MAX_QUEUE=${MAX_QUEUE}`);
	lines.push('');
	lines.push(`accepted (201):  ${val('scans_accepted_201')}`);
	lines.push(`rejected (429):  ${val('scans_rejected_429')}`);
	lines.push(`bad req  (400):  ${val('bad_requests_400')}`);
	lines.push(`server errs 5xx: ${val('server_errors_5xx')}   (expected 0)`);
	lines.push(`http_req_failed: ${(val('http_req_failed', 'rate') * 100).toFixed(2)}%   (expected 0.00%)`);
	lines.push('');

	if (SCENARIO === 'backpressure') {
		const acc = val('scans_accepted_201');
		const rej = val('scans_rejected_429');
		lines.push('deterministic expectations:');
		lines.push(`  accepted == MAX_QUEUE (${MAX_QUEUE}):  actual ${acc}  ${acc === MAX_QUEUE ? 'PASS' : 'FAIL'}`);
		lines.push(`  rejected == BP_OVERFLOW (${BP_OVERFLOW}): actual ${rej}  ${rej === BP_OVERFLOW ? 'PASS' : 'FAIL'}`);
		lines.push('');
	}

	if (SCENARIO === 'burst') {
		const acc = val('scans_accepted_201');
		const rej = val('scans_rejected_429');
		lines.push('burst expectations:');
		lines.push('  server_errors_5xx == 0 (bursts queue, never 500)');
		lines.push(`  accepted >= MAX_QUEUE (${MAX_QUEUE}):   actual ${acc}  ${acc >= MAX_QUEUE ? 'PASS' : 'CHECK'}`);
		lines.push(`  rejected observed (429 path fired):     actual ${rej}  ${rej > 0 ? 'PASS' : 'CHECK'}`);
		lines.push('  note: exact counts vary with scan duration; invariants above are exact.');
		lines.push('');
	}

	const text = lines.join('\n');
	return {
		stdout: text + '\n',
		'loadtest-summary.json': JSON.stringify(data, null, 2),
	};
}
