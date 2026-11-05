"""Regression tests: UTF-8 BOM in user-supplied word lists (-d/--dictionary, --tld).

A word-list file saved by a Windows editor usually starts with the UTF-8 BOM
(U+FEFF).  Opening such a file with encoding='utf-8' keeps the BOM glued to the
first line, so the first word / first TLD silently fails the input regex and is
dropped.  Opening it with encoding='utf-8-sig' strips the BOM and leaves every
line intact.

The tests drive the real CLI entry point ``dnstwist.run()`` with
``format='list'`` and the lightweight ``dictionary`` / ``tld-swap`` fuzzers,
then consume the returned records and the real stdout.

This module is deliberately free of import-time side effects: it does not patch
``socket`` and does not install a process-wide network guard.  Network isolation
belongs to the outer evidence runner, which installs it before the product is
imported, so importing this test can never leak a global patch into other suites.
"""

import io
import os
import signal
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

BOM = b'\xef\xbb\xbf'

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
	sys.path.insert(0, REPO_ROOT)

import dnstwist  # noqa: E402


class InputListTestCase(unittest.TestCase):

	def setUp(self):
		self._tmp = tempfile.TemporaryDirectory()
		self.addCleanup(self._tmp.cleanup)
		self._argv = list(sys.argv)
		self._signals = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
		self.addCleanup(self._restore_globals)

	def _restore_globals(self):
		"""Undo the global state that dnstwist.run() changes (argv, signal handlers)."""
		sys.argv[:] = self._argv
		for sig, handler in self._signals.items():
			signal.signal(sig, handler)

	def _write_list(self, name, lines, bom=False, newline='\n'):
		path = os.path.join(self._tmp.name, name)
		data = newline.join(lines) + newline
		with open(path, 'wb') as handle:
			handle.write((BOM if bom else b'') + data.encode('utf-8'))
		return path

	def _run(self, **kwargs):
		return dnstwist.run(format='list', **kwargs)

	@staticmethod
	def _domains(records):
		return {record['domain'] for record in records}

	@staticmethod
	def _pairs(records):
		return sorted((record['fuzzer'], record['domain']) for record in records)

	def test_dictionary_bom_keeps_first_and_later_words(self):
		path = self._write_list('dictionary-bom.txt', ['alpha', 'beta'], bom=True)
		domains = self._domains(self._run(domain='example.com', fuzzers='dictionary', dictionary=path))
		self.assertIn('examplealpha.com', domains, 'first word lost to the BOM')
		self.assertIn('examplebeta.com', domains)

	def test_dictionary_without_bom_keeps_first_and_later_words(self):
		path = self._write_list('dictionary-plain.txt', ['alpha', 'beta'])
		domains = self._domains(self._run(domain='example.com', fuzzers='dictionary', dictionary=path))
		self.assertIn('examplealpha.com', domains)
		self.assertIn('examplebeta.com', domains)

	def test_tld_bom_keeps_first_and_later_tlds(self):
		path = self._write_list('tld-bom.txt', ['museum', 'network'], bom=True)
		domains = self._domains(self._run(domain='example.com', fuzzers='tld-swap', tld=path))
		self.assertIn('example.museum', domains, 'first TLD lost to the BOM')
		self.assertIn('example.network', domains)

	def test_tld_without_bom_keeps_first_and_later_tlds(self):
		path = self._write_list('tld-plain.txt', ['museum', 'network'])
		domains = self._domains(self._run(domain='example.com', fuzzers='tld-swap', tld=path))
		self.assertIn('example.museum', domains)
		self.assertIn('example.network', domains)

	def test_bom_and_plain_lists_are_equivalent(self):
		with_bom = self._write_list('dictionary-bom.txt', ['alpha', 'beta'], bom=True)
		plain = self._write_list('dictionary-plain.txt', ['alpha', 'beta'])
		bom_records = self._run(domain='example.com', fuzzers='dictionary', dictionary=with_bom)
		plain_records = self._run(domain='example.com', fuzzers='dictionary', dictionary=plain)
		self.assertEqual(self._pairs(plain_records), self._pairs(bom_records))
		self.assertTrue(bom_records)

	def test_uppercase_crlf_bom_dictionary(self):
		path = self._write_list('dictionary-bom-crlf.txt', ['ALPHA', 'BETA'], bom=True, newline='\r\n')
		domains = self._domains(self._run(domain='example.com', fuzzers='dictionary', dictionary=path))
		self.assertIn('examplealpha.com', domains)
		self.assertIn('examplebeta.com', domains)

	def test_dictionary_and_tld_together_with_bom(self):
		dictionary = self._write_list('dictionary-bom.txt', ['alpha', 'gamma'], bom=True)
		tld = self._write_list('tld-bom.txt', ['museum', 'network'], bom=True)
		records = self._run(domain='example.com', fuzzers='dictionary,tld-swap', dictionary=dictionary, tld=tld)
		domains = self._domains(records)
		self.assertIn('examplealpha.com', domains, 'first word lost to the BOM')
		self.assertIn('example.museum', domains, 'first TLD lost to the BOM')
		self.assertIn('examplegamma.com', domains)
		self.assertIn('example.network', domains)
		self.assertEqual({'dictionary', 'tld-swap'}, {record['fuzzer'] for record in records})

	def test_list_output_consumer_sees_every_domain(self):
		path = self._write_list('dictionary-bom.txt', ['alpha', 'beta'], bom=True)
		buffer = io.StringIO()
		with redirect_stdout(buffer):
			records = self._run(domain='example.com', fuzzers='dictionary', dictionary=path)
		lines = [line for line in buffer.getvalue().splitlines() if line]
		self.assertEqual(sorted(self._domains(records)), sorted(lines))
		self.assertIn('examplealpha.com', lines)


if __name__ == '__main__':
	unittest.main()
