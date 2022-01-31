from setuptools import setup
import dnstwist

with open('requirements.txt') as f:
	full = [line for line in f.read().splitlines() if not line.startswith('#')]

setup(
	name='dnstwist',
	version=dnstwist.__version__,
	author='Marcin Ulikowski',
	author_email='marcin@ulikowski.pl',
	description='Domain name permutation engine for detecting homograph phishing attacks, typo squatting, and brand impersonation',
	long_description='Project website: https://github.com/elceef/dnstwist',
	url='https://github.com/elceef/dnstwist',
	license='ASL 2.0',
	py_modules=['dnstwist'],
	entry_points={
		'console_scripts': ['dnstwist=dnstwist:run']
	},
	install_requires=[],
	extras_require={
		'full': full
	},
	classifiers=[
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: Apache Software License',
		'Operating System :: OS Independent',
	],
)
