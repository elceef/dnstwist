from setuptools import setup
import dnstwist

setup(
	name='dnstwist',
	version=dnstwist.__version__,
	author='Marcin Ulikowski',
	author_email='marcin@ulikowski.pl',
	description='Domain name permutation engine for detecting homograph phishing attacks, typo squatting, and brand impersonation',
	long_description='Project website: https://github.com/elceef/dnstwist',
	url='https://github.com/elceef/dnstwist',
	py_modules=['dnstwist'],
	entry_points={
		'console_scripts': ['dnstwist=dnstwist:main']
	},
	classifiers=[
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: Apache Software License',
		'Operating System :: OS Independent',
	],
)
