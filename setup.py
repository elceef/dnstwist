import setuptools
from dnstwist import __version__ as version

with open('README.md', 'r') as fh:
	long_description = fh.read()

setuptools.setup(
	name='dnstwist',
	version=version,
	author='Marcin Ulikowski',
	author_email='marcin@ulikowski.pl',
	description='Domain name permutation engine for detecting homograph phishing attacks, typo squatting, and brand impersonation.',
	long_description=long_description,
	long_description_content_type='text/markdown',
	url='https://github.com/elceef/dnstwist',
	packages=setuptools.find_packages(),
	entry_points={
		'console_scripts': ['dnstwist=dnstwist:main']
	},
	classifiers=[
		'Programming Language :: Python :: 3',
		'License :: OSI Approved :: Apache Software License',
		'Operating System :: OS Independent',
	],
)
