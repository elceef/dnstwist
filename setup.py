import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='dnstwist',
    version='1.02',
    author="Marcin Ulikowski",
    author_email="marcin@ulikowski.pl",
    description="See what sort of trouble users can get in trying to type your domain name. Find similar-looking domains that adversaries can use to attack you.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/elceef/dnstwist",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)