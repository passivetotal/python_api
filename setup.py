#!/usr/bin/env python
import os
import re
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

# pylint: disable=locally-disabled, invalid-name
with open('passivetotal/_version.py', 'r') as fd:
    v_match = re.search(r'^VERSION\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE)
    __version__ = v_match.group(1) if v_match else 'no version'
# pylint: enable=locally-disabled, invalid-name

setup(
    name='passivetotal',
    version=__version__,
    description='Library for the RiskIQ PassiveTotal and Illuminate API',
    url="https://github.com/passivetotal/python_api",
    author="RiskIQ",
    author_email="admin@passivetotal.org",
    license="GPLv2",
    packages=find_packages(),
    install_requires=['requests', 'python-dateutil', 'future', 'tldextract'],
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    classifiers=[],
    entry_points={
        'console_scripts': [
            'pt-info = passivetotal.cli.info:main',
            'pt-config = passivetotal.cli.config:main',
            'pt-client = passivetotal.cli.client:main',
        ],
    },
    extras_require={
        'pandas': ['pandas']
    },
    package_data={
        'passivetotal': [],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=['threats', 'research', 'analysis'],
    download_url='https://github.com/passivetotal/python_api/archive/master.zip'
)
