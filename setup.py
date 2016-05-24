#!/usr/bin/env python
import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='passivetotal',
    version='1.0.25',
    description='Client for the PassiveTotal REST API',
    url="https://github.com/passivetotal/python_api",
    author="Research Team, passivetotal",
    author_email="admin@passivetotal.org",
    license="GPLv2",
    packages=find_packages(),
    install_requires=['requests', 'tabulate', 'stix', 'ez_setup', 'lxml',
                      'cybox', 'python-dateutil', 'dicttoxml', 'future'],
    long_description=read('README.rst'),
    classifiers=[],
    entry_points={
        'console_scripts': [
            'pt-info = passivetotal.cli.info:main',
            'pt-config = passivetotal.cli.config:main',
            'pt-client = passivetotal.cli.client:main',
        ],
    },
    package_data={
        'passivetotal': [],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=['threats', 'research', 'analysis'],
    download_url='https://github.com/passivetotal/python_api/archive/master.zip'
)
