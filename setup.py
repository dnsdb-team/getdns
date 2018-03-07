from setuptools import find_packages, setup

PACKAGE = "getdns"
NAME = "dnsdb-getdns"
DESCRIPTION = "Query DNS records from dnsdb.io"
AUTHOR = "DnsDB Team"
AUTHOR_EMAIL = "team@dnsdb.io"
URL = "http://getdns.dnsdb.io"
VERSION = __import__(PACKAGE).__version__

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=open('README.rst').read(),
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license="BSD License",
    url=URL,
    packages=find_packages(exclude=['docs', 'tests']),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: Chinese (Simplified)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={
        'console_scripts': [
            'getdns=getdns:main',
        ]
    },
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, <4',
    zip_safe=False,
    install_requires=[
        "colorama",
        "dnsdb_python_sdk>=0.1.2b2",
        "iptools",
        "setuptools",
        "progress",
    ],
)
