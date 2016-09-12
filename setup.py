from setuptools import setup, find_packages

PACKAGE = "getdns"
NAME = "getdns"
DESCRIPTION = "Query DNS records from dnsdb.io"
AUTHOR = "DnsDB Team"
AUTHOR_EMAIL = "team@dnsdb.io"
URL = "http://getdns.dnsdb.io"
VERSION = __import__(PACKAGE).__version__

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license="BSD License",
    url=URL,
    packages=find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: Chinese (Simplified)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],
    entry_points={
        'console_scripts': [
            'getdns=getdns.getdns:main',
        ]
    },
    zip_safe=False,
    install_requires=['requests', ],
)
