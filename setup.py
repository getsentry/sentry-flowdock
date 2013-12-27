#!/usr/bin/env python
"""
sentry-flowdock
===============

An extension for Sentry which integrates with Flowdock. It will forwards
notifications to a flowdock room.

:copyright: (c) 2011 by the Linovia, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""
from setuptools import setup, find_packages


tests_require = [
]

install_requires = [
    'sentry>=4.6.0',
]

setup(
    name='sentry-flowdock',
    version='0.1.0',
    author='David Cramer',
    author_email='dcramer@gmail.com',
    url='http://github.com/getsentry/sentry-flowdock',
    description='A Sentry extension which integrates with Flowdock.',
    long_description=__doc__,
    license='BSD',
    packages=find_packages(exclude=['tests']),
    zip_safe=False,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={'test': tests_require},
    include_package_data=True,
    entry_points={
        'sentry.apps': [
            'sentry_flowdock = sentry_flowdock ',
        ],
        'sentry.plugins': [
            'flowdock = sentry_flowdock.models:FlowdockMessage',
        ],
    },
    classifiers=[
        'Framework :: Django',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Topic :: Software Development'
    ],
)
