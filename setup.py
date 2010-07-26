#!/usr/bin/env python

from distutils.core import setup

setup(
        name='openidserver',
        author='Vladimir S Eremin (aka hidded)',
        author_email='me@hidded.name',
        url='http://github.com/hidded/ownopenidserver/',
        version='0.9',
        packages=['openidserver'],
        package_data = {
            'openidserver': [
                        'templates/base.html',
                        'templates/login.html',
                        'templates/verify.html',
                        'templates/password.html',
                        'templates/trusted.html',
                        'templates/trusted_confirm.html',
                    ],
            },
)
