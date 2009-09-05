#!/usr/bin/env python

from distutils.core import setup

setup(
        name='openidserver',
        author='Vladimir S Eremin (aka hidded)',
        author_email='me@hidded.name',
        url='http://github.com/hidded/ownopenidserver/',
        version='0.1.0',
        scripts=['scripts/openidserver-conf'],
        package_dir={'openidserver': ''},
        packages=['openidserver'],
        data_files=[
                ('/usr/share/openidserver/templates', [
                        'templates/base.html',
                        'templates/login.html',
                        'templates/verify.html',
                        'templates/password.html',
                    ]),
                ('/usr/lib/cgi-bin', [
                        'scripts/openidserver.cgi',
                    ]),
                ('/usr/share/doc/openidserver', [
                        'README.md',
                        'COPYING.gz',
                    ]),
            ],
)
