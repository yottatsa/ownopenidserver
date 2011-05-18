#!/usr/bin/env python

from distutils.core import setup

setup(
        name='openidserver',
        author='Vladimir S Eremin (aka yottatsa)',
        author_email='me@yottatsa.name',
        url='http://ownopenidserver.com/',
        version='1.0',
        scripts=['scripts/openidserver-conf'],
        packages=['openidserver'],
        data_files=[
                ('/usr/share/openidserver/templates', [
                        'openidserver/templates/base.html',
                        'openidserver/templates/login.html',
                        'openidserver/templates/verify.html',
                        'openidserver/templates/password.html',
                        'openidserver/templates/trusted.html',
                        'openidserver/templates/trusted_confirm.html',
                    ]),
                ('/usr/lib/cgi-bin', [
                        'scripts/openidserver.cgi',
                        'scripts/openidserver.fcgi',
                    ]),
                ('/etc/apache2/conf.d', [
                        'conf/apache2/openidserver.conf',
                    ]),
                ('/etc/lighttpd/conf-available', [
                        'conf/lighttpd/20-openidserver-fastcgi.conf',
                    ]),
                ('/usr/share/doc/openidserver', [
                        'README.md',
                        'COPYING.gz',
                        'conf/nginx/nginx-config.txt',
                    ]),
            ],
)
