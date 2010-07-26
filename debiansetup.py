#!/usr/bin/env python

from distutils.core import setup

setup(
        name='openidserver',
        author='Vladimir S Eremin (aka hidded)',
        author_email='me@hidded.name',
        url='http://github.com/hidded/ownopenidserver/',
        version='0.9',
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
