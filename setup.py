#!/usr/bin/env python

from distutils.core import setup

setup(
        name='openidserver',
        author='Vladimir S Eremin (aka hidded)',
        author_email='me@hidded.name',
        url='http://github.com/hidded/ownopenidserver/',
        version='0.9',
        scripts=['scripts/openidserver-conf'],
        package_dir={'openidserver': ''},
        packages=['openidserver'],
        data_files=[
                ('/usr/share/openidserver/templates', [
                        'templates/base.html',
                        'templates/login.html',
                        'templates/verify.html',
                        'templates/password.html',
                        'templates/trusted.html',
                        'templates/trusted_confirm.html',
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
