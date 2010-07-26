#!/usr/bin/env python

from openidserver import openidserver, debiansettings

app = openidserver.init(
        debiansettings.ROOT_STORE,
        debiansettings.TRUST_ROOT_STORE,
        debiansettings.SESSION_STORE,
        debiansettings.PASSWORD_STORE,
        debiansettings.TEMPLATES
    )


import sys
from flup.server.fcgi_single import WSGIServer

args = sys.argv[1:]
if args:
    WSGIServer(app.wsgifunc(), bindAddress=openidserver.web.validaddr(args[0])).run()
else:
    WSGIServer(app.wsgifunc()).run()
