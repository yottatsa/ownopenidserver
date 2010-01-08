#!/usr/bin/env python

import sys
from openidserver import openidserver
from flup.server.fcgi_single import WSGIServer

openidserver.web.config.debug = False
openidserver.server = openidserver.OpenIDServer(
        openidserver.openid_store,
        openidserver.trust_root_store
    )

args = sys.argv[1:]
if args:
    WSGIServer(openidserver.app.wsgifunc(), bindAddress=openidserver.web.validaddr(args[0])).run()
else:
    WSGIServer(openidserver.app.wsgifunc()).run()
