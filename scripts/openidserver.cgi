#!/usr/bin/env python

from openidserver import openidserver
from flup.server.cgi import WSGIServer

openidserver.web.config.debug = False
openidserver.server = openidserver.OpenIDServer(
        openidserver.openid_store,
        openidserver.trust_root_store
    )

WSGIServer(openidserver.app.wsgifunc()).run()
