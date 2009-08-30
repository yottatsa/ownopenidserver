#!/usr/bin/env python

from openidserver import *

web.config.debug = False
environ = os.environ
app.load(os.environ)
openid_server = openid.server.server.Server(openid_store,
        web.ctx.homedomain + web.url('/endpoint'))
server = OpenIDServer(openid_server, trust_root_store)
app.run()
