#!/usr/bin/env python

from openidserver import openidserver

openidserver.web.config.debug = False
openidserver.app.load(openidserver.os.environ)
openidserver.openid_server = openidserver.openid.server.server.Server(
        openidserver.openid_store,
        openidserver.web.ctx.homedomain + openidserver.web.url('/endpoint')
    )
openidserver.server = openidserver.OpenIDServer(
        openidserver.openid_server,
        openidserver.trust_root_store
    )
openidserver.app.run()
