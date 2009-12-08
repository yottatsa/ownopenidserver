#!/usr/bin/env python

from openidserver import openidserver

openidserver.web.config.debug = False
openidserver.server = openidserver.OpenIDServer(
        openidserver.openid_store,
        openidserver.trust_root_store
    )
openidserver.app.run()
