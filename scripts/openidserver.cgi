#!/usr/bin/env python

from openidserver import openidserver, debiansettings

app = openidserver.init(
        debiansettings.ROOT_STORE,
        debiansettings.TRUST_ROOT_STORE,
        debiansettings.SESSION_STORE,
        debiansettings.PASSWORD_STORE,
        debiansettings.TEMPLATES
    )

from flup.server.cgi import WSGIServer
WSGIServer(app.wsgifunc()).run()
