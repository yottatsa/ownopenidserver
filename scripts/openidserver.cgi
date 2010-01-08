#!/usr/bin/env python

from openidserver import openidserver
from openidserver.localsettings import *


openidserver.openid_store = openidserver.openid.store.filestore.FileOpenIDStore(ROOT_STORE)

openidserver.trust_root_store = openidserver.TrustRootStore(TRUST_ROOT_STORE)

sessions_store = openidserver.web.session.DiskStore(SESSION_STORE)
openidserver.session = openidserver.web.session.Session(openidserver.app, sessions_store)

openidserver.password_manager = openidserver.PasswordManager(PASSWORD_STORE)

openidserver.render = openidserver.web.contrib.template.render_jinja(TEMPLATES)

openidserver.web.config.debug = False
openidserver.server = openidserver.OpenIDServer(
        openidserver.openid_store,
        openidserver.trust_root_store
    )


from flup.server.cgi import WSGIServer
WSGIServer(openidserver.app.wsgifunc()).run()
