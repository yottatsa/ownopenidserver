#!/usr/bin/env python

ROOT_STORE = 'sstore'
TEMPLATES = 'templates'


import os, os.path
import urlparse
import urllib
import md5, sys, random

import web, web.http, web.form, web.session, web.contrib.template

import openid.server.server, openid.store.filestore


class TrustRootStore(object):
    """
    Store and lookup over trust root list
    """


    def __init__(self, directory):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)


    def _get_filename(self, url):
        """
        Encode url to filename
        TODO: doctest
        """

        url = urlparse.urlparse(url)
        filename = urllib.quote('__'.join(tuple(url)).replace('/', '_'))

        return os.path.join(self.directory, filename)


    def add(self, url):
        return os.symlink(url, self._get_filename(url))


    def check(self, url):
        return os.path.lexists(self._get_filename(url))


class OpenIDResponse(object):
    """
    Handle requests to OpenID, including trust root lookups
    """


    class NoneRequest(Exception):
        """
        Raise if request is empty
        """
        pass


    class DecisionNeed(Exception):
        """
        Raise if user decision of approve or decline autorization need
        """
        pass


    class LogInNeed(Exception):
        """
        Raise if need user to be logged in
        """
        pass


    def _encode_response(self, response):
        self.response = response
        self.webresponse = self.server.openid.encodeResponse(self.response)
        return self.webresponse


    def __init__(self, server, query):
        """
        Decode request
        """

        self.server = server
        self.query = query

        # parse openid request
        self.request = self.server.openid.decodeRequest(query)


    def process(self, logged_in=False):
        """
        Main checks routine
        """

        # no request
        if self.request is None:
            raise OpenIDResponse.NoneRequest

        if self.request.mode in ["checkid_immediate", "checkid_setup"]:
            # check request

            if not logged_in:
                # this stage required restricted access to endpoint
                raise OpenIDResponse.LogInNeed

            if self.server.trust_root_store.check(self.request.trust_root):
                # approve if request from trustroot
                return self.approve()

            elif self.request.immediate:
                # decline if immediate and not in trustroot
                return self.decline()

            # last hope route to user decision
            raise OpenIDResponse.DecisionNeed


        # return openid.server.server.WebResponse
        return self._encode_response(self.server.openid.handleRequest(self.request))


    def approve(self, identity=None):
        """
        Approve request
        TODO: sreg

        """
        return self._encode_response(self.request.answer(
                allow=True,
                identity=identity
            ))


    def always(self, identity=None):
        """
        Approve request and to append to trust root store
        """
        self.server.trust_root_store.add(self.request.trust_root)
        return self.approve(identity)


    def decline(self):
        """
        Decline request

        """
        return self._encode_response(self.request.answer(allow=False))


class OpenIDServer(object):
    """
    Manage OpenID server and trust root store, emit response
    """

    def __init__(self, openid, trust_root_store):
        self.openid = openid
        self.trust_root_store = trust_root_store


    def request(self, query):
        return OpenIDResponse(self, query)


class PasswordManager(object):
    """
    Manage access password
    """

    def __init__(self, directory):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)


    def _get_filename(self):
        return os.path.join(self.directory, 'password')


    def _generate_hash(self, salt, password):
        """
        build hash as md5 of concat of salt and password
        """
        return md5.md5(''.join([salt, str(password)])).hexdigest()


    def check(self, password):
        """
        Check password. Return False if passwords don't match, else return True if
        passwords match or unavailable
        """
        try:
            file = open(self._get_filename(), 'rb+')

            # read salt and hash splitted by '$' from password file
            salt, hash = file.read().strip().split('$', 1)

            file.close()

            # build hash and compare with stored
            if not self._generate_hash(salt, password) == hash:
                return False
        except:
            pass
        return True


    def set(self, password):
        """
        Set password
        """
        try:
            file = open(self._get_filename(), 'wb+')
            salt = str(random.randint(1, sys.maxint))

            file.write('$'.join([salt, self._generate_hash(salt, password)]))

            file.close()
            return True
        except:
            raise


def render_openid_to_response(response):
    """
    Return WebResponse as web.py response
    """
    if response.code in [200]:
        for name, value in response.headers.items():
            web.header(name, value)
        return response.body
    elif response.code in [302] and response.headers.has_key('location'):
        return web.found(response.headers['location'])
    else:
        return web.HTTPError(str(response.code) + ' ', response.headers)


class WebOpenIDIndex(object):


    def GET(self):
        web.header('Content-type', 'text/html')
        return render.base(
                logged_in=session.get('logged_in', False),
                logout_url=web.ctx.homedomain + web.url('/account/logout/'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password/'),
                endpoint=server.openid.op_endpoint,
                yadis=web.ctx.homedomain + web.url('/yadis.xrds'),
            )


def WebOpenIDLoginRequired():
    query = dict(web.input())
    query['return_to'] = web.ctx.homedomain + web.url(web.ctx.path)
    return web.found(web.ctx.homedomain + web.url('/account/login/', **query))


def WebOpenIDLoginForm(callback):
    return web.form.Form(
            web.form.Password("password",
                web.form.Validator('Incorrect', callback),
                description="Password: ",
            ),
        )


class WebOpenIDLogin(object):


    def GET(self):
        query = web.input()

        form = WebOpenIDLoginForm(lambda password: False)()

        web.header('Content-type', 'text/html')
        return render.login(
                logged_in=session.get('logged_in', False),
                logout_url=web.ctx.homedomain + web.url('/account/logout/'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password/'),
                form=form,
                query=query.items(),
            )


    def POST(self):
        query = web.input()

        return_to = query.get('return_to',
                web.ctx.homedomain + web.url('/account/'))

        data = filter(lambda item: item[0] not in ['password'], query.items())

        form = WebOpenIDLoginForm(password_manager.check)()

        if form.validates(query):
            session['logged_in'] = True

            return web.found(return_to + '?' + web.http.urlencode(dict(data)))

        web.header('Content-type', 'text/html')
        return render.login(
                logged_in=session.get('logged_in', False),
                logout_url=web.ctx.homedomain + web.url('/account/logout/'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password/'),
                form=form,
                query=data,
            )


class WebOpenIDLogout(object):


    def GET(self):
        session['logged_in'] = False
        return web.found(web.ctx.homedomain + web.url('/account/login/'))


WebOpenIDChangePasswordForm = web.form.Form(
            web.form.Password("password",
                web.form.notnull,
                description="Password: ",
            ),
            web.form.Password("confirm",
                web.form.notnull,
                description="Retype: ",
            ),
            validators=[
                    web.form.Validator('Passwords did not match',
                        lambda source: source['password'] == source['confirm']),
                ],
        )


class WebOpenIDChangePassword(object):


    def GET(self):
        # check for login
        logged_in = session.get('logged_in', False)

        if not logged_in:
            return WebOpenIDLoginRequired()

        form = WebOpenIDChangePasswordForm()

        web.header('Content-type', 'text/html')
        return render.password(
                logged_in=session.get('logged_in', False),
                logout_url=web.ctx.homedomain + web.url('/account/logout/'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password/'),
                form=form,
            )


    def POST(self):
        # check for login
        logged_in = session.get('logged_in', False)

        if not logged_in:
            return WebOpenIDLoginRequired()

        query = web.input()

        form = WebOpenIDChangePasswordForm()

        if form.validates(query):
            password_manager.set(query['password'])

            return web.found(web.url('/account/'))

        return render.password(
                logged_in=session.get('logged_in', False),
                logout_url=web.ctx.homedomain + web.url('/account/logout/'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password/'),
                form=form,
            )



class WebOpenIDYadis(object):


    def GET(self):
        import openid.consumer
        web.header('Content-type', 'application/xrds+xml')
        return """<?xml version="1.0" encoding="UTF-8"?>\n<xrds:XRDS \
                xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)"><XRD><Service \
                priority="0"><Type>%s</Type><Type>%s</Type><URI>%s</URI><LocalID>%s</LocalID></Service></XRD></xrds:XRDS>""" %\
            (
                openid.consumer.discover.OPENID_2_0_TYPE,
                openid.consumer.discover.OPENID_1_0_TYPE,
                server.openid.op_endpoint,
                web.ctx.homedomain,
            )


class WebOpenIDEndpoint(object):


    def GET(self):
        return self.endpoint()


    def POST(self):
        return self.endpoint()


    def endpoint(self):
        query = web.input()

        # check for login
        logged_in = session.get('logged_in', False)

        request = server.request(query)
        try:
            response = request.process(logged_in)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.LogInNeed:
            # redirect request login form
            return WebOpenIDLoginRequired()

        except OpenIDResponse.DecisionNeed:
            # redirect request to decision page in restricted area
            return web.found(web.ctx.homedomain + web.url('/decision/', **query))

        return render_openid_to_response(response)


class WebOpenIDDecision(object):


    def GET(self):
        query = web.input()

        # check for login
        logged_in = session.get('logged_in', False)

        if not logged_in:
            return WebOpenIDLoginRequired()

        request = server.request(query)

        try:
            response = request.process(logged_in=True)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.DecisionNeed:
            web.header('Content-type', 'text/html')
            return render.verify(
                    logged_in=logged_in,
                    logout_url=web.ctx.homedomain + web.url('/account/logout/'),
                    change_password_url=web.ctx.homedomain + web.url('/account/change_password/'),
                    identity=request.request.identity,
                    trust_root=request.request.trust_root,
                    query=dict(query).items(),

                )

        return render_openid_to_response(response)


    def POST(self):
        query = web.input()

        # check for login
        logged_in = session.get('logged_in', False)

        if not logged_in:
            return WebOpenIDLoginRequired()

        request = server.request(query)

        try:
            response = request.process(logged_in=True)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.DecisionNeed:
            if query.has_key('approve'):
                response = request.approve()
            elif query.has_key('always'):
                response = request.always()
            else:
                response = request.decline()

        return render_openid_to_response(response)


app = web.application(
        (
            '/', 'WebOpenIDIndex',
            '/account/', 'WebOpenIDIndex',
            '/account/login/', 'WebOpenIDLogin',
            '/account/logout/', 'WebOpenIDLogout',
            '/account/change_password/', 'WebOpenIDChangePassword',
            '/yadis.xrds', 'WebOpenIDYadis',
            '/endpoint/', 'WebOpenIDEndpoint',
            '/decision/', 'WebOpenIDDecision',
        ),
        globals()
    )


TRUST_ROOT_STORE = os.path.join(ROOT_STORE, 'trust_root')
SESSION_STORE = os.path.join(ROOT_STORE, 'sessions')
PASSWORD_STORE = ROOT_STORE

openid_store = openid.store.filestore.FileOpenIDStore(ROOT_STORE)

trust_root_store = TrustRootStore(TRUST_ROOT_STORE)

sessions_store = web.session.DiskStore(SESSION_STORE)
session = web.session.Session(app, sessions_store)

password_manager = PasswordManager(PASSWORD_STORE)

render = web.contrib.template.render_jinja(TEMPLATES)


if __name__ == '__main__':
    web.config.debug = False
    #app.load(os.environ)
    openid_server = openid.server.server.Server(openid_store,
            'http://127.0.0.1:8080/endpoint/')
            #web.ctx.homedomain + web.url('/endpoint/'))
    server = OpenIDServer(openid_server, trust_root_store)
    app.run()
