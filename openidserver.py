#!/usr/bin/env python


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


class PasswordManager(web.form.Validator):
    """
    Manage access password
    """

    class NoPassword(Exception):
        pass

    def __init__(self, directory):
        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)

        self.msg = 'Invalid password'


    def _get_filename(self):
        return os.path.join(self.directory, 'password')


    def _generate_hash(self, salt, password):
        """
        build hash as md5 of concat of salt and password
        """
        return md5.md5(''.join([salt, str(password)])).hexdigest()


    def valid(self, password):
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
            raise PasswordManager.NoPassword

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


class WebHandler(object):


    def __init__(self):
        self.query = web.input()
        self.method = None


    def GET(self):
        self.method = 'GET'
        return self.request()


    def POST(self):
        self.method = 'POST'
        return self.request()


    def request(self):
        raise NotImplemented


class WebOpenIDIndex(WebHandler):


    def request(self):
        web.header('Content-type', 'text/html')
        return render.base(
                logged_in=session.get('logged_in', False),
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                no_password=session.get('no_password', False),
                endpoint=server.openid.op_endpoint,
                yadis=web.ctx.homedomain + web.url('/yadis.xrds'),
            )


def WebOpenIDLoginRequired(query):
    query['return_to'] = web.ctx.homedomain + web.url(web.ctx.path)
    return web.found(web.ctx.homedomain + web.url('/account/login', **query))


def WebOpenIDLoginForm(validator):
    return web.form.Form(
            web.form.Password("password",
                validator,
                description="Password: ",
            ),
        )


class WebOpenIDLogin(WebHandler):


    def request(self):
        return_to = self.query.get('return_to', web.ctx.homedomain + web.url('/account'))

        data = filter(lambda item: item[0] not in ['password'], self.query.items())

        form = WebOpenIDLoginForm(password_manager)()

        session['no_password'] = False

        if self.method == 'POST':
            try:
                if form.validates(self.query):
                    session['logged_in'] = True
                    return web.found(return_to + '?' + web.http.urlencode(dict(data)))

            except PasswordManager.NoPassword:
                session['no_password'] = True
                session['logged_in'] = True
                return web.found(return_to + '?' + web.http.urlencode(dict(data)))

        web.header('Content-type', 'text/html')
        return render.login(
                logged_in=session.get('logged_in', False),
                login_url=web.ctx.homedomain + web.url('/account/login'),
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                no_password=session.get('no_password', False),
                form=form,
                query=data,
            )


class WebOpenIDLogout(WebHandler):


    def request(self):
        session['logged_in'] = False
        return web.found(web.ctx.homedomain + web.url('/account/login'))


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


class WebOpenIDChangePassword(WebHandler):


    def request(self):
        # check for login
        logged_in = session.get('logged_in', False)

        if not logged_in:
            return WebOpenIDLoginRequired(self.query)

        form = WebOpenIDChangePasswordForm()

        if self.method == 'POST':
            if form.validates(self.query):
                password_manager.set(self.query['password'])

                session['no_password'] = False

                return web.found(web.ctx.homedomain + web.url('/account'))

        web.header('Content-type', 'text/html')
        return render.password(
                logged_in=session.get('logged_in', False),
                logout_url=web.ctx.homedomain + web.url('/account/logout'),
                change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                no_password=session.get('no_password', False),
                form=form,
            )


class WebOpenIDYadis(WebHandler):


    def request(self):
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


class WebOpenIDEndpoint(WebHandler):


    def request(self):
        # check for login
        logged_in = session.get('logged_in', False)

        request = server.request(self.query)
        try:
            response = request.process(logged_in)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.LogInNeed:
            # redirect request to login form
            return WebOpenIDLoginRequired(self.query)

        except OpenIDResponse.DecisionNeed:
            # redirect request to decision page in restricted area
            return web.found(web.ctx.homedomain + web.url('/account/decision', **self.query))

        return render_openid_to_response(response)


class WebOpenIDDecision(WebHandler):


    def request(self):
        # check for login
        logged_in = session.get('logged_in', False)

        if not logged_in:
            return WebOpenIDLoginRequired(self.query)

        request = server.request(self.query)

        try:
            response = request.process(logged_in=True)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.DecisionNeed:
            if self.method == 'POST':
                if self.query.has_key('approve'):
                    response = request.approve()
                elif self.query.has_key('always'):
                    response = request.always()
                else:
                    response = request.decline()
            else:
                data = filter(lambda item: item[0] not in ['approve', 'always'], self.query.items())

                web.header('Content-type', 'text/html')
                return render.verify(
                        logged_in=logged_in,
                        logout_url=web.ctx.homedomain + web.url('/account/logout'),
                        change_password_url=web.ctx.homedomain + web.url('/account/change_password'),
                        no_password=session.get('no_password', False),
                        decision_url=web.ctx.homedomain + web.url('/account/decision'),
                        identity=request.request.identity,
                        trust_root=request.request.trust_root,
                        query=data,
                    )

        return render_openid_to_response(response)


app = web.application(
        (
            '/account', 'WebOpenIDIndex',
            '/account/login', 'WebOpenIDLogin',
            '/account/logout', 'WebOpenIDLogout',
            '/account/change_password', 'WebOpenIDChangePassword',
            '/yadis.xrds', 'WebOpenIDYadis',
            '/endpoint', 'WebOpenIDEndpoint',
            '/account/decision', 'WebOpenIDDecision',
        ),
        globals()
    )


ROOT_STORE = 'sstore'
TEMPLATES = 'templates'

TRUST_ROOT_STORE = os.path.join(ROOT_STORE, 'trust_root')
SESSION_STORE = os.path.join(ROOT_STORE, 'sessions')
PASSWORD_STORE = ROOT_STORE


if __name__ != '__main__':
    try:
        from localsettings import *
    except ImportError: pass


openid_store = openid.store.filestore.FileOpenIDStore(ROOT_STORE)

trust_root_store = TrustRootStore(TRUST_ROOT_STORE)

sessions_store = web.session.DiskStore(SESSION_STORE)
session = web.session.Session(app, sessions_store)

password_manager = PasswordManager(PASSWORD_STORE)

render = web.contrib.template.render_jinja(TEMPLATES)


if __name__ == '__main__':
    try:
        app.load(os.environ)
    except: pass
    web.config.debug = True
    openid_server = openid.server.server.Server(openid_store,
            web.ctx.homedomain + web.url('/endpoint'))
    server = OpenIDServer(openid_server, trust_root_store)
    app.run()
