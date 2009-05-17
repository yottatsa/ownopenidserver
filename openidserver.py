#!/usr/bin/env python


class TrustRootStore(object):
    """
    Store and lookup over trust root list
    """


    def __init__(self, directory):
        import os, os.path

        self.directory = directory
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)


    def _get_filename(self, url):
        """
        Encode url to filename
        TODO: doctest
        """
        import urlparse
        import urllib
        import os.path

        url = urlparse.urlparse(url)
        filename = urllib.quote('__'.join(tuple(url)).replace('/', '_'))

        return os.path.join(self.directory, filename)


    def add(self, url):
        import os
        return os.symlink(url, self._get_filename(url))


    def check(self, url):
        import os.path
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
                endpoint=server.openid.op_endpoint,
                yadis=web.ctx.homedomain + web.url('/yadis.xrds'),
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


    def endpoint(self, logged_in=False):
        query = web.input()

        request = server.request(query)
        try:
            response = request.process(logged_in)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.LogInNeed:
            # redirect request to restricted area
            return web.found(web.ctx.homedomain + web.url('/private/endpoint/', **dict(query)))

        except OpenIDResponse.DecisionNeed:
            # redirect request to decision page in restricted area
            return web.found(web.ctx.homedomain + web.url('/private/decision/', **dict(query)))

        return render_openid_to_response(response)


class WebOpenIDPrivateEndpoint(WebOpenIDEndpoint):


    def endpoint(self):
        return super(WebOpenIDPrivateEndpoint, self).endpoint(logged_in=True)


class WebOpenIDDecision(object):


    def GET(self):
        query = web.input()

        request = server.request(query)

        try:
            response = request.process(logged_in=True)

        except OpenIDResponse.NoneRequest:
            return web.badrequest()

        except OpenIDResponse.DecisionNeed:
            web.header('Content-type', 'text/html')
            return render.verify(
                    identity=request.request.identity,
                    trust_root=request.request.trust_root,
                    query=dict(query).items(),

                )

        return render_openid_to_response(response)


    def POST(self):
        query = web.input()

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


if __name__ == '__main__':
    import os

    import openid.store.filestore
    import openid.server.server

    import web
    import web.contrib.template

    urls = (
            '/', 'WebOpenIDIndex',
            '/private/', 'WebOpenIDIndex',
            '/yadis.xrds', 'WebOpenIDYadis',
            '/endpoint/', 'WebOpenIDEndpoint',
            '/private/endpoint/', 'WebOpenIDPrivateEndpoint',
            '/private/decision/', 'WebOpenIDDecision',
        )

    app = web.application(urls, globals())
    app.load(os.environ)

    openid_store = openid.store.filestore.FileOpenIDStore('sstore')
    openid_server = openid.server.server.Server(openid_store,
            web.ctx.homedomain + web.url('/endpoint/'))
    trust_root_store = TrustRootStore('sstore/trust_root')

    server = OpenIDServer(openid_server, trust_root_store)

    render = web.contrib.template.render_jinja('.')

    app.run()
