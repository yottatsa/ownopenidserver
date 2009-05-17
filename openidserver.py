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
        filename = urllib.quote('__'.join([
                url.scheme or '',
                url.username or '',
                '_'.join([url.hostname or '', url.port and str(url.port) or '']),
                '_'.join(url.path.split('/')),
                url.params or '',
                url.query or '',
            ]))

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


    def approve(self):
        """
        Approve request
        TODO: sreg

        """
        return self._encode_response(self.request.answer(True))


    def always(self):
        """
        Approve request and to append to trust root store
        """
        self.server.trust_root_store.add(self.request.trust_root)
        return self.approve()


    def decline(self):
        """
        Decline request

        """
        return self._encode_response(self.request.answer(False))


class OpenIDServer(object):
    """
    Manage OpenID server and trust root store, emit response
    """

    def __init__(self, openid, trust_root_store):
        self.openid = openid
        self.trust_root_store = trust_root_store


    def request(self, query):
        return OpenIDResponse(self, query)


if __name__ == '__main__':

    import openid.store.filestore
    import openid.server.server
    import cgi
    import os
    import sys
    import string
    import urllib

    openid_store = openid.store.filestore.FileOpenIDStore('sstore')
    openid_server = openid.server.server.Server(openid_store,
            'http://127.0.0.1:8000/cgi-bin/openidserver.py')
    trust_root_store = TrustRootStore('sstore/trust_root')
    server = OpenIDServer(openid_server, trust_root_store)

    if os.environ['REQUEST_METHOD'] in ['GET', 'POST']:
        if os.environ['REQUEST_METHOD'] == 'GET':
            QUERY = os.environ['QUERY_STRING']
        elif os.environ['REQUEST_METHOD'] == 'POST':
            QUERY = sys.stdin.read(int(os.environ['CONTENT_LENGTH']))
        QUERY = dict(cgi.parse_qsl(QUERY))

    TEMPLATE = string.Template(
u"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="ru" lang="ru">
	<head>
		<title>$title</title>
		<style type="text/css">
			body { background-color: #fff; font: 1.0em serif; color: black; }
			h1 { top: 35%; font-size: 2.1em; padding-bottom: 0.3em; border-bottom: 1px solid gray; }
		</style>
	</head>
    <body>
		<h1>$header</h1>

$body
	</body>
</html>
""")


    def error_page(message, debug=u''):
        ERROR = string.Template(u"""
        <p class="error">$message</p>
        <pre>$debug</pre>
        """)

        print "Content-Type: text/html\r\n"

        print TEMPLATE.substitute(
                title=u'Error',
                header=u'Error',
                body=ERROR.substitute(
                    message=message,
                    debug=debug
                ),
            )


    def decision_page(query, trust_root):
        DECISION = string.Template(u"""
        <p>Host $trust_root requested autorization</p>
        <form method="post" action="/cgi-bin/openidserver.py/account/decision">
            <input type="hidden" name="query" value="$query" />
            <input type="submit" name="approve" value="Approve" />
            <input type="submit" name="always" value="Always" />
            <input type="submit" name="decline" value="Decline" />
        </form>
        """)

        print "Content-Type: text/html\r\n"

        print TEMPLATE.substitute(
                title=u'Need decision',
                header=u'Need decision',
                body=DECISION.substitute(
                    query=query,
                    trust_root=trust_root
                ),
            )


    def print_response(response):
        print "Status: %s " % response.code
        for header, value in response.headers.items():
            print '%s: %s' % (header, value)
        if response.code in [302]:
            error_page('<a href="%s">Redirect</a>' % response.headers['location'])
        else:
            print "Content-Type: text/plain\r\n"
            print response.body


    def redirect(location):
        print "Status: 302"
        print "Location: %s" % location
        error_page('<a href="%s">Redirect</a>' % location)


    URLMAP = dict()


    def openid_endpoint(query, server, logged_in=False):
        request = server.request(query)
        try:
            response = request.process(logged_in)

        except OpenIDResponse.NoneRequest:
            error_page('No request')
            return

        except OpenIDResponse.DecisionNeed:
            # redirect request to decision page in restricted area
            location = "/cgi-bin/openidserver.py/account/decision?%s" % urllib.urlencode(query.items())
            redirect(location)
            return

        except OpenIDResponse.LogInNeed:
            # redirect request to restricted area
            location = "/cgi-bin/openidserver.py/account/endpoint?%s" % urllib.urlencode(query.items())
            redirect(location)
            return

        print_response(response)

    URLMAP[''] = lambda: openid_endpoint(query=QUERY, server=server, logged_in=False)
    URLMAP['/account/endpoint'] = lambda: openid_endpoint(query=QUERY, server=server, logged_in=True)


    def decision(method, query, server):
        if method == 'GET':
            request = server.request(query)
        elif method == 'POST':
            request = server.request(dict(cgi.parse_qsl(query['query'])))

        try:
            response = request.process(logged_in=True)

        except OpenIDResponse.NoneRequest:
            error_page('No request')
            return

        except OpenIDResponse.DecisionNeed:
            if method == 'GET':
                decision_page(urllib.urlencode(query.items()),
                        request.request.trust_root)
                return

            elif method == 'POST':
                if query.has_key('approve'):
                    response = request.approve()
                elif query.has_key('always'):
                    response = request.always()
                elif query.has_key('decline'):
                    response = request.decline()

        print_response(response)

    URLMAP['/account/decision'] = lambda: decision(method=os.environ['REQUEST_METHOD'], query=QUERY, server=server)


    URLMAP.get(os.environ['PATH_INFO'], cgi.test)()
