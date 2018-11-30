from jupyterhub.auth import Authenticator, PAMAuthenticator
from jupyterhub.handlers import LoginHandler
from tornado import gen
from traitlets import Unicode, Type, Instance, default
from jinja2 import Environment
import duo_web

class DuoHandler(LoginHandler):
    """Duo Two-Factor Handler"""

    @gen.coroutine
    def post(self):
        """Override the default POST handler.  If the Duo signed response isn't present,
        do primary auth and POST back to the same URL with the request.  If the response 
        is present, call the stock LoginHandler post method, which will call 
        DuoAuthenticator.authenticate() to perform verification of the response.
        """
        # parse the arguments dict
        data = {}
        for arg in self.request.arguments:
            data[arg] = self.get_argument(arg, strip=False)
        sig_response = self.get_argument("sig_response", default=None)
        if sig_response:
            # Duo signed response present, do secondary auth
            yield LoginHandler.post(self)

        else:
            # no sig_response, do primary auth and generate the request
            data = yield self.authenticator.do_primary_auth(self,data)
            if data:
                sig_request = duo_web.sign_request(self.authenticator.ikey,
                    self.authenticator.skey, self.authenticator.akey, data['name'])

                common_args = {
                    'host': self.authenticator.apihost,
                    'sig_request': sig_request,
                    'data': data,
                }

                html = self.render_template('duo.html',
                    custom_fields = Environment().from_string(self.authenticator.duo_custom_fields).render(common_args),
                    custom_html = Environment().from_string(self.authenticator.duo_custom_html).render(common_args),
                    **common_args
                )
                self.finish(html)
            else:
                html = self._render(
                    login_error='Invalid username or password',
                    username=None,
                )
                self.finish(html)

class DuoAuthenticator(Authenticator):
    """Duo Two-Factor Authenticator"""

    ikey = Unicode(
        help="""
        The Duo Integration Key.

        """
    ).tag(config=True)

    skey = Unicode(
        help="""
        The Duo Secret Key.

        """
    ).tag(config=True)

    akey = Unicode(
        help="""
        The Duo Application Key.

        """
    ).tag(config=True)

    apihost =  Unicode(
        help="""
        The Duo API hostname.

        """
    ).tag(config=True)

    primary_auth_class = Type(PAMAuthenticator, Authenticator,
        help="""Class to use for primary authentication of users.

        Must follow the same structure as a standard authenticator class.

        Defaults to PAMAuthenticator.
        """
    ).tag(config=True)

    primary_authenticator = Instance(Authenticator)

    @default('primary_authenticator')
    def _primary_auth_default(self):
        return self.primary_auth_class(parent=self, db=self.db)

    duo_custom_html = Unicode(
        help="""
        Custom html to use for the Duo iframe page.  Must contain at minimum an
        iframe with id="duo_iframe", as well as 'data-host' and 'data-sig-request'
        template attributes to be populated.

        Defaults to an empty string, which uses the included 'duo.html' template.
        """
    ).tag(config=True)

    duo_custom_fields = Unicode(
        help="""
        Custom fields within the duo_form that get posted back to the authenticator.

        Example value: <input type="hidden" name="someMetadata" value="{{stuff}}" />

        Defaults to an empty string.
        """
    ).tag(config=True)

    def get_handlers(self,app):
        return [
            (r'/login', DuoHandler)
        ]

    @gen.coroutine
    def authenticate(self, handler, data):
        """Do secondary authentication with Duo, and return the username if successful.

        Return None otherwise.
        """

        sig_response = data['sig_response']
        authenticated_username = duo_web.verify_response(self.ikey,\
            self.skey, self.akey, sig_response)
        if authenticated_username:
            self.log.info("Duo Authentication succeeded for user '%s'", \
                authenticated_username)
            return {
                'name': authenticated_username,
                'auth_state': data,
            }
        else:
            self.log.warning("Duo Authentication failed for user")
            return None

    @gen.coroutine
    def do_primary_auth(self, handler, data):
        """Do primary authentication, and return the username if successful.

        Return None otherwise.
        """
        data = yield self.primary_authenticator.authenticate(handler, data)
        if data:
          return data
        else:
          return None
