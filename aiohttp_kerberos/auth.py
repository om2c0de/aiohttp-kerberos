import logging
import sys
from contextvars import ContextVar
from functools import wraps
from os import environ
from socket import gethostname

from aiohttp import web

# Platform-specific Kerberos requirements
if sys.platform == 'win32':
    import kerberos_sspi as kerberos
    import pywintypes

    pywintypes_error = pywintypes.error
else:
    import kerberos

    pywintypes_error = OSError


# Initialize logger
logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


# Kerberos context
_service_name = ...

# Request context variables
_kerberos_user = ContextVar('kerberos_user')
_kerberos_token = ContextVar('kerberos_token')


def init_kerberos(service='HTTP', hostname=None):
    """
    Configure the GSSAPI service name, and validate the presence of the
    appropriate principal in the kerberos keytab.

    :param service: GSSAPI service name
    :type service: str
    :param hostname: hostname the service runs under
    :type hostname: str
    """

    hostname = hostname or gethostname()

    global _service_name
    _service_name = f'{service}@{hostname}'

    if 'KRB5_KTNAME' not in environ:
        logger.debug("Kerberos: set KRB5_KTNAME to your keytab file")

    else:
        try:
            principal = kerberos.getServerPrincipalDetails(service, hostname)
        except kerberos.KrbError as error:
            logger.debug(f'Kerberos: {error}')
        else:
            logger.info(f'Kerberos: server is {principal}')


def _gssapi_authenticate(token, service_name=None):
    """
    Performs GSSAPI Negotiate Authentication

    On success also stashes the server response token for mutual authentication
    at the top of request context with the name kerberos_token, along with the
    authenticated user principal with the name kerberos_user.

    :param token: GSSAPI Authentication Token
    :type token: str
    :param service_name: Service name for example - "HTTP@example.com"
    :type service_name: str
    :returns gssapi return code or None on failure
    :rtype: int or None
    """
    state = None
    service_name = service_name or _service_name
    try:
        logger.debug(f'Kerberos: service name is {service_name}')
        result, state = kerberos.authGSSServerInit(service_name)
        if result != kerberos.AUTH_GSS_COMPLETE:
            return None
        logger.debug(f'Kerberos: state is {state}')
        result = kerberos.authGSSServerStep(state, token)
        if result == kerberos.AUTH_GSS_COMPLETE:
            _kerberos_token.set(kerberos.authGSSServerResponse(state))
            _kerberos_user.set(kerberos.authGSSServerUserName(state))
            return result
        elif result == kerberos.AUTH_GSS_CONTINUE:
            return kerberos.AUTH_GSS_CONTINUE
        else:
            return None
    except (kerberos.GSSError, pywintypes_error) as error:
        logger.debug(f'Kerberos: {error}')
        return None
    finally:
        if state:
            kerberos.authGSSServerClean(state)


def login_required(function):
    """
    Require that the wrapped view function only be called by users
    authenticated with Kerberos. The view function will have the authenticated
    users principal passed to it as its first argument.

    :param function: view function
    :type function: function
    :returns: decorated function
    :rtype: function
    """
    @wraps(function)
    async def wrapped(*args, **kwargs):
        request = args[-1]

        header = request.headers.get("Authorization")
        if header:
            logger.debug(f'Kerberos: Authorization header is {header}')
            _, token = header.split()
            logger.debug(f'Kerberos: token is {token}')
            result = _gssapi_authenticate(token)
            if result == kerberos.AUTH_GSS_COMPLETE:
                kerberos_user = _kerberos_user.get()
                response = await function(kerberos_user, *args, **kwargs)
                kerberos_token = _kerberos_token.get()
                if kerberos_token is not None:
                    response.headers['WWW-Authenticate'] = f'Negotiate {kerberos_token}'
                logger.debug(f'Kerberos: response headers are {response.headers}')
                return response
            elif result != kerberos.AUTH_GSS_CONTINUE:
                return web.HTTPForbidden(reason='Invalid authorization header')
        return web.HTTPUnauthorized(reason='Missing authorization token', headers={'WWW-Authenticate': 'Negotiate'})
    return wrapped


class KerberosTicket:
    """
    Usage:
        >>> krb = KerberosTicket("HTTP@krbhost.example.com")
        >>> headers = {"Authorization": krb.auth_header}
        >>>
    """
    def __init__(self, service):
        _, krb_context = kerberos.authGSSClientInit(service)
        kerberos.authGSSClientStep(krb_context, '')
        self._krb_context = krb_context
        self.auth_header = ('Negotiate ' + kerberos.authGSSClientResponse(krb_context))
