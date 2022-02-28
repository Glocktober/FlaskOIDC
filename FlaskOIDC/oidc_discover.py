import requests as req
import sys

from .JWKS import Jwks


class   OidcDiscover:
    """
    OidcDiscover - discover OIDC configuration and JWK signing keys

    discov = OIDC_discover(url, timeout)
    
        Autodiscover OIDC endpoint from discovery url
        url - discovery url
        timeout - timeout for config retrival (def: 4 Seconds)
    """

    def __init__(self, url, timeout = 4):

        self.discovery_url = url
        self.add_offline_scp = False
        self.discovery_complete = False
        self.timeout = timeout

        self.discover()
        

    def discover(self, url=None):
        """Retrieve OIDC autodiscovery to configure authorizer."""
        
        if url is None:
            url = self.discovery_url

        print(f'** Initating OIDC autodiscovery on "{url}" **', file=sys.stderr)

        try:
            discovery_config = req.get(url, timeout=self.timeout).json()
            if 'error' in discovery_config:
                print(discovery_config['error_description'], file=sys.stderr)
                raise Exception(discovery_config['error_description'])

            self.issuer = discovery_config['issuer']
            self.auth_url = discovery_config['authorization_endpoint']
            self.token_url = discovery_config['token_endpoint']

            self.jwks_uri = discovery_config.get('jwks_uri')
            
            self.logout_url = discovery_config.get('end_session_endpoint')
            self.scopes_supported = discovery_config.get('scopes_supported',[])
            
        except Exception as e:

            print(f'** OIDC Autodiscovery FAILED using "{url}" **',file=sys.stderr)
            raise e

        self.jwks = Jwks(self.jwks_uri)

        print(f'** OIDC autodiscovery completed.**', file=sys.stderr)

