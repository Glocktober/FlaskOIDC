"""
Jwks - retrieve public keys from url and decode/verify tokens

"""
import base64
import json
import jwt
import requests as req
import sys

from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.asymmetric import padding


def __base64url_decode(input):
    """pad out input length to mod 4 and decode."""

    if isinstance(input, str):
        input = input.encode("ascii")

    rem = len(input) % 4

    if rem > 0:
        input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input)


class   Jwks:

    def __init__(self, url=None, timeout=4):
        """
        jwks = Jwks(url, timeout)

        Keys are obtained from url on object instantiation
            url - points to jwks json object
            timeout - for retrieving url (def 4 sec)

        """

        self.url = url
        self.timeout = timeout
        self.pub_keys = {}

        if url:
            self.pub_keys = self._load_jwks(url)
        else:
            self.pub_keys = {}

        self.rsa = jwt.algorithms.RSAAlgorithm(hashes.SHA256)


    def load_jwks(self, url):

        self.pub_keys = self._load_jwks(url)

        
    def _load_jwks(self, url):
        """ Load keys from public endpoint. """

        print(f'*** Loading JWKS from {url}', file=sys.stderr)
        pub_keys = {}
        try:
            jwks_config = req.get(url, timeout=self.timeout).json()

            if 'keys' not in jwks_config:
                raise Exception('no keys in jwks')

            for jwk in jwks_config['keys']:
                # Load only RSA signature keys
                if jwk['kty'] == 'RSA' and jwk['use'] == 'sig':
                    pub_keys[jwk['kid']] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

        except Exception as e:
            print(f'Failure loading jwks {str(e)}', file=sys.stderr)
            print(f'*** Loading JWKS Falied. ***', file=sys.stderr)
            raise e
        
        print(f'*** JWKS loading completed: {len(pub_keys)} keys loaded. ***', file=sys.stderr)
        return pub_keys


    def decode(self, token, options={}, **kwargs):
        """
        jwks.decode(token, **kwargs)

            Decodes token with PyJWT perameters/options.
            Returns payload on success, None on failure
        """

        try:
            kid = jwt.get_unverified_header(token)['kid']
            
            if self.pub_keys and kid in self.pub_keys:
                pub_key = self.pub_keys[kid]
                try:
                    
                    return jwt.decode(token, key=pub_key, algorithms=['RS256'], options=options, **kwargs)
                    
                except Exception as e:
                    print(f'Error: verify/decode Failed {str(e)}', file=sys.stderr)
                    return None
            else:
                print(f'Error: can not verify: Public Key with KID {kid} has not been loaded', file=sys.stderr)
        
        except Exception as e:
            print(f'Error: decode Bad Token: {str(e)}', file=sys.stderr)

        return None
    

    def signature_verify(self, token):
        """
        jwks.signature_verify(token)

            Verify signature only (not iat, issuer, etc.)
            Returns payload on success, None on failure
        """

        try:
            kid = jwt.get_unverified_header(token)['kid']
            
            if self.pub_keys and kid in self.pub_keys:
                pub_key = self.pub_keys[kid]
                try:
                    return self._jwt_verify_signature(pub_key, token)

                except Exception as e:
                    print(f'Error: signature_verify Failed: {str(e)}', file=sys.stderr)
            else:
                print(f'Error: signature_verify: No Public Key with KID: {kid}', file=sys.stderr)
        
        except Exception as e:
            print(f'Error: signature_verify Bad Token: {str(e)}', file=sys.stderr)
    
        return None


    def decode_noverify(self, token, **kwargs):
        """    
        jwks.decode_noverify(token)

            Decodes token, but does no verification. 
            Returns payload on success, None on failure
        """

        try:
            return jwt.decode(token, options={'verify_signature': False, **kwargs})

        except Exception as e:
            print(f'Error: decode_noverify: decode failed {str(e)}', file=sys.stderr)
            return None


    def _jwt_verify_signature(self, pub_key, token):
        """ Verify signing on token with public key. """

        # split token
        (message, signature) = token.rsplit('.', 1)
        (header, payload) = message.split('.', 1)
        
        # verify
        self.rsa.verify(message.encode('utf-8'), pub_key, __base64url_decode(signature))
        
        payload_data = json.loads(__base64url_decode(payload))

        return payload_data

