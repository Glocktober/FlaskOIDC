
# Example configuration template
oidc_config = {
    "client_id": "IDP Provided Client ID",
    "client_secret": "IDP Provided Secret",
    "discovery_url": "https://login.microsoftonline.com/<tenentid>/V2.0/.well-known/openid-configuration",
    "client_scope": ["openid", "email", "profile", ],
    "user_attr": 'email'
}

session_config = {
    'secret_key': b'now is the time to test this',
    'SESSION_TYPE': 'filesystem', # You can use redis/memcache/etc - see Flask-Session docs
    'SESSION_FILE_DIR': './.cache', # for filesystem cache
    'PERMANENT_SESSION_LIFETIME' : 300,
    'SESSION_COOKIE_NAME' :'demo', # name of the cookie
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SECURE': True,
}