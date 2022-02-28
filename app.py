import os
import jwt 

from flask import Flask, request, session
from flask_session import Session
from FlaskOIDC import FlaskOIDC

from config import oidc_config, session_config

DEBUG = os.environ.get('DEBUG', False)

app = Flask(__name__)
app.config.from_mapping(session_config)

Session(app)

auth = FlaskOIDC(config=oidc_config, app=app)

#
# Authentication: require_login decorator
#
@app.route('/login')
@app.route('/logon')
@auth.require_login
def login():
    """ Login """
    
    return {'username': session['username']}

#
# logout 
#
@app.route('/logout')
@app.route('/logoff')
def bye():
    """ Logout """

    if auth.is_authenticated:
        return auth.initiate_logout(next=request.url)
    else:
        return 'ok'

#
# Authorization: require_user decorator
#
@app.route('/bob')
@auth.require_user(['bob','rkras'])
def bob():
    """ Only bob """
    return 'hi bob'

#
# Authorization: require_attribute decorator
#
@app.route('/sa')
@auth.require_attribute('groups', ['netadmin', 'sysadmin'])
def sa():
    return 'hi sa'


if DEBUG:
    # DEBUG helpers

    @app.route('/mysession')
    def my_session_status():
        """ Dump username/attributes from OIDC id token state """
        
        return {
            'username': auth.my_username,
            'attributes': auth.my_attrs
        }


    @app.route('/<scpname>/expire')
    @app.route('/expire')
    @auth.assert_login
    def expire(scpname=auth.token_name):
        """ Hasten token expiration by 1 hr. - for testing auto token refresh """

        session[scpname]['exp'] -= 3600
        session.modified = True
        return 'ok'


    def decode_jwt(token):
        """ decode and return token response. """

        payload = jwt.decode(token, options={'verify_signature': False})
        return payload


    @app.route('/<scpname>/new')   
    @auth.assert_login
    def new_scope_token(scpname='meh'):
        """ 
        Request new tokens with new scope.
        
        New requested scope is provided a query string "scp="
        
            GET /dbaccess/new?scp=[db.dbread]
        
        'dbaccess' is the name then used to access the tokens.
        """
        newscp = request.args.get('scp')
        tokens = auth.get_access_token(scpname, scope=newscp)
        return {'tokens': tokens}


    @app.route('/id')          # decode id token for login scope
    @app.route('/<scpname>/id')    # decode id token for named scope
    @auth.assert_login
    def decode_id_tok(scpname=auth.token_name):
        """ 
        decode id token 
        
            GET /id
        
        returns id token for login (default) scope

            GET /dbaccess/id
        
        returns id token for `dbaccess` named tokens
        """

        return decode_jwt(session[scpname]['id_token'])


    @app.route('/id/raw')
    @app.route('/<scpname>/id/raw')
    @auth.assert_login
    def raw_id_tok(scpname=auth.token_name):
        """ Return the id token raw """

        return session[scpname]['id_token']


    @app.route('/access')          # decode access token from login
    @app.route('/<scpname>/access')    # decode access token for named scope
    def decode_access_tok(scpname=auth.token_name):
        """ 
        decode access token 
        
            GET /access
        
        return access token for login (default) scope

            GET /dbaccess/access
        
        return access token for 'dbaccess' named token
        """

        return decode_jwt(session[scpname]['access_token'])


    @app.route('/access/raw')
    @app.route('/<scpname>/access/raw')
    @auth.assert_login
    def raw_access_tok(scpname=auth.token_name):
        """ Return the access token raw """

        return session[scpname]['access_token']
