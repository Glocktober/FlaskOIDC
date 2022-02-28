
## Flask-OIDC-SP - OIDC Service Provider Blueprint for Flask

**FlaskOIDC** is an OpenID Connect module providing authentication and authorization for [Flask web framework.](https://palletsprojects.com/p/flask/) web apps.

**FlaskOIDC** supports OIDC auto discovery to simplify configuration and deployment.
### Installing

```bash
# pip install Flask-OIDC-SP
```
This loads the necessary python modules including Flask, Flask-Session, requests, and PyJWT.
### Using FlaskOIDC
```python
from flask import Flask, request, session
from flask_session import Session
from FlaskOIDC import FlaskOIDC

from config import oidc_config, session_config

app = Flask(__name__)
app.config.from_mapping(session_config)

Session(app)

auth = FlaskOIDC(config=oidc_config, app=app)

@app.route('/login')
@auth.require_login
def login():
    return f'hello {auth.my_username}'

@app.route('/bob')
@auth.require_user('bob')
    return 'You must be bob'

```
#### Signature and Parameters

```
auth = FlaskOIDC(config, app)
```
**`app`** - the Flask() application context object. **Optional.** when provided FlaskOIDC registers itself with flask.

**`config`** - a python `dict` of configuration parameters and options. **Required.**

### Configuration Options
**FlaskOIDC** is configured by passing a python `dict` with the necessary parameters:
> Example Configuration
```python
oidc_config = {
  "discovery_url": "https://login.microsoftonline.com/<tenentid>/V2.0/.well-known/openid-configuration",
  "client_id": "1b170767-1234-5678-abcd-90ff90ff90ff",
  "client_secret": "MYCLIENTsecret",
  "client_scope": ["openid", "email", "profile", ],
  "user_attr" : "email",
}
```

**`discovery_url`** - oidc auto discovery url of the IdP. **Required.**

**`client_id`** - oidc client identifier of the app registered with IdP. **Required.**

**`client_secret`** - oidc client secret for the app provided by the IdP. **Required.**

**`client_scope`** - a Python `list` of requested scopes. Default is *['openid', 'email', 'profile']*).

**`user_attr`** - attribute to set username. Default is `email`

**`logout_idp`** - on logout, initiate IdP logout process.  Default is `False`.

#### FlaskOIDC Object Properties
**`auth.is_authenticated`** - Is `True` if the current session is authenticated.

**`auth.my_username`** - Returns None if the user is not authenticated. Returns `user_attr` value from the Id token, or 'AuthenticatedUser' if the attribute was not available in the Id token.

**`auth.my_attrs`** - Returns dict of attrs returned in the OIDC Id token, or {} if not authenticated.

> Example using object properties:
```python
@app.route('/status')
def view():
    if auth.is_authenticated:
        return {
            'user': auth.my_username,
            'data': auth.my_attrs
        }
    else:
        return 'You are not Authenticated.'
```
### FlaskOIDC methods

#### auth.initiate_login()

```python
return auth.initiate_login(next, force_reauth, userhint)
```

`init_login()` returns OIDC code grant request redirect to iDP that initiates login. Arguments:

**`next`** - URL to redirect after login completed. Optional. 

**`force_reauth`** - `True` requests IdP to require full reauth for this login. Default `False`

**`userhint`** - (where possible) provides the iDP with username hint. Default `None`

#### auth.initiate_logout()
```python         
return auth.initiate_logout(next)
``` 
`initiate_logout()` clears the Session data to log the user out locally. (To logout from IdP set the **`logout_idp`** config option to `True`.)

**`next`** - URL to redirect after logout completed. Default is '/', *Optional.*

```python
@app.route('/logout')
def logout():
    return auth.initiate_logout()
```

#### @auth.login_required
```python
@app.route('/loginrequired')
@auth.login_required
def view():
    return 'logged in'
```
Decorates a function to initiate login if the session is not authenticated. On successful authentication the browser will be redirected to the view.

#### @auth.add_login_hook
```python
@oidc.add_login_hook
def hook(username, attrs):
    return username, attrs
```
Decorates a function to runs after OIDC authentication is completed and tokens have been retrieved. 

Login hooks can process and filter username and Id token attributes before the data is stored in the session.  Hooks are run in the order they are added.

#### @auth.require_user
```python
@auth.require_user(['bob', 'alice'])
def view():
    return 'only bob or alice can get here'
```
Decorator adds authorization requirement to a view. If the sessions `username` is in the list, the view is reached and processed. Otherwise returns a `403 Unauthorized` error if the user is not in the list.

#### @auth.require_attr(attr, value)
```python
@auth.require_attr(attr='groups', value=['sysadmin', 'netadmin']) 
def view():
    return 'you are in sysadmin or netadmin'
```
Decorator adds authorization requirement to a view. If the session has the desired attribute (in the id token) and it matches one of the values listed, the view is reached and processed. Otherwise returns a `403 Unauthorized` error.
