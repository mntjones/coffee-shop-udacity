import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen

from dotenv import load_dotenv
import os
load_dotenv()

#REMOVE - in .env file
AUTH0_DOMAIN = 'dev-xdrh4efh06zfn7ch.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'udacity-test'
CLIENT_ID = 'AxP76dlPMRuJUZjihzfs9gl6PqMUDlOe'


## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

def get_token_auth_header():

    #check if authorization header exists
    auth = request.headers.get('Authorization', None)

    if auth is None:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'No Authorization header found'
        }, 401)


    #splits authorization into parts - should be 2
    token = auth.split(' ')

    # checks for 'Bearer' in the beginning of authorization
    if token[0] != 'Bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Bearer missing from Authorization'
        }, 401)

    # check for correct length of authorization
    if len(token) != 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization format incorrect'
        }, 401)

    # returns token part of header
    return token[1]

'''
@INPUTS
    permission: string permission (i.e. 'post:drink')
    payload: decoded jwt payload
'''
def check_permissions(permission, payload):

    # checks if permissions in payload
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'No permissions in token'
            }, 400)

    # checks if requested permission string in the payload
    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found'
            }, 403)

    return True

'''
    @INPUTS
    token: a json web token (string)
    
    ex. 
    {"keys": [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "x5c": [
              "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
            ],
            "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
            "e": "AQAB",
            "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
            "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
        }
    ]}

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    #verify token with Auth0
    url = urlopen(f'https://{AUTO0_DOMAIN}/.well-known/jwks.json')

    #load json
    jwt_json = json.loads(jsonurl.read())

    #get header
    header_unv = jwt.get_unverified_header(token)

    # check if Auth0 token with kid id
    if 'kid' not in header_unv:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization format incorrect'
            }, 401)

    # get rsa_key by matching Auth0 'kid id'
    for key in jwkw['keys']:
        if key['kid'] == header_unv['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    # verify token
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms = ALGORITHMS,
                audience = API_AUDIENCE,
                issuer = f'https://{AUTH0_DOMAIN}/'
            )

            return payload
            
        #errors
        except jwt.ExpiredSignatureError:

            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired'
            }, 401)

        except jwt.JWTClaimsError:

            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Invalid claims'
            }, 401)

        except Exception:

            raise AuthError({
                'code': 'invalid_header',
                'description': 'Invalid token information'
            }, 401)

    raise AuthError({
        'code':'invalid_header',
        'description': 'No key to decode'
        }, 400)

'''
    @INPUTS
    permission: string permission (i.e. 'post:drink')
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # gets token
            token = get_token_auth_header()
            try:
                #decodes token
                payload = verify_decode_jwt(token)
            except:
                abort(401)
            # validate claims
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator