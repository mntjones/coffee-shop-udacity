import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen

from dotenv import load_dotenv
import os
load_dotenv()

#REMOVE - in .env file
#AUTH0_DOMAIN = 'dev-icyd3s7p2aeojxvf.us.auth0.com'
#ALGORITHMS = ['RS256']
#API_AUDIENCE = 'udacity-test'
#CLIENT_ID = 'gJpszpl55Dl0opM5lrco5bmsCdRLjHTd'


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
    auth = request.headers.get('Authorization', None)

    if auth is None:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'No Authorization header found'
        }, 401)

    token = auth.split()

    if token[0] != 'Bearer':
        raise AuthError({
            'code': 'invalid-header',
            'description': 'Bearer missing from Authorization'
        }, 401)

    if len(token) <= 1 or len(token) > 2:
        raise AuthError({
            'code': 'invalid-header',
            'description': 'Authorization format incorrect'
        }, 401)

    return token[1]

'''
@INPUTS
    permission: string permission (i.e. 'post:drink')
    payload: decoded jwt payload
'''
def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'No permissions in token'
            }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Unauthorized attempt'
            }, 403)

    return True

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    raise Exception('Not Implemented')

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator