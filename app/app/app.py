import sys
import os
import json
import configparser
from functools import wraps

import flask_restplus

from flask import Flask, request, abort, Response, jsonify, url_for, session
from flask_restplus import Api, Resource, fields, reqparse

from AppAuth import AppAuth
from config import AppConfig

DEBUG = True

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_object('config.AppConfig')
app.config.from_pyfile(os.path.join(".", "config/env.cfg"), silent=False)

config = configparser.ConfigParser

api = Api(app, version='1.0', title='Simple Ldap App', description = 'Simple Flask Ldap App')
ns = api.namespace('pyfln',description='Simple Flask Ldap App')

def must_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            flask_restplus.abort(401, 'Requires authentication!')
        if AppAuth.verify_auth_token(app,auth_header) is None:
            flask_restplus.abort(403, 'Authentication token is expired or invalid!')
        return f(*args, **kwargs)
    return decorated

login_model = api.model("loginmodel", {
    "username": fields.String("Username."),
    "password": fields.String("Password.")
})


@ns.route("/auth_token")
class AuthToken(Resource):
    @api.expect(login_model)
    def post(self):
        error=None
        login_m = api.payload
        user = str(login_m['username'])
        passwd = str(login_m['password'])
        if AppAuth.verify_password(app, user,passwd) is not None:
            session['logged_in'] = True
            return {'Basic': str(AppAuth.generate_auth_token(app, user))}
        else:
            error = 'Invalid Credentials, please try again later!'
            return authenticate()
    def get(self):
        session['logged_in']=False
        return Response(json.dumps({ 'status': 200, 'message': 'You are successfully logged out!'}),200)
@ns.route("/index")
class Home(Resource):
    method_decorators=[must_auth]
    def get(self):
        return json.dumps({'payload': ['You','Got','Data']})

def authenticate():
    message = {
        'error': 'unauthorized',
        'message': 'Invalid Credentials, please try again later!',
        'status': 403
        }
    response = Response(
        json.dumps(message),
        403,
        {
            'WWW-Authenticate': 'Basic realm="Authentication Required"',
            'Location': url_for('pyfln_auth_token')
            }
        )
    return response

if __name__=="__main__":
    app.run(host='0.0.0.0')