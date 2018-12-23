from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from functools import wraps
from flask import Blueprint, current_app, jsonify, Response, request, url_for
import json
import ldap


class AppAuth:
    @staticmethod
    def generate_auth_token(app, data, expiration=500):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'payload': data}).decode('utf-8')

    @staticmethod
    def verify_auth_token(app, auth_token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            token = auth_token
            if auth_token.startswith('Bearer '):
                token=auth_token[7:]
            data=s.loads(auth_token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        return s.dumps({'payload': data})

    @staticmethod
    def verify_password(app, username, password):
        connection = ldap.initialize(app.config['LDAP_AUTH_SERVER'])
        try:
            user_dn = 'uid={},{}'.format(username,app.config['LDAP_TOP_DN'])
            connection.simple_bind_s(user_dn, password)
            result = connection.search_s(
            app.config['LDAP_TOP_DN'],
            ldap.SCOPE_ONELEVEL,
            '(uid={})'.format(username)
            )
            if not result:
                print 'User doesn\'t exist'
                return None
            else:
                dn = result[0]
                connection.unbind_s()
                return dn
        except ldap.INVALID_CREDENTIALS:
            return None


# EOF
