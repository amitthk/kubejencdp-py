import os

class AppConfig(object):
    BASE_DIR=os.path.dirname(os.path.realpath(__file__))
    DEBUG = True
    TESTING = True
    SECRET_KEY='1230947fadsfad;slk78412;ewlsd'
    LDAP_TOP_DN='ou=People,dc=amitthk,dc=com'
    LDAP_AUTH_SERVER='ldap://192.168.0.119:389/'