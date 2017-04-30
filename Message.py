import json

SEPARATOR = '\n'
SEPARATOR1 = ' '
MAX_MSG_SIZE = 65536

MAX_TIMESTAMP_GAP = 10


class MessageType(object):
    INIT = 'INIT'
    AUTH_START = 'AUTH_START'
    AUTH_END = 'AUTH_END'

    LIST_USERS = 'LIST_USERS'
    GET_USER_INFO = 'GET_USER_INFO'

    CONN_USER_START = 'CONN_USER_START'
    CONN_USER_RES = 'CONN_USER_RES'
    CONN_USER_END = 'CONN_USER_END'
    DIS_CONN = 'DIS_CONN'

    TEXT_MSG = 'PLAIN_MSG'
    LOGOUT = 'LOGOUT'

    RES_FOR_INVALID_REQ = 'RES_FOR_INVALID_REQ'
    RES_FOR_VALID_REQ = 'RES_FOR_VALID_REQ'


def loads(msg):
    json_obj = json.loads(msg)
    tpe = json_obj['type']
    data = json_obj['data']
    return tpe, data


def dumps(tpe, data=''):
    msg = dict()
    msg['type'] = tpe
    msg['data'] = data
    return json.dumps(msg)


class AuthStartMsg(object):
    def __init__(self,
                 user_name,
                 password,
                 rsa_pub_key,
                 dh_pub_key,
                 ip,
                 port,
                 c1_nonce):
        self.user_name = user_name
        self.password = password
        self.rsa_pub_key = rsa_pub_key
        self.dh_pub_key = dh_pub_key
        self.ip = ip
        self.port = port
        self.c1_nonce = c1_nonce


class AuthStartRes(object):
    def __init__(self,
                 dh_pub_key,
                 c1_nonce,
                 c2_nonce):
        self.dh_pub_key = dh_pub_key
        self.c1_nonce = c1_nonce
        self.c2_nonce = c2_nonce


class UserListRes(object):
    def __init__(self,
                 user_names,
                 timestamp=None):
        self.user_names = user_names
        self.timestamp = timestamp


class UserInfoRes(object):
    def __init__(self,
                 ip,
                 port,
                 sec_key,
                 ticket,
                 ticket_signature,
                 pub_key,
                 timestamp=None):
        self.ip = ip
        self.port = port
        self.sec_key = sec_key
        self.ticket = ticket
        self.ticket_signature = ticket_signature
        self.pub_key = pub_key
        self.timestamp = timestamp


class ConnStartMsg(object):
    def __init__(self,
                 user_name,
                 ip,
                 port,
                 pub_key,
                 ticket,
                 ticket_signature,
                 c3_nonce,
                 timestamp):
        self.user_name = user_name
        self.ip = ip
        self.port = port
        self.pub_key = pub_key
        self.ticket = ticket
        self.ticket_signature = ticket_signature
        self.c3_nonce = c3_nonce
        self.timestamp = timestamp


class ConnBackMsg(object):
    def __init__(self,
                 user_name,
                 iv,
                 encrypted_c3_nonce,
                 c4_nonce,
                 timestamp):
        self.user_name = user_name
        self.iv = iv
        self.encrypted_c3_nonce = encrypted_c3_nonce
        self.c4_nonce = c4_nonce
        self.timestamp = timestamp


class ConnEndMsg(object):
    def __init__(self,
                 user_name,
                 iv,
                 encrypted_c4_nonce,
                 timestamp):
        self.user_name = user_name
        self.iv = iv
        self.encrypted_c4_nonce = encrypted_c4_nonce
        self.timestamp = timestamp


class TextMsg(object):
    def __init__(self,
                 user_name,
                 iv,
                 encrypted_msg,
                 msg_signature,
                 timestamp):
        self.user_name = user_name
        self.iv = iv
        self.encrypted_msg = encrypted_msg
        self.msg_signature = msg_signature
        self.timestamp = timestamp


class DisconnMsg(object):
    def __init__(self,
                 user_name,
                 timestamp):
        self.user_name = user_name
        self.timestamp = timestamp


class LogoutRes(object):
    def __init__(self,
                 result,
                 timestamp=None):
        self.result = result
        self.timestamp = timestamp
