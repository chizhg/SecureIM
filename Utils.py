import socket
import commands
import os
import pickle
import base64
import time
import ConfigParser
import Crypto
import Message


# ---------------------- Network related utils -----------------------#
def get_free_port():
    # get free port : creating a new socket (port is randomly assigned), and close it
    sock = socket.socket()
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return int(port)


def get_local_ip():
    # get local ip address with ifconfig command, can be applied on unix platform
    ip_info = commands.getoutput('/sbin/ifconfig').split('\n')
    for ip_line in ip_info:
        if ip_line.find('inet') != -1 and ip_line.find('netmask') != -1 and ip_line.find('ast') != -1:
            ip = ip_line.split(' ')[1].strip()
            return ip
    # if failed to get ip with ifconfig, return '127.0.0.1' by default
    return '127.0.0.1'


# ---------------------- Other specific utils -----------------------#
def load_config(config_file):
    config = ConfigParser.RawConfigParser()
    config.read(config_file)
    return config


def validate_timestamp(timestamp):
    cur_time = time.time()
    if cur_time - float(timestamp) > Message.MAX_TIMESTAMP_GAP:
        print 'Timestamp gap is too large, invalid message!'
        return False
    return True


# ---------------------- String related utils -----------------------#
def substring_before(s, splitter):
    split_index = s.find(splitter)
    if split_index != -1:
        return s[0:split_index].strip()
    return ''


def substring_after(s, splitter):
    split_index = s.find(splitter)
    if split_index != -1:
        return s[split_index:].strip()
    return ''


# ---------------------- Nonce related utils -----------------------#
def generate_nonce(size=128):
    nonce_str = os.urandom(size / 8)
    nonce_num = long(nonce_str.encode('hex'), 16)
    return nonce_num


def generate_challenge():
    challenge = generate_nonce()
    trunc_challenge = challenge & 0x0000ffffffffffffffffffffffffffff
    challenge_hash = Crypto.generate_hash(str(challenge))
    return challenge, challenge_hash, trunc_challenge


def solve_challenge(trunc_challenge, challenge_hash):
    trunc_challenge = long(trunc_challenge)
    guessed_challenge = trunc_challenge
    n = 0
    while len(str(guessed_challenge)) <= 40:
        guessed_challenge = str(trunc_challenge + (n << 112))
        if Crypto.generate_hash(guessed_challenge) == challenge_hash:
            return guessed_challenge
        n += 1


def generate_iv():
    return base64.b64encode(os.urandom(16))


def generate_symmetric_key():
    return base64.b64encode(os.urandom(32))


# ---------------------- Object serialization related utils -----------------------#
def serialize_obj(obj):
    return pickle.dumps(obj, pickle.HIGHEST_PROTOCOL)


def deserialize_obj(obj_str):
    return pickle.loads(obj_str)
