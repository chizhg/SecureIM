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
    # get local ip address by trying to connect to the DNS of google
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip


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
