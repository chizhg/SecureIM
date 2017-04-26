import socket
import threading
import csv
import Crypto
import os
import Message
import Utils
import time

from Message import MessageType, SEPARATOR, SEPARATOR1, MAX_MSG_SIZE

USERS_INFO_FILE = 'users.csv'
DELIMITER = ','
QUOTECHAR = '|'
# MSS = 1460


class UserState(object):
    INIT = 0,
    VERIFIED = 1,
    AUTHENTICATED = 2


class UserInfo:
    def __init__(self, challenge):
        self.state = UserState.INIT
        self.challenge = challenge
        self.rsa_pub_key = None
        self.secret_key = None
        self.user_name = ''
        self.ip = ''
        self.port = ''
        self.temp_nonce = ''


class ChatServer:
    def __init__(self, host, port, private_key_file):
        self.host = host
        self.port = port
        self.pri_key = Crypto.load_private_key(private_key_file)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.all_users = self._load_users_info()
        self.login_users = dict()

    @staticmethod
    def _load_users_info():
        users_info = dict()
        with open(USERS_INFO_FILE, 'rb') as csv_file:
            rows = csv.reader(csv_file, delimiter=DELIMITER, quotechar=QUOTECHAR)
            for row in rows:
                username = row[0]
                salt_and_hash = (row[1], row[2])
                users_info[username] = salt_and_hash
        return users_info

    def run(self):
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            threading.Thread(target=self._listen_to_exit, args=()).start()
            print 'Server Initialized on ' + self.host + ':' + str(self.port) + ' ...'
            while True:
                connection, client_address = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(connection, client_address)).start()
        except socket.error:
            print 'Failed to start the chat server'

    def _listen_to_exit(self):
        while True:
            cmd = raw_input()
            if cmd == 'exit':
                print 'shut down the server'
                self.sock.close()
                os._exit(0)

    def _handle_client(self, connection, client_address):
        try:
            while True:
                # total_data = []
                # while True:
                #     data = connection.recv(MAX_MSG_SIZE)
                #     total_data.append(data)
                #     if len(data) != MSS:
                #         break
                # msg = ''.join(total_data)
                msg = connection.recv(MAX_MSG_SIZE)
                if not msg:
                    break
                tpe, data = Message.loads(msg)
                # ----------------- handle messages sent from unauthenticated users --------------------#
                # handle authentication init message
                if tpe == MessageType.INIT and client_address not in self.login_users:
                    print 'receive authentication init message from ', client_address
                    self._handle_client_init(connection, client_address)
                # handle authentication start message
                elif tpe == MessageType.AUTH_START and client_address in self.login_users \
                        and self.login_users[client_address].state == UserState.INIT:
                    print 'receive authentication start message from ', client_address
                    ver_result, response_msg = self._handle_client_auth_start(client_address, data)
                    if not ver_result:
                        self._client_error(connection, client_address)
                        break
                    connection.sendall(response_msg)
                # handle authentication end message
                elif tpe == MessageType.AUTH_END and client_address in self.login_users \
                        and self.login_users[client_address].state == UserState.VERIFIED:
                    print 'receive authentication end message from ', client_address
                    auth_result = self._handle_client_auth_end(client_address, data)
                    if not auth_result:
                        self._client_error(connection, client_address)
                        break
                    self.login_users[client_address].state = UserState.AUTHENTICATED
                    print 'successfully login user: ', self.login_users[client_address].user_name
                # ----------------- handle messages sent from authenticated users --------------------#
                elif client_address in self.login_users and self.login_users[
                    client_address].state == UserState.AUTHENTICATED:
                    iv, encrypted_msg = data.split(SEPARATOR)
                    user_info = self.login_users[client_address]
                    decrypted_msg = Crypto.symmetric_decrypt(user_info.secret_key,
                                                             Crypto.asymmetric_decrypt(self.pri_key, iv),
                                                             encrypted_msg)
                    # handle list message
                    if tpe == MessageType.LIST_USERS:
                        print 'receive list request message from ', client_address
                        self._handle_client_list(user_info, connection, decrypted_msg)
                    # handle get user info message
                    elif tpe == MessageType.GET_USER_INFO:
                        print 'receive get user info message from ', client_address
                        self._handle_get_user_info(user_info, connection, decrypted_msg)
                    # handle validate user message
                    elif tpe == MessageType.VALIDATE_USER_INFO:
                        print 'receive validate user info message from ', client_address
                        self._handle_val_user_info(user_info, connection, decrypted_msg)
                    # handle logout message
                    elif tpe == MessageType.LOGOUT:
                        print 'receive logout message from ', client_address
                        self._handle_logout(user_info, client_address, connection, decrypted_msg)
                    else:
                        print 'illegal message type: ', tpe
        except:
            print 'Error happens when handling client messages, break the connection!'
            self._client_error(connection, client_address)
        finally:
            print 'Close the connection with ' + str(client_address)
            connection.close()

    # --------------------------- login related messages ------------------------- #
    def _handle_client_init(self, connection, client_address):
        challenge, challenge_hash, trunc_challenge = Utils.generate_challenge()
        connection.sendall(str(trunc_challenge) + SEPARATOR + challenge_hash)
        user_info = UserInfo(str(challenge))
        self.login_users[client_address] = user_info

    def _handle_client_auth_start(self, client_address, data):
        challenge = Utils.substring_before(data, SEPARATOR)
        auth_start_msg = Crypto.asymmetric_decrypt(self.pri_key, Utils.substring_after(data, SEPARATOR))
        auth_start_msg_obj = Utils.deserialize_obj(auth_start_msg)
        # if the challenge solution is wrong, return false directly
        if challenge != self.login_users[client_address].challenge:
            return False, None
        user_name = auth_start_msg_obj.user_name
        # the same user cannot login twice
        if self._find_user_info_by_name(user_name) is not None:
            return False, None
        # if the provided password is wrong
        password = auth_start_msg_obj.password
        if not self._verify_password(user_name, password):
            return False, None
        # set user information
        user_info_obj = self.login_users[client_address]
        user_info_obj.user_name = auth_start_msg_obj.user_name
        user_info_obj.ip = auth_start_msg_obj.ip
        user_info_obj.port = int(auth_start_msg_obj.port)
        user_info_obj.rsa_pub_key = Crypto.deserialize_pub_key(auth_start_msg_obj.rsa_pub_key)
        user_info_obj.state = UserState.VERIFIED
        # DH key exchange
        user_dh_pub_key = Crypto.deserialize_pub_key(auth_start_msg_obj.dh_pub_key)
        dh_pri_key, dh_pub_key = Crypto.generate_dh_key_pair()
        user_info_obj.secret_key = Crypto.generate_shared_dh_key(dh_pri_key, user_dh_pub_key)
        # compose response message
        c1_nonce = auth_start_msg_obj.c1_nonce
        c2_nonce = Utils.generate_nonce(32)
        user_info_obj.temp_nonce = c2_nonce
        serialized_dh_pub_key = Crypto.serialize_pub_key(dh_pub_key)
        response_msg = serialized_dh_pub_key + SEPARATOR + str(c1_nonce) + SEPARATOR + str(c2_nonce)
        encrypted_response_msg = Crypto.asymmetric_encrypt(user_info_obj.rsa_pub_key, response_msg)
        return True, encrypted_response_msg

    def _verify_password(self, user_name, password):
        if user_name not in self.all_users:
            return False
        salt, pwd_hash = self.all_users[user_name]
        if Crypto.generate_hash(password, salt) != pwd_hash:
            return False
        return True

    def _handle_client_auth_end(self, client_address, data):
        user_info = self.login_users[client_address]
        iv, encrypted_c2_nonce = data.split(SEPARATOR)
        received_c2_nonce = Crypto.symmetric_decrypt(user_info.secret_key,
                                                     Crypto.asymmetric_decrypt(self.pri_key, iv),
                                                     encrypted_c2_nonce)
        return received_c2_nonce == str(user_info.temp_nonce)

    # --------------------------- get all users' names --------------------------- #
    def _handle_client_list(self, request_user_info, connection, received_list_message):
        list_flag, list_send_time = received_list_message.split(SEPARATOR)
        if self._check_timestamp(connection, list_send_time):
            current_user_names = SEPARATOR1.join(user.user_name for client_addr, user in self.login_users.iteritems())
            self._send_sym_encrypted_msg_to_client(connection, request_user_info, current_user_names)

    # --------------------------- get information of another user ------------------------- #
    def _handle_get_user_info(self, request_user_info, connection, user_info_msg):
        target_user_name, send_time = user_info_msg.split(SEPARATOR)
        if not self._check_timestamp(connection, send_time):
            return
        target_user_info = self._find_user_info_by_name(target_user_name)
        if target_user_info is not None:
            key_between_client = Utils.generate_symmetric_key()
            target_pubkey = target_user_info.rsa_pub_key
            target_message = str((target_user_info.ip, target_user_info.port)) + SEPARATOR + \
                             key_between_client + SEPARATOR + \
                             Crypto.serialize_pub_key(target_pubkey)
            self._send_sym_encrypted_msg_to_client(connection, request_user_info, target_message)
        else:
            connection.sendall(
                Message.dumps(MessageType.RES_FOR_INVALID_REQ, 'The user <' + target_user_name + '> is offline!'))

    def _find_user_info_by_name(self, user_name):
        for user_addr in self.login_users:
            login_user_info = self.login_users[user_addr]
            if login_user_info.user_name == user_name:
                return login_user_info
        return None

    # --------------------------- user validation request ------------------------- #
    def _handle_val_user_info(self, request_user_info, connection, val_user_msg):
        user_name, ip, port, timestamp = val_user_msg.split(SEPARATOR)
        if not self._check_timestamp(connection, timestamp):
            return
        user_info_to_val = self._find_user_info_by_name(user_name)
        if user_info_to_val is not None and user_info_to_val.ip == ip and str(user_info_to_val.port) == port:
            self._send_sym_encrypted_msg_to_client(connection, request_user_info, 'OK')
        else:
            connection.sendall(
                Message.dumps(MessageType.RES_FOR_INVALID_REQ, 'Invalid user information!'))

    # --------------------------- logout the user ------------------------- #
    def _handle_logout(self, request_user_info, client_address, connection, logout_msg):
        n, timestamp = logout_msg.split(SEPARATOR)
        if not self._check_timestamp(connection, timestamp):
            return
        if client_address in self.login_users:
            del self.login_users[client_address]
            self._send_sym_encrypted_msg_to_client(connection, request_user_info, 'OK')
        else:
            connection.sendall(
                Message.dumps(MessageType.RES_FOR_INVALID_REQ, 'Trying to logout an offline user!'))

    # ------------ Common function using symmetric encryption to send back message to client -------------- #
    @staticmethod
    def _send_sym_encrypted_msg_to_client(connection, request_user_info, msg):
        iv = Utils.generate_iv()
        res_message = msg + SEPARATOR + str(time.time())
        encrypted_res_message = Crypto.symmetric_encrypt(request_user_info.secret_key, iv, res_message)
        send_res_msg = Message.dumps(MessageType.RES_FOR_VALID_REQ,
                                     Crypto.asymmetric_encrypt(request_user_info.rsa_pub_key, iv) +
                                     SEPARATOR + encrypted_res_message)
        connection.sendall(send_res_msg)

    def _client_error(self, connection, client_address):
        del self.login_users[client_address]
        connection.close()

    @staticmethod
    def _check_timestamp(connection, timestamp):
        if not Utils.validate_timestamp(timestamp):
            connection.sendall(
                Message.dumps(MessageType.RES_FOR_INVALID_REQ, 'Timestamp gap is too large, invalid message!'))
            return False
        return True


if __name__ == '__main__':
    # parse the innput parameters
    config = Utils.load_config('server.cfg')
    port_num = config.getint('info', 'port')
    pri_key = config.get('info', 'pri_key')
    host_name = Utils.get_local_ip()
    # create the chat server
    chat_server = ChatServer(host_name, port_num, pri_key)
    # start running the chat server
    chat_server.run()
