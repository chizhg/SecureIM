import socket
import cmd
import threading
import os
import sys
import Crypto
import Utils
import Message
import time
import ast
import getpass
from Message import SEPARATOR, MessageType, AuthStartMsg, MAX_MSG_SIZE, SEPARATOR1, ConnStartMsg, ConnBackMsg, \
    ConnEndMsg, TextMsg, DisconnMsg

MAX_RETRY_LOGIN_TIMES = 3
CMD_PROMPT = '+> '
MSG_PROMPT = '<- '


class UserInfo:
    def __init__(self):
        self.address = None
        self.sec_key = None
        self.pub_key = None
        self.ticket = None
        self.ticket_signature = None
        self.info_known = False
        self.c3_nonce = None
        self.c4_nonce = None
        self.connected = False


class ChatClient(cmd.Cmd):
    def __init__(self, ip, port, pub_key_file):
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock = None
        # user name for this chat client
        self.user_name = None
        # chat server ip, port and public key
        self.server_ip = ip
        self.server_port = port
        self.server_pub_key = Crypto.load_public_key(pub_key_file)
        # generate rsa key pair
        self.rsa_pri_key, self.rsa_pub_key = Crypto.generate_rsa_key_pair()
        # generate dh key pair
        self.dh_pri_key, self.dh_pub_key = Crypto.generate_dh_key_pair()
        # shared dh key
        self.shared_dh_key = None
        # chat client ip and port, used to receive messages
        self.client_ip = Utils.get_local_ip()
        self.client_port = Utils.get_free_port()
        # online-users known to the chatclient
        self.online_list = dict()
        # start socket for receiving messages
        self._start_recv_sock()
        # start commandline interactive mode
        cmd.Cmd.__init__(self)

    # --------------------------- login to the server ------------------------- #
    def login(self):
        login_times = 0
        logined = False
        while login_times < MAX_RETRY_LOGIN_TIMES and not logined:
            logined, user_name = self._auth_to_server()
            login_times += 1
            if logined:
                self.user_name = user_name
                chat_client.prompt = self.user_name + CMD_PROMPT
                chat_client.cmdloop('###### User <' + user_name + '> successfully login')
        if not logined:
            print 'Your retry times has exceeded the maximum allowed times, exit the program!'
            self.recv_sock.close()
            os._exit(0)

    def _auth_to_server(self):
        user_name = raw_input('Please input your user name: ')
        password = getpass.getpass('Please input your password: ')
        login_result = False
        self.user_name = user_name
        try:
            self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_sock.connect((self.server_ip, self.server_port))
            # Step 1: initiate the authentication to server
            auth_init_response = self._auth_init()
            solved_challenge = self._handle_auth_init_response(auth_init_response)
            # Step 2: send authentication start message(including user name, password, etc.) to the server
            c1_nonce, auth_start_response = self._auth_start(solved_challenge, user_name, password)
            auth_result, self.shared_dh_key, c2_nonce = self._handle_auth_start_response(c1_nonce, auth_start_response)
            # Step 3: send authentication confirmation message back to the server,
            # which is c2_nonce encrypted with dh_shared key
            if auth_result and self._auth_end(c2_nonce):
                login_result = True
        except socket.error:
            print 'Cannot connect to the server in the authentication process, exit the program!'
            os._exit(0)
        except:
            print 'Unknown error happens when trying to login: ', sys.exc_info()[0], ', please retry!'
        finally:
            if not login_result:
                self.client_sock.close()
            return login_result, user_name

    def _auth_init(self):
        init_msg = Message.dumps(MessageType.INIT)
        self.client_sock.sendall(init_msg)
        auth_init_response = self.client_sock.recv(MAX_MSG_SIZE)
        return auth_init_response

    @staticmethod
    def _handle_auth_init_response(auth_init_response):
        trunc_challenge = Utils.substring_before(auth_init_response, SEPARATOR)
        challenge_hash = Utils.substring_after(auth_init_response, SEPARATOR)
        solved_challenge = Utils.solve_challenge(trunc_challenge, challenge_hash)
        return solved_challenge

    def _auth_start(self, solved_challenge, user_name, password):
        c1_nonce = Utils.generate_nonce()
        msg = AuthStartMsg(
            user_name,
            password,
            Crypto.serialize_pub_key(self.rsa_pub_key),
            Crypto.serialize_pub_key(self.dh_pub_key),
            self.client_ip,
            self.client_port,
            c1_nonce
        )
        msg_str = Utils.serialize_obj(msg)
        encrypted_msg_str = Crypto.asymmetric_encrypt(self.server_pub_key, msg_str)
        full_msg = solved_challenge + SEPARATOR + encrypted_msg_str
        auth_start_msg = Message.dumps(MessageType.AUTH_START, full_msg)
        self.client_sock.sendall(auth_start_msg)
        auth_start_response = self.client_sock.recv(MAX_MSG_SIZE)
        return c1_nonce, auth_start_response

    def _handle_auth_start_response(self, expected_c1_nonce, auth_start_response):
        tpe, data = Message.loads(auth_start_response)
        if tpe == MessageType.RES_FOR_INVALID_REQ:
            print data
            return False, None, None
        decrypted_auth_start_response = Crypto.asymmetric_decrypt(self.rsa_pri_key, data)
        res_obj = Utils.deserialize_obj(decrypted_auth_start_response)
        server_dh_key, c1_nonce, c2_nonce = res_obj.dh_pub_key, res_obj.c1_nonce, res_obj.c2_nonce
        if str(expected_c1_nonce) != str(c1_nonce):
            return False, None, None
        shared_dh_key = Crypto.generate_shared_dh_key(self.dh_pri_key, Crypto.deserialize_pub_key(server_dh_key))
        return True, shared_dh_key, str(c2_nonce)

    def _auth_end(self, c2_nonce):
        iv = Utils.generate_iv()
        encrypted_c2_nonce = Crypto.symmetric_encrypt(self.shared_dh_key, iv, c2_nonce)
        auth_end_msg = Message.dumps(MessageType.AUTH_END,
                                     Crypto.asymmetric_encrypt(self.server_pub_key, iv) +
                                     SEPARATOR + encrypted_c2_nonce)
        self.client_sock.sendall(auth_end_msg)
        validate_result, decrypted_nonce_response = self._recv_sym_encrypted_msg_from_server(False)
        if validate_result and long(decrypted_nonce_response) == long(c2_nonce) + 1:
            return True
        else:
            return False

    # --------------------------- list online users ------------------------- #
    def do_list(self, arg):
        try:
            self._send_sym_encrypted_msg_to_server(MessageType.LIST_USERS, 'list')
            validate_result, list_response = self._recv_sym_encrypted_msg_from_server()
            if validate_result:
                print MSG_PROMPT + 'Online users: ' + ', '.join(list_response.user_names.split(SEPARATOR1))
                # set the client information in self.online_list
                parsed_list_response = list_response.user_names.split(SEPARATOR1)
                for user in parsed_list_response:
                    if user != self.user_name and user not in self.online_list:
                        self.online_list[user] = UserInfo()
        except (socket.error, ValueError) as e:
            self._re_login()
        except:
            print 'Unknown error happens when trying to get user name list from the server!'

    # --------------------------- send message to another user ------------------------- #
    def do_send(self, arg):
        try:
            receiver_name = Utils.substring_before(arg, SEPARATOR1)
            msg = Utils.substring_after(arg, SEPARATOR1)
            if receiver_name == self.user_name:
                print 'Cannot send message to yourself!'
            elif receiver_name not in self.online_list:
                print 'User not in client list! Try using list command to update the client list.'
            else:
                receiver_info = self.online_list[receiver_name]
                # if we don't know the receiver's user information
                if not receiver_info.info_known:
                    self._get_user_info(receiver_name)
                # if we haven't connected to this user
                if receiver_info.info_known and not receiver_info.connected:
                    self._connect_to_user(receiver_info)
                    # wait 1 seconds before successfully connected
                    time.sleep(1)
                # if we have already connected to this user, send message to the user
                if receiver_info.connected:
                    print '###### Sent message to the user <' + receiver_name + '>'
                    self._send_text_msg(msg, receiver_info)
                # otherwise we cannot send message to the user
                else:
                    print 'Cannot send message to the user because it is not connected.'
        except (socket.error, ValueError) as e:
            self._re_login()
        except:
            print 'Unknown error happens when trying to send message to another user!'

    # --------------------------- get user information from the server ------------------------- #
    def _get_user_info(self, user_name):
        self._send_sym_encrypted_msg_to_server(MessageType.GET_USER_INFO, user_name)
        validate_result, user_info_obj = self._recv_sym_encrypted_msg_from_server()
        if validate_result:
            # print target_address
            user_info = self.online_list[user_name]
            user_info.address = (user_info_obj.ip, user_info_obj.port)
            user_info.sec_key = user_info_obj.sec_key
            user_info.pub_key = Crypto.deserialize_pub_key(user_info_obj.pub_key)
            user_info.ticket = user_info_obj.ticket
            user_info.ticket_signature = user_info_obj.ticket_signature
            user_info.info_known = True

    # --------------------------- build connection with the user ------------------------- #
    def _connect_to_user(self, target_user_info):
        # start authentication process
        target_user_info.c3_nonce = Utils.generate_nonce()
        msg = ConnStartMsg(
            self.user_name,
            self.client_ip,
            self.client_port,
            Crypto.serialize_pub_key(self.rsa_pub_key),
            target_user_info.ticket,
            target_user_info.ticket_signature,
            target_user_info.c3_nonce,
            time.time()
        )
        self._send_encrypted_msg_to_user(target_user_info, MessageType.CONN_USER_START, msg)

    # --------------------------- send the final message to the target user ------------------------- #
    def _send_text_msg(self, msg, receiver_info):
        iv = Utils.generate_iv()
        sec_key = receiver_info.sec_key
        text_msg = TextMsg(
            self.user_name,
            Crypto.asymmetric_encrypt(receiver_info.pub_key, iv),
            Crypto.symmetric_encrypt(sec_key, iv, msg),
            Crypto.sign(self.rsa_pri_key, msg),
            time.time()
        )
        self._send_encrypted_msg_to_user(receiver_info, MessageType.TEXT_MSG, text_msg)

    # --------------------------- start a server socket to receive messages from other users ------------------------- #
    def _start_recv_sock(self):
        try:
            print '###### Start recv socket on ' + self.client_ip + ':' + str(self.client_port)
            self.recv_sock.bind((self.client_ip, self.client_port))
            threading.Thread(target=self._listen_msg).start()
        except socket.error:
            print 'Failed to start the socket for receiving messages'

    def _listen_msg(self):
        while True:
            msg, addr = self.recv_sock.recvfrom(MAX_MSG_SIZE)
            if not msg:
                break
            # print 'Receive message from ', addr, ':\n', msg
            tpe, data = Message.loads(msg)
            decrypted_data = Crypto.asymmetric_decrypt(self.rsa_pri_key, data)
            msg_obj = Utils.deserialize_obj(decrypted_data)
            # if the message's timestamp is invalid
            if not Utils.validate_timestamp(msg_obj.timestamp):
                print 'Timestamp of the message from another user is invalid, drop the message!'
                continue
            if tpe == MessageType.CONN_USER_START:
                self._handle_conn_start(msg_obj)
            elif tpe == MessageType.CONN_USER_RES:
                self._handle_conn_back(msg_obj)
            elif tpe == MessageType.CONN_USER_END:
                self._handle_conn_end(msg_obj)
            elif tpe == MessageType.DIS_CONN:
                self._handle_disconn_msg(msg_obj)
            elif tpe == MessageType.TEXT_MSG:
                self._handle_text_msg(msg_obj)

    def _handle_conn_start(self, conn_start_msg):
        ticket = conn_start_msg.ticket
        ticket_signature = conn_start_msg.ticket_signature
        if not Crypto.verify_signature(self.server_pub_key, ticket, ticket_signature):
            return
        src_user_name, sec_session_key, timestamp_to_expire = ticket.split(SEPARATOR1)
        if src_user_name != conn_start_msg.user_name or float(timestamp_to_expire) < time.time():
            return
        src_user_info = UserInfo()
        src_user_info.address = (conn_start_msg.ip, conn_start_msg.port)
        src_user_info.pub_key = Crypto.deserialize_pub_key(conn_start_msg.pub_key)
        src_user_info.sec_key = sec_session_key
        src_user_info.info_known = True
        self.online_list[conn_start_msg.user_name] = src_user_info
        # send connection back message to the initiator
        c3_nonce = conn_start_msg.c3_nonce
        src_user_info.c4_nonce = Utils.generate_nonce()
        iv = Utils.generate_iv()
        conn_back_msg = ConnBackMsg(
            self.user_name,
            iv,
            Crypto.symmetric_encrypt(src_user_info.sec_key, iv, str(c3_nonce)),
            src_user_info.c4_nonce,
            time.time()
        )
        self._send_encrypted_msg_to_user(src_user_info, MessageType.CONN_USER_RES, conn_back_msg)

    def _handle_conn_back(self, conn_back_msg):
        user_info = self.online_list[conn_back_msg.user_name]
        decrypted_c3_nonce = Crypto.symmetric_decrypt(user_info.sec_key,
                                                      conn_back_msg.iv,
                                                      conn_back_msg.encrypted_c3_nonce)
        if str(decrypted_c3_nonce) == str(user_info.c3_nonce):
            # print 'Successfully connected to the user <' + conn_back_msg.user_name + '>'
            user_info.connected = True
            iv = Utils.generate_iv()
            conn_end_msg = ConnEndMsg(
                self.user_name,
                iv,
                Crypto.symmetric_encrypt(user_info.sec_key, iv, str(conn_back_msg.c4_nonce)),
                time.time()
            )
            self._send_encrypted_msg_to_user(user_info, MessageType.CONN_USER_END, conn_end_msg)

    def _handle_conn_end(self, conn_end_msg):
        user_info = self.online_list[conn_end_msg.user_name]
        decrypted_c4_nonce = Crypto.symmetric_decrypt(user_info.sec_key, conn_end_msg.iv,
                                                      conn_end_msg.encrypted_c4_nonce)
        if str(user_info.c4_nonce) == str(decrypted_c4_nonce):
            user_info.connected = True

    def _handle_text_msg(self, text_msg):
        user_name = text_msg.user_name
        if user_name in self.online_list and self.online_list[user_name].connected:
            user_info = self.online_list[user_name]
            iv = Crypto.asymmetric_decrypt(self.rsa_pri_key, text_msg.iv)
            encrypted_msg = text_msg.encrypted_msg
            decrypted_msg = Crypto.symmetric_decrypt(user_info.sec_key, iv, encrypted_msg)
            msg_signature = text_msg.msg_signature
            if Crypto.verify_signature(user_info.pub_key, decrypted_msg, msg_signature):
                # print '\n' + MSG_PROMPT + '<From ' + ip + ':' + str(port) + ':' + user_name + ">: " + decrypted_msg
                print '\n' + user_name + MSG_PROMPT + decrypted_msg
                print self.user_name + CMD_PROMPT,

    def _handle_disconn_msg(self, disconn_msg):
        user_name = disconn_msg.user_name
        if user_name in self.online_list:
            del self.online_list[user_name]

    # --------------------------- logout the user and exit the program ------------------------- #
    def do_logout(self, arg):
        try:
            if self._logout_from_server():
                print '###### User <' + self.user_name + '> successfully logout.'
                self._disconnect_all_users()
                self.client_sock.close()
                self.recv_sock.close()
                os._exit(0)
        except:
            print 'Error happens when trying to exit the client!'
            os._exit(0)

    def _logout_from_server(self):
        self._send_sym_encrypted_msg_to_server(MessageType.LOGOUT, '')
        result, msg = self._recv_sym_encrypted_msg_from_server()
        return result

    def _disconnect_all_users(self):
        for user_name, user_info in self.online_list.iteritems():
            if user_info.connected:
                print '###### Disconnect to the user <' + user_name + '>'
                disconn_msg = DisconnMsg(self.user_name, time.time())
                self._send_encrypted_msg_to_user(user_info, MessageType.DIS_CONN, disconn_msg)

    # ------------------------ try to re-login if server broken down or reset ----------------------- #
    def _re_login(self):
        print 'Server broken down or reset, please try to re-login!'
        self.client_sock.close()
        self.user_name = None
        self.rsa_pri_key, self.rsa_pub_key = Crypto.generate_rsa_key_pair()
        self.dh_pri_key, self.dh_pub_key = Crypto.generate_dh_key_pair()
        self.shared_dh_key = None
        self.login()

    # --------------------------- common functions for message exchange ------------------------- #
    def _send_sym_encrypted_msg_to_server(self, message_type, msg):
        send_time = time.time()
        iv = Utils.generate_iv()
        plain_msg = msg + SEPARATOR + str(send_time)
        encrypted_msg = Crypto.symmetric_encrypt(self.shared_dh_key, iv, plain_msg)
        final_msg = Message.dumps(message_type,
                                  Crypto.asymmetric_encrypt(self.server_pub_key, iv) +
                                  SEPARATOR + encrypted_msg)
        self.client_sock.sendall(final_msg)

    def _recv_sym_encrypted_msg_from_server(self, validate_timestamp=True):
        encrypted_server_response = self.client_sock.recv(MAX_MSG_SIZE)
        tpe, data = Message.loads(encrypted_server_response)
        if tpe == MessageType.RES_FOR_INVALID_REQ:
            print data
            return False, data
        else:
            iv, encrypted_response_without_iv = data.split(SEPARATOR)
            decrypted_response = Crypto.symmetric_decrypt(self.shared_dh_key,
                                                          Crypto.asymmetric_decrypt(self.rsa_pri_key, iv),
                                                          encrypted_response_without_iv)
            if validate_timestamp:
                decrypted_response = Utils.deserialize_obj(decrypted_response)
                if not Utils.validate_timestamp(decrypted_response.timestamp):
                    return False, None
            return True, decrypted_response

    def _send_encrypted_msg_to_user(self, target_user_info, message_type, msg_obj):
        encrypted_msg = Crypto.asymmetric_encrypt(target_user_info.pub_key,
                                                  Utils.serialize_obj(msg_obj))
        msg = Message.dumps(message_type, encrypted_msg)
        self.send_sock.sendto(msg, target_user_info.address)

    # -------------- override default function: will be invoked if inputting invalid command -------------- #
    def default(self, line):
        print '=========== Only the following 3 commands are supported: ============='
        print '|| list: list all online user names                                 ||'
        print '|| send <user_name> <message>: send message to another online user  ||'
        print '|| logout: logout from the server and disconnect all other users    ||'
        print '======================================================================'


if __name__ == '__main__':
    config = Utils.load_config('conf/client.cfg')
    server_ip = config.get('server_info', 'ip')
    server_port = config.getint('server_info', 'port')
    server_pub_key = config.get('server_info', 'pub_key')

    # initialize the client
    chat_client = ChatClient(server_ip, server_port, server_pub_key)
    # connect the client to the chat server
    chat_client.login()
