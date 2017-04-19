import base64

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature


def generate_rsa_key_pair(public_exponent=65537, key_size=1024):
    rsa_private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend()
    )
    rsa_public_key = rsa_private_key.public_key()
    return rsa_private_key, rsa_public_key


# sign the plain text with private key, and return the signature
def sign(private_key, plain_text):
    signer = private_key.signer(
        asymmetric_padding.PSS(
            mgf=asymmetric_padding.MGF1(hashes.SHA256()),
            salt_length=asymmetric_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signer.update(plain_text)
    signature = signer.finalize()
    return base64.b64encode(signature)


# use AES and CTR mode to symmetrically encrypt the plain text, and return the encryption result
def symmetric_encrypt(key, iv, ori_text):
    cipher = Cipher(algorithms.AES(base64.b64decode(key)), modes.CTR(base64.b64decode(iv)), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(ori_text) + encryptor.finalize()
    return base64.b64encode(cipher_text)


# use AES and CTR mode to symmetrically decrypt the encrypted text, and return the decryption result
def symmetric_decrypt(key, iv, encrypted_text):
    cipher = Cipher(algorithms.AES(base64.b64decode(key)), modes.CTR(base64.b64decode(iv)), backend=default_backend())
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(base64.b64decode(encrypted_text)) + decryptor.finalize()
    return plain_text


# asymmetrically encrypt the given message with rsa
def asymmetric_encrypt(public_key, message):
    key_size = public_key.key_size
    seg_size = key_size / 8 - 42
    cipher_text = ''
    msg_size = len(message)
    start = 0
    while start < msg_size:
        seg_msg = message[start: min(start + seg_size, msg_size)]
        seg_cipher_text = public_key.encrypt(
            seg_msg,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA1(),
                label=None))
        cipher_text += base64.b64encode(seg_cipher_text)
        start += seg_size
    return cipher_text


# asymmetrically decrypt the given message with rsa
def asymmetric_decrypt(private_key, encrypted_msg):
    key_size = private_key.key_size
    encrypted_seg_size = (key_size / 8 - 42) * 2
    plain_text = ''
    encrypted_msg_size = len(encrypted_msg)
    start = 0
    try:
        while start < encrypted_msg_size:
            seg_encrypted_msg = encrypted_msg[start: start + encrypted_seg_size]
            seg_plain_text = private_key.decrypt(
                base64.b64decode(seg_encrypted_msg),
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA1(),
                    label=None))
            plain_text += seg_plain_text
            start += encrypted_seg_size
        return plain_text
    except (TypeError, ValueError):
        print 'failed to decrypt the text asymmetrically, exit the program!'
        exit(-1)


# verify the sign with private key, and return the result
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            base64.b64decode(signature),
            message,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def generate_hash(data, salt=''):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    if salt != '':
        digest.update(salt)
    digest.update(data)
    hash_val = base64.b64encode(digest.finalize())
    return hash_val


# The Elliptic Curve Diffie-Hellman Key Exchange algorithm
def generate_dh_key_pair():
    dh_pri_key = ec.generate_private_key(
        ec.SECP384R1, default_backend()
    )
    dh_pub_key = dh_pri_key.public_key()

    return dh_pri_key, dh_pub_key


def generate_shared_dh_key(x_pri_key, y_pub_key):
    shared_key = x_pri_key.exchange(ec.ECDH(), y_pub_key)
    xkdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=None,
        backend=default_backend()
    )
    return base64.b64encode(xkdf.derive(shared_key))


def serialize_pri_key(pri_key):
    serialized_pri_key = pri_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(serialized_pri_key)


def deserialize_pri_key(serialized_pri_key):
    pri_key = serialization.load_pem_private_key(
        base64.b64decode(serialized_pri_key),
        password=None,
        backend=default_backend()
    )
    return pri_key


def serialize_pub_key(pub_key):
    serialized_pub_key = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(serialized_pub_key)


def deserialize_pub_key(serialized_pub_key):
    pub_key = serialization.load_pem_public_key(
        base64.b64decode(serialized_pub_key),
        backend=default_backend()
    )
    return pub_key


def load_private_key(key_file):
    with open(key_file, 'r') as f:
        private_key_str = f.read()
        return deserialize_pri_key(base64.b64encode(private_key_str))


def load_public_key(key_file):
    with open(key_file, 'r') as f:
        public_key_str = f.read()
        return deserialize_pub_key(base64.b64encode(public_key_str))
