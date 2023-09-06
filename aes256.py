from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from data import Data
import base64
import os


backend = default_backend()

def generate_key():
    key = os.urandom(32)
    iv = os.urandom(16)

    return encode_b64(key+iv)


def encrypt(enc_key: str, data: bytes):
    try:
        data_hash = data[-32:]
        raw_data =  data[:-32]

        if check_hash(data_hash, raw_data):
            return Data(error="bu dosya daha önce zaten şifrelenmiş")
        
        decoded_key = decode_b64(enc_key)
        key, iv = decoded_key[:32], decoded_key[-16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher_data = encryptor.update(padded_data) + encryptor.finalize()
        return Data(data=cipher_data + hash_data(cipher_data))
    except Exception as e:
        return Data(error=e)

def decrypt(dec_key: str, encrypted_data: bytes):
    try:
        data_hash = encrypted_data[-32:]
        raw_data =  encrypted_data[:-32]
        
        if not check_hash(data_hash, raw_data):
            return Data(error="bu dosya şifreli değil yada bu yazılım tarafından şifrelenmemiş. Çözülemiyor.")
        
        decoded_key = decode_b64(dec_key)
        key, iv = decoded_key[:32], decoded_key[-16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(raw_data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return Data(data=unpadded_data)
    except Exception as e:
        return Data(error=e)



def encode_b64(data: bytes):
    return base64.b64encode(data).decode("utf-8")


def decode_b64(data: str):
    return base64.b64decode(data)


def hash_data(data: bytes):
    hash_object = hashes.Hash(hashes.SHA256())
    hash_object.update(data)
    hash_data = hash_object.finalize()
    return hash_data


def check_hash(data_hash: bytes, data: bytes):
    hashed_data = hash_data(data)
    if hashed_data == data_hash:
        return True
    else:
        return False
