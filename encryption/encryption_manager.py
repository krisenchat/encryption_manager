import datetime
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from os import urandom

from encryption.config_manager import ConfigManager

class EncryptionManager:
    def __init__(self, encryption_status):
        self.encryption_status = encryption_status
        self.key_cache = {}  # Cache for storing key and IV

    def _get_current_key_and_iv(self, key_name):
        if key_name in self.key_cache:
            key, iv, timestamp = self.key_cache[key_name]
            if datetime.datetime.now() - timestamp < datetime.timedelta(hours=1):  # 1 hour validity
                return key, iv
            else:
                ConfigManager.destroy_secret_version(key_name, version="latest")

        key = self._generate_symmetric_key()
        iv = urandom(16)

        self._save_key_and_iv(key_name, key, iv)
        # Update cache
        self.key_cache[key_name] = (key, iv, datetime.datetime.now())
        return key, iv

    def _generate_symmetric_key(self):
        # Generate a random symmetric key for AES (256-bit key)
        return urandom(32)

    def _encrypt_data(self, data, key_name):
        key, iv = self._get_current_key_and_iv(key_name)

        # Ensure data is bytes
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Encrypt the data
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted_data

    def _save_key_and_iv(self, key_name, key, iv):
        # Convert the key and iv from bytes to a string for storage
        encoded_key_iv = b64encode(key + iv).decode('utf-8')
        ConfigManager.save_secret_to_gcloud(key_name, encoded_key_iv)

    def _retrieve_key_and_iv(self, key_name):
        # Fetch the combined key and IV
        encoded_key_iv = ConfigManager.get_key_iv(key_name)
        key_iv = b64decode(encoded_key_iv)
        key, iv = key_iv[:32], key_iv[32:]
        return key, iv

    def _decrypt_data(self, encrypted_data, key_name):
        key, iv = self._get_current_key_and_iv(key_name)

        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data.decode('utf-8')

    def process_outgoing_object(self, object_to_encrypt, key_name):
        if self.encryption_status:
            return self._encrypt_data(object_to_encrypt, key_name)
        return object_to_encrypt

    def process_incoming_object(self, object_to_decrypt, key_name):
        if self.encryption_status:
            return self._decrypt_data(object_to_decrypt, key_name)
        return object_to_decrypt
