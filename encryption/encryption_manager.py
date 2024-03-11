import base64
import json
import pickle
import time
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, padding
from cryptography.hazmat.backends import default_backend
from os import urandom


class EncryptionManager:
    def __init__(self, config_manager):
        self.encryption_status = config_manager.get_encryption_status()
        self.key_cache = {}  # Cache for storing key and IV
        self.config_manager = config_manager

    def _get_current_key_and_iv(self, key_name):
        current_timestamp = time.time()
        if key_name in self.key_cache:
            key, iv, cached_timestamp = self.key_cache[key_name]
            if current_timestamp - cached_timestamp < 3600:  # 1 hour validity in seconds
                return key, iv

        # Fetch from storage if not in cache or cache is expired
        try:
            key, iv, stored_timestamp = self._retrieve_key_and_iv(key_name)
            if current_timestamp - stored_timestamp < 3600:  # Check validity
                self.key_cache[key_name] = (key, iv, stored_timestamp)
                return key, iv

            self.config_manager.destroy_and_delete_secret(key_name, "latest")

        except Exception as e:
            # If retrieval fails, log the exception and proceed to generate a new key
            print(f"Error retrieving key: {e}")

        # Generate new key and IV
        key = self._generate_symmetric_key()
        iv = urandom(16)
        self._save_key_and_iv(key_name, key, iv)
        self.key_cache[key_name] = (key, iv, current_timestamp)
        return key, iv

    def _save_key_and_iv(self, key_name, key, iv):
        data = {
            "key": b64encode(key).decode('utf-8'),
            "iv": b64encode(iv).decode('utf-8'),
            "timestamp": time.time()  # Current timestamp
        }
        encoded_data = b64encode(json.dumps(data).encode('utf-8'))
        self.config_manager.save_secret_to_gcloud(key_name, encoded_data)

    def _retrieve_key_and_iv(self, key_name):
        # Retrieve the base64-encoded data, which is a string
        base64_encoded_json_str = self.config_manager.get_key_iv(key_name)

        # First, decode the base64 string to get the actual JSON string in bytes
        json_bytes = b64decode(base64_encoded_json_str)

        # Then, decode the bytes to a string using UTF-8
        json_str = json_bytes.decode('utf-8')

        # Now, you can use json.loads() to deserialize the string into a Python object
        data = json.loads(json_str)

        # Extract 'key', 'iv', and 'timestamp' from the data, assuming they are base64 encoded
        key = b64decode(data["key"])
        iv = b64decode(data["iv"])
        timestamp = data["timestamp"]  # Assuming timestamp is in the expected format

        return key, iv, timestamp

    def _generate_symmetric_key(self):
        # Generate a random symmetric key for AES (256-bit key)
        return urandom(32)

    def _encrypt_data(self, data, key_name):
        try:
            key, iv = self._get_current_key_and_iv(key_name)

            # Ensure data is bytes
            if isinstance(data, str):
                data = data.encode('utf-8')

            elif isinstance(data, object):
                data = pickle.dumps(data)

            # Encrypt the data
            encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            return encrypted_data

        except Exception as e:
            print(f"Unable to encrypt data due to: {e}")
            raise Exception

    def _decrypt_data(self, encrypted_data, key_name):
        key, iv = self._get_current_key_and_iv(key_name)

        encrypted_data = base64.b64decode(encrypted_data)

        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        try:
            # Attempt to unpickle the decrypted data
            return pickle.loads(decrypted_data)
        except Exception:
            # If an error occurs, assume the data is a string and decode it
            try:
                return decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                # If decoding also fails, return the raw decrypted data
                # This might indicate binary data that isn't pickled or encoded text
                return decrypted_data

    def process_outgoing_object(self, object_to_encrypt, key_name):
        if self.encryption_status:
            return self._encrypt_data(object_to_encrypt, key_name)
        return object_to_encrypt

    def process_incoming_object(self, object_to_decrypt, key_name):
        if self.encryption_status:
            return self._decrypt_data(object_to_decrypt, key_name)
        return object_to_decrypt
