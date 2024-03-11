import unittest
from unittest.mock import Mock, patch

from encryption.encryption_manager import EncryptionManager


class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.mock_config_manager = Mock()
        self.encryption_manager = EncryptionManager(config_manager=self.mock_config_manager)

    @patch('encryption.encryption_manager.urandom')  # Assuming urandom is in the same module, adjust the import path as necessary
    @patch('encryption.encryption_manager.time.time', side_effect=[100, 200])  # Mock time to simulate passage of time
    def test_get_current_key_and_iv_with_cache_miss(self, mock_time, mock_urandom):
        # Setup
        key_name = "test_key"
        expected_key = b'key'
        expected_iv = b'iv'
        mock_urandom.side_effect = [expected_key, expected_iv]

        # Execute
        result_key, result_iv = self.encryption_manager._get_current_key_and_iv(key_name)

        # Verify
        self.assertEqual(result_key, expected_key)
        self.assertEqual(result_iv, expected_iv)
        self.mock_config_manager.save_secret_to_gcloud.assert_called_once()  # Ensure it attempts to save the new key

    @patch('encryption.encryption_manager.time.time', side_effect=[100, 101])  # Mock time to ensure cache is used
    def test_get_current_key_and_iv_with_cache_hit(self, mock_time):
        # Setup
        key_name = "test_key"
        self.encryption_manager.key_cache[key_name] = (b'key', b'iv', 100)  # Pretend cache has valid data

        # Execute
        result_key, result_iv = self.encryption_manager._get_current_key_and_iv(key_name)

        # Verify
        self.assertEqual(result_key, b'key')
        self.assertEqual(result_iv, b'iv')
        self.mock_config_manager.get_key_iv.assert_not_called()  # Ensure it does not attempt to fetch from storage

    @patch('encryption.encryption_manager.b64decode')
    def test_retrieve_key_and_iv(self, mock_b64decode):
        # Setup
        key_name = "test_key"
        self.mock_config_manager.get_key_iv.return_value = "encoded_data"
        mock_b64decode.side_effect = [b'{"key": "a2V5", "iv": "aXY=", "timestamp": 1000}', b'key',
                                      b'iv']  # Mocked decoded values

        # Execute
        key, iv, timestamp = self.encryption_manager._retrieve_key_and_iv(key_name)

        # Verify
        self.mock_config_manager.get_key_iv.assert_called_with(key_name)
        self.assertEqual(timestamp, 1000)
        mock_b64decode.assert_called()

    @patch('encryption.encryption_manager.b64encode')
    @patch('encryption.encryption_manager.time.time', return_value=1000)
    def test_save_key_and_iv(self, mock_time, mock_b64encode):
        # Setup
        key_name = "test_key"
        key = b'key'
        iv = b'iv'
        mock_b64encode.side_effect = [b'encoded_key', b'encoded_iv', b'encoded_data']  # Mocked encoded values

        # Execute
        self.encryption_manager._save_key_and_iv(key_name, key, iv)

        # Verify
        self.mock_config_manager.save_secret_to_gcloud.assert_called_once()
        mock_b64encode.assert_called()
        mock_time.assert_called_once()

    @patch('encryption.encryption_manager.Cipher')
    def test_encrypt_data_success(self, mock_cipher):
        # Setup
        mock_encryptor = Mock()
        mock_cipher.return_value.encryptor.return_value = mock_encryptor
        mock_encryptor.update.return_value = b'encrypted_data_part'
        mock_encryptor.finalize.return_value = b'encrypted_data_final'

        # Correctly mock _get_current_key_and_iv to return a 32-byte key and a 16-byte IV
        self.encryption_manager._get_current_key_and_iv = Mock(return_value=(b'\x00' * 32, b'\x00' * 16))

        # Execute
        encrypted_data = self.encryption_manager._encrypt_data(b'data', 'test_key')

        # Verify
        self.assertTrue(mock_cipher.called)
        self.assertIn(b'encrypted_data_partencrypted_data_final', encrypted_data)


