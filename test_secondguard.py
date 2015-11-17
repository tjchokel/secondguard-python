import unittest

# Traversal
from secondguard.utils import is_valid_seed_hex, is_seed_hash_pair, derive_child_key

# API
from secondguard.api import ping  # , get_encryption_info, get_decryption_info

# Crypto
from secondguard.crypto import encrypt, decrypt

# Rate limited crypto
from secondguard.xlimit import sg_encrypt_secret, sg_decrypt_secret, sg_decrypt_from_priv_seed


import os


class TestTraversal(unittest.TestCase):
    def setUp(self):
        self.priv_seed_hex = 'a737d2fb2f2b980d6c31c2f1d6128c42e57375a8441af33e15c20063899cbbde'
        self.seed_public_hash_hex = 'a260496dddefefd6cf6ca90bc7d9fd34a1c9eaf050a36f60a246b22d89e957ef'
        self.some_nonce = 'c0f9901aa6ecc5eaa027bd8c5bd2f72fabf62e320cf34193bfef54b74a219eae'
        self.child_key = '57984537148886888fe9233b33c822c5d325be47b4ec35c9ceb5c3bad36894f3'

    def test_seed_hex_validity(self):
        assert is_valid_seed_hex(self.priv_seed_hex), self.priv_seed_hex
        assert is_valid_seed_hex(self.seed_public_hash_hex), self.seed_public_hash_hex

        is_valid, err_msg = is_valid_seed_hex('Some Non 64 Char Hex String')
        assert not is_valid, 'Should be valid but got: %s' % err_msg

    def test_seed_hash_pair(self):
        is_pair = is_seed_hash_pair(
                private_seed_hex=self.priv_seed_hex,
                seed_public_hash_hex=self.seed_public_hash_hex,
                )
        assert is_pair, 'Should be a pair but returned otherwise'

    def test_derive_child_key(self):
        child_key = derive_child_key(
                private_seed_hex=self.priv_seed_hex,
                nonce=self.some_nonce,
                )
        assert self.child_key == child_key


class TestBasicEncryption(unittest.TestCase):

    def setUp(self):
        self.byte_key = ('a' * 16).encode('utf-8')
        self.str_key = 'a' * 16
        self.byte_message = 'Attack at dawn!'.encode('utf-8')
        self.str_message = 'Attack at dawn!'

    def test_encryption(self):
        for key in (self.byte_key, self.str_key):
            for secret_message in (self.byte_message, self.str_message):
                assert decrypt(encrypt(secret_message, key), key) == secret_message


# Hackey way to pass encryption credentials to unit tests
if os.getenv('SG_API_TOKEN'):
    class TestAPI(unittest.TestCase):

        def setUp(self):
            self.api_token = os.getenv('SG_API_TOKEN')
            self.seed_pub_hash_hex = os.getenv('SG_SEED_PUB_HASH')
            self.private_seed_hex = os.getenv('SG_PRIVATE_SEED')
            self.byte_message = 'Attack at dawn!'.encode('utf-8')*10
            self.str_message = 'Attack at dawn!'*10

        def test_ping(self):
            ping_response = ping()
            assert ping_response['pong'] is True

        def test_encryption(self):

            for secret_message in (self.byte_message, self.str_message):

                to_save = sg_encrypt_secret(
                        secret_to_encrypt=secret_message,
                        seed_pub_hash_hex=self.seed_pub_hash_hex,
                        sg_api_token=self.api_token,
                        )

                locally_decrypted = sg_decrypt_from_priv_seed(
                        to_decrypt=to_save,
                        private_seed_hex=self.private_seed_hex,
                        )
                assert locally_decrypted == secret_message

                api_decrypted = sg_decrypt_secret(
                        to_decrypt=to_save,
                        api_token=self.api_token
                        )
                assert api_decrypted == secret_message


if __name__ == '__main__':
    unittest.main()
