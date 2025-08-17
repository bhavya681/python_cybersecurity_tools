import unittest
from modules.crypto_tools import CryptoTool

class TestCrypto(unittest.TestCase):
    def test_fernet(self):
        c = CryptoTool()
        key = c.fernet_generate_key()
        msg = b"hello world"
        ct = c.fernet_encrypt(key, msg)
        pt = c.fernet_decrypt(key, ct)
        self.assertEqual(pt, msg)

    def test_rsa(self):
        c = CryptoTool()
        priv, pub = c.rsa_generate_keys(2048)
        msg = b"hi rsa"
        ct = c.rsa_encrypt(pub, msg)
        pt = c.rsa_decrypt(priv, ct)
        self.assertEqual(pt, msg)

if __name__ == "__main__":
    unittest.main()
