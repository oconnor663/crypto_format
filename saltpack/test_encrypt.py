from unittest import TestCase

import nacl.bindings

from saltpack.encrypt import encrypt, decrypt


class Test(TestCase):
    def test_encrypt(self):
        for message in (b'', b'foo bar', b'long message' * 10 ** 4):
            for chunk_size in (10 ** 6, 10 ** 3):
                private_sender = b'\0' * 32
                recipient_private_keys = [b'\1' * 32, b'\1' * 31 + b'\0']
                recipient_public_keys = [nacl.bindings.crypto_scalarmult_base(x) for x in recipient_private_keys]

                for major_version in (1, 2):
                    encrypted = encrypt(private_sender, recipient_public_keys, message, chunk_size,
                                        major_version=major_version)

                    for recipient_private_key in recipient_private_keys:
                        decrypted = decrypt(encrypted, recipient_private_key)
                        self.assertEqual(decrypted, message)
                        self.assertNotEqual(encrypted, message)

                    self.assertRaises(RuntimeError, decrypt, encrypted, private_sender)
