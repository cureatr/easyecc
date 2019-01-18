from __future__ import print_function
import _easyecc


class ECC(object):
    def __init__(self, private_key=None, public_key=None):
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def new_key(cls):
        private_key, public_key = _easyecc.new_key()
        return cls(private_key=private_key, public_key=public_key)

    def encrypt(self, plaintext):
        return _easyecc.encrypt(self._public_key, plaintext)

    def decrypt(self, ciphertext):
        return _easyecc.decrypt(self._private_key, ciphertext)


if __name__ == "__main__":
    plaintext = b"This is a big secret"
    print(plaintext)
    ecc = ECC.new_key()
    print(ecc.decrypt(ecc.encrypt(plaintext)))
