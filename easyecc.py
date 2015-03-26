import _easyecc


class ECC(object):
    def __init__(self, *args, **kwargs):
        self._private_key = kwargs.get('private_key')
        self._public_key = kwargs.get('public_key')

    @classmethod
    def new_key(cls):
        private_key, public_key = _easyecc.new_key()
        return cls(private_key=private_key, public_key=public_key)

    def encrypt(self, plaintext):
        return _easyecc.encrypt(self._public_key, plaintext)

    def decrypt(self, ciphertext):
        return _easyecc.decrypt(self._private_key, ciphertext)

if __name__ == "__main__":
    plaintext = "This is a big secret"
    print plaintext
    ecc = ECC.new_key()
    print ecc.decrypt(ecc.encrypt(plaintext))
