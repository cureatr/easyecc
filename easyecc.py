import warnings
import _easyecc

if _easyecc.CRYPTOPP_VERSION > 564 and _easyecc.CRYPTOPP_VERSION <= 820:
    warnings.warn(f"libcryptopp {_easyecc.CRYPTOPP_VERSION} is a known buggy version, see https://github.com/weidai11/cryptopp/issues/856")


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
    ciphertext = ecc.encrypt(plaintext)
    print(ciphertext)
    print(ecc.decrypt(ciphertext))
