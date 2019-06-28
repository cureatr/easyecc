#include <Python.h>

// crypto++
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>

#if CRYPTOPP_VERSION >= 600
#define byte CryptoPP::byte
#endif

#if PY_MAJOR_VERSION >= 3
#define TWO_BUFFERS_FORMAT "y#y#"
#else
#define TWO_BUFFERS_FORMAT "s#s#"
#endif

struct module_state {
    PyObject *error;
};

#if PY_MAJOR_VERSION >= 3
#define GETSTATE(m) ((struct module_state *)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
static struct module_state _state;
#endif

typedef CryptoPP::ECP DefaultEC;

// having this as a static global makes CryptoPP barf on MacOS, hence the #define
#define DefaultECParameters CryptoPP::ASN1::secp256k1()

namespace PyEasyECC
{
    class NULLHash : public CryptoPP::IteratedHashWithStaticTransform
        <CryptoPP::word32, CryptoPP::BigEndian, 32, 0, NULLHash>
    {
    public:
        static void InitState(HashWordType *state) { return; }
        static void Transform(CryptoPP::word32 *digest, const CryptoPP::word32 *data) { return; }
        static const char *StaticAlgorithmName() {return "NULL HASH";}
    };

    //
    // From /usr/include/cryptopp/eccrypto.h:
    //
    //! Elliptic Curve Integrated Encryption Scheme, AKA <a href="http://www.weidai.com/scan-mirror/ca.html#ECIES">ECIES</a>
    /*! Default to (NoCofactorMultiplication and DHAES_MODE = false) for compatibilty with SEC1 and Crypto++ 4.2.
      The combination of (IncompatibleCofactorMultiplication and DHAES_MODE = true) is recommended for best
      efficiency and security. */
    template <class EC, class COFACTOR_OPTION = CryptoPP::IncompatibleCofactorMultiplication, bool DHAES_MODE = true>
        struct ECIES_PY
        : public CryptoPP::DL_ES<
            CryptoPP::DL_Keys_EC<EC>,
            CryptoPP::DL_KeyAgreementAlgorithm_DH<typename EC::Point, COFACTOR_OPTION>,
            CryptoPP::DL_KeyDerivationAlgorithm_P1363<typename EC::Point, DHAES_MODE, CryptoPP::P1363_KDF2<CryptoPP::SHA1> >,
            // use NULLHash to decrease the size of the encrypted value
            CryptoPP::DL_EncryptionAlgorithm_Xor<CryptoPP::HMAC<NULLHash>, DHAES_MODE>,
            ECIES_PY<EC> >
        {
            static std::string CRYPTOPP_API StaticAlgorithmName() {return "ECIES_PY";}
        };
}

static PyObject *
raise_error(PyObject *m, const char *msg) {
    struct module_state *st = GETSTATE(m);
    PyErr_SetString(st->error, msg);
    return NULL;
}

// make a new key
// @returns tuple(private_key, public_key)
static PyObject *
ECC_new_key(PyObject *self)
{
    PyObject *private_key_out = 0;
    PyObject *public_key_out = 0;

    try
    {
        // generate elliptic crypto key pair
        PyEasyECC::ECIES_PY<DefaultEC>::PrivateKey private_key;
        PyEasyECC::ECIES_PY<DefaultEC>::PublicKey public_key;

        CryptoPP::AutoSeededRandomPool rng;

        private_key.Initialize(rng, DefaultECParameters);
        private_key.MakePublicKey(public_key);

        std::string private_key_str;
        // extract the private key into a string
        CryptoPP::Integer pk_int = private_key.GetPrivateExponent();
        CryptoPP::StringSink priv(private_key_str);
        pk_int.Encode(priv, pk_int.MinEncodedSize());
        private_key_out = PyBytes_FromStringAndSize(private_key_str.data(), private_key_str.size());

        // extract the public key
        CryptoPP::ECP::Point point(public_key.GetPublicElement());

        // figure out how many bytes both parts of the key will need
        unsigned int pub_encoding_size = std::max(point.x.MinEncodedSize(), point.y.MinEncodedSize());

        std::string public_key_str;
        CryptoPP::StringSink pub(public_key_str);
        point.x.Encode(pub, pub_encoding_size);
        point.y.Encode(pub, pub_encoding_size);
        public_key_out = PyBytes_FromStringAndSize(public_key_str.data(), public_key_str.size());
    }
    catch (CryptoPP::Exception &e)
    {
        return raise_error(self, e.GetWhat().data());
    }

    if (private_key_out && public_key_out)
        return PyTuple_Pack(2, private_key_out, public_key_out);
    else {
        return raise_error(self, "NULL keys");
    }
}

// encrypt data
static PyObject *
ECC_encrypt(PyObject *self, PyObject *args)
{
    const char *_public_key, *_data_decrypted;
    int _public_key_size, _data_decrypted_size;
    if (!PyArg_ParseTuple(args, TWO_BUFFERS_FORMAT, &_public_key, & _public_key_size, &_data_decrypted, &_data_decrypted_size))
        return NULL;

    PyObject *data_encrypted_out = 0;

    try
    {
        PyEasyECC::ECIES_PY<DefaultEC>::Encryptor encryptor;
        CryptoPP::AutoSeededRandomPool rng;

        // reconstruct EC public key
        // Can't use EncodePoint/DecodePoint https://www.cryptopp.com/docs/ref/class_e_c_p.html#aac188a1e14a4f7807720f45e3aa30768
        // because we don't encode a type byte.
        unsigned int pub_encoding_size = _public_key_size / 2;
        CryptoPP::ECP::Point point(
            CryptoPP::Integer(reinterpret_cast<const byte *>(_public_key), pub_encoding_size),
            CryptoPP::Integer(reinterpret_cast<const byte *>(_public_key) + pub_encoding_size, pub_encoding_size)
        );

        encryptor.AccessKey().AccessGroupParameters().Initialize(DefaultECParameters);
        encryptor.AccessKey().SetPublicElement(point);
        encryptor.AccessKey().ThrowIfInvalid(rng, 3);

        unsigned long data_encrypted_length = encryptor.CiphertextLength(_data_decrypted_size);
        byte data_encrypted[data_encrypted_length];
        encryptor.Encrypt(rng, reinterpret_cast<const byte *>(_data_decrypted), _data_decrypted_size, data_encrypted);

        data_encrypted_out = PyBytes_FromStringAndSize(reinterpret_cast<const char *>(data_encrypted), data_encrypted_length);
    }
    catch (CryptoPP::Exception &e)
    {
        return raise_error(self, e.GetWhat().data());
    }

    if (data_encrypted_out)
        return data_encrypted_out;
    else {
        return raise_error(self, "NULL encrypted data");
    }
}

// decrypt data
static PyObject *
ECC_decrypt(PyObject *self, PyObject *args)
{
    const char *_private_key, *_data_encrypted;
    int _private_key_size, _data_encrypted_size;
    if (!PyArg_ParseTuple(args, TWO_BUFFERS_FORMAT, &_private_key, & _private_key_size, &_data_encrypted, &_data_encrypted_size))
        return NULL;

    PyObject *data_decrypted_out;
    try
    {
        PyEasyECC::ECIES_PY<DefaultEC>::Decryptor decryptor;
        CryptoPP::AutoSeededRandomPool rng;

        // reconstruct EC private key
        CryptoPP::Integer pk_int;
        pk_int.Decode(reinterpret_cast<const byte *>(_private_key), _private_key_size);

        decryptor.AccessKey().Initialize(DefaultECParameters, pk_int);
        decryptor.AccessKey().ThrowIfInvalid(rng, 3);

        unsigned long data_decrypted_max_length = decryptor.MaxPlaintextLength(_data_encrypted_size);

        byte data_decrypted[data_decrypted_max_length];
        CryptoPP::DecodingResult res = decryptor.Decrypt(rng, reinterpret_cast<const byte *>(_data_encrypted), _data_encrypted_size, data_decrypted);
        if (!res.isValidCoding)
        {
            return raise_error(self, "DecodingResult invalid");
        }

        // return decrypted data
        data_decrypted_out = PyBytes_FromStringAndSize(reinterpret_cast<const char *>(data_decrypted), res.messageLength);
    }
    catch (CryptoPP::Exception &e)
    {
        return raise_error(self, e.GetWhat().data());
    }

    if (data_decrypted_out)
        return data_decrypted_out;
    else {
        return raise_error(self, "NULL decrypted data");
    }
}

static PyMethodDef EasyECCMethods[] = {
    {"new_key",  (PyCFunction)ECC_new_key, METH_NOARGS, "Generate a new keypair."},
    {"encrypt",  (PyCFunction)ECC_encrypt, METH_VARARGS, "Encrypt data."},
    {"decrypt",  (PyCFunction)ECC_decrypt, METH_VARARGS, "Decrypt data."},
    {NULL, NULL, 0, NULL},
};

#if PY_MAJOR_VERSION >= 3

static int _easyecc_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int _easyecc_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        "_easyecc",
        NULL,
        sizeof(struct module_state),
        EasyECCMethods,
        NULL,
        _easyecc_traverse,
        _easyecc_clear,
        NULL
};

#define INITERROR return NULL

PyMODINIT_FUNC
PyInit__easyecc(void)

#else
#define INITERROR return

PyMODINIT_FUNC
init_easyecc(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject *module = PyModule_Create(&moduledef);
#else
    PyObject *module = Py_InitModule("_easyecc", EasyECCMethods);
#endif

    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("_easyecc.EasyECCError", NULL, NULL);
    if (st->error == NULL) {
        Py_DECREF(module);
        INITERROR;
    }
    Py_INCREF(st->error);
    PyModule_AddObject(module, "EasyECCError", st->error);
    PyModule_AddIntConstant(module, "CRYPTOPP_VERSION", CRYPTOPP_VERSION);

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
