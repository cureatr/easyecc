#include <vector>
#include <algorithm>
#include <stdexcept>

// crypto++
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/default.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/trunhash.h>

// boost
#include <boost/python.hpp>
#include <boost/python/tuple.hpp>
using namespace boost::python;

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
	// From /usr/local/include/eccrypto.h:
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

// make a new key
// @returns tuple(private_key, public_key)
tuple ECC_new_key()
{
	std::string private_key_out;
	std::string public_key_out;

	try
	{
		// generate elliptic crypto key pair
		PyEasyECC::ECIES_PY<DefaultEC>::PrivateKey private_key;
		PyEasyECC::ECIES_PY<DefaultEC>::PublicKey public_key;
		
		CryptoPP::AutoSeededRandomPool rng;

		private_key.Initialize(rng, DefaultECParameters);
		private_key.MakePublicKey(public_key);
		
		// extract the private key into a string
		CryptoPP::Integer pk_int = private_key.GetPrivateExponent();
		CryptoPP::StringSink priv(private_key_out);
		pk_int.Encode(priv, pk_int.MinEncodedSize());
		
		// extract the public key
		CryptoPP::Integer pubx = public_key.GetPublicElement().x;
		CryptoPP::Integer puby = public_key.GetPublicElement().y;
		
		// figure out how many bytes both parts of the key will need
		unsigned int pubx_size = pubx.MinEncodedSize();
		unsigned int puby_size = puby.MinEncodedSize();
		unsigned int pub_encoding_size = std::max(pubx_size, puby_size);

		CryptoPP::StringSink pub(public_key_out);
		pubx.Encode(pub, pub_encoding_size);
		puby.Encode(pub, pub_encoding_size);
	}
	catch (CryptoPP::Exception &e)
	{
		throw e.GetWhat();
	}

	return make_tuple<std::string, std::string>(private_key_out, public_key_out);
}

// encrypt data
std::string ECC_encrypt(
	const std::string &_public_key,
	const std::string &_data_decrypted)
{
	std::string data_encrypted_out;

	try 
	{
		// reconstruct EC public key
		unsigned int pub_encoding_size = _public_key.size() / 2;
		CryptoPP::Integer pubx(reinterpret_cast<const byte *>(_public_key.data()), pub_encoding_size);
		CryptoPP::Integer puby(reinterpret_cast<const byte *>(_public_key.data()) + pub_encoding_size, pub_encoding_size);

		PyEasyECC::ECIES_PY<DefaultEC>::PublicKey public_key;
		public_key.Initialize(DefaultECParameters, DefaultEC::Element(pubx, puby));

		// encrypt the value
		CryptoPP::AutoSeededRandomPool rng;
		PyEasyECC::ECIES_PY<DefaultEC>::Encryptor encryptor(public_key);

		unsigned long data_encrypted_length = encryptor.CiphertextLength(_data_decrypted.size());
		byte data_encrypted[data_encrypted_length];
		encryptor.Encrypt(rng, reinterpret_cast<const byte *>(_data_decrypted.data()), _data_decrypted.size(), data_encrypted);

		// casting to add const is needed to help the compiler resolve the overloaded method
		data_encrypted_out.assign(reinterpret_cast<const char *>(data_encrypted), data_encrypted_length);
	}
	catch (CryptoPP::Exception &e)
	{
		throw e.GetWhat();
	}

	return data_encrypted_out;
}

// decrypt data
std::string ECC_decrypt(
	const std::string &_private_key,
	const std::string &_data_encrypted)
{
	std::string data_decrypted_out;
	try 
	{
		// reconstruct EC private key
		CryptoPP::Integer pk_int;
		pk_int.Decode(reinterpret_cast<const byte *>(_private_key.data()), _private_key.size());

		PyEasyECC::ECIES_PY<DefaultEC>::PrivateKey private_key;
		private_key.Initialize(DefaultECParameters, pk_int);

		// decrypt the value
		PyEasyECC::ECIES_PY<DefaultEC>::Decryptor decryptor(private_key);

		unsigned long data_decrypted_max_length = decryptor.MaxPlaintextLength(_data_encrypted.length());

		byte data_decrypted[data_decrypted_max_length];
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::DecodingResult res = decryptor.Decrypt(rng, reinterpret_cast<const byte *>(_data_encrypted.data()), _data_encrypted.size(), data_decrypted);
		if (!res.isValidCoding)
		{
			throw "DecodingResult invalid";
		}

		// return decrypted data
		data_decrypted_out.assign(reinterpret_cast<const char *>(data_decrypted), res.messageLength);
	}
	catch (CryptoPP::Exception &e)
	{
		throw e.GetWhat();
	}

	return data_decrypted_out;
}

BOOST_PYTHON_MODULE(_easyecc)
{
    def("new_key", ECC_new_key);
    def("encrypt", ECC_encrypt);
    def("decrypt", ECC_decrypt);
}
