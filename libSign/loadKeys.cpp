#include <print>
#include <vector>
#include <span>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "openssl_cpp.h"
#include "libSign.h"

#include "keys.h"


namespace LibSign
{
    namespace
    {
        auto loadPublicKey(std::span<uint8_t const> const &bytes)
        {
            auto data           = bytes.data();
            auto publicKey      = d2i_PUBKEY( nullptr, &data, static_cast<long>(bytes.size()));

            OpenSSL::checkBool(publicKey,"d2i_PUBKEY");

            return OpenSSL::PublicKey{publicKey};
        }

        auto loadPrivateKey(int keyType, std::span<uint8_t const> const &bytes)
        {
            auto privateKey = OpenSSL::PrivateKey{EVP_PKEY_new()};

            checkBool(privateKey,"EVP_PKEY_new");

            auto result     = EVP_PKEY_set_type(privateKey.get(), keyType);

            OpenSSL::checkResult(result,"EVP_PKEY_set_type");

            auto data       = bytes.data();
            auto key        = d2i_PrivateKey(keyType, std::out_ptr(privateKey), &data, static_cast<long>(bytes.size()));

            OpenSSL::checkBool(key,"d2i_PrivateKey");

            return privateKey;
        }
    }

    namespace RSA
    {
        OpenSSL::KeyPair load()
        {
            return std::make_pair(loadPublicKey(::Keys::rsaPublicKeyBytes),loadPrivateKey(EVP_PKEY_RSA,::Keys::rsaPrivateKeyBytes));
        }
    }

    namespace EC256
    {
        OpenSSL::KeyPair load()
        {
            return std::make_pair(loadPublicKey(::Keys::ec256PublicKeyBytes),loadPrivateKey(EVP_PKEY_EC,::Keys::ec256PrivateKeyBytes));
        }
    }

    namespace EC25519
    {
        OpenSSL::KeyPair load()
        {
            return std::make_pair(loadPublicKey(::Keys::ec25519PublicKeyBytes),loadPrivateKey(EVP_PKEY_ED25519,::Keys::ec25519PrivateKeyBytes));
        }
    }
}





