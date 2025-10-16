#include <print>
#include <vector>
#include <span>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "openssl_cpp.h"
#include "libSign/libSign.h"


namespace LibSign
{
    namespace
    {
        bool verify_sha256(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};

            checkBool(context,"EVP_MD_CTX_new");

            auto result     = EVP_MD_CTX_init(context.get());

            OpenSSL::checkResult(result,"EVP_MD_CTX_init");

            result          = EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, publicKey.get());

            OpenSSL::checkResult(result,"EVP_DigestVerifyInit");

            result          = EVP_DigestVerifyUpdate(context.get(), message.data(), message.size());

            OpenSSL::checkResult(result,"EVP_DigestVerifyUpdate");

            result          = EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size());

            if(result == 1)
            {
                return true;
            }
            else if(result == 0)
            {
                return false;
            }
            else
            {
                std::print("{} ",result);
                throw OpenSSL::openssl_error{"EVP_DigestVerifyFinal"};
            }
        }


        bool verify_default_algorithm(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};

            checkBool(context,"EVP_MD_CTX_new");

            auto result     = EVP_MD_CTX_init(context.get());

            OpenSSL::checkResult(result,"EVP_MD_CTX_init");

            result          = EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, publicKey.get());

            OpenSSL::checkResult(result,"EVP_DigestVerifyInit");


            result = EVP_DigestVerify(context.get(),
                                      signature.data(), signature.size(),
                                      reinterpret_cast<const uint8_t*>(message.data()), message.size());

            if(result == 1)
            {
                return true;
            }
            else if(result == 0)
            {
                return false;
            }
            else
            {
                std::print("{} ",result);
                throw OpenSSL::openssl_error{"EVP_DigestVerifyFinal"};
            }
        }
    }


    namespace RSA
    {
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            // documentation says that the algorthm must be specified when verifying a signature made with an RSA key
            // although experimentation shows that `verify_default_algorithm` does work here.
            return verify_sha256(publicKey,signature,message);
        }
    }

    namespace EC256
    {
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            // documentation says that the algorthm must be specified when verifying a signature made with this EC key
            // although experimentation shows that `verify_default_algorithm` does work here.
            return verify_sha256(publicKey,signature,message);
        }
    }

    namespace ED25519
    {
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            // documentation says that the algorthm must not be specified when verifying a signature made with this EC key
            // and experimentation does show that `verify_sha256` does not work here 
            return verify_default_algorithm(publicKey,signature,message);
        }
    }

    namespace DSA
    {
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            return verify_sha256(publicKey,signature,message);
        }
    }

    namespace SLHDSA
    {
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            return verify_default_algorithm(publicKey,signature,message);
        }
    }
}

