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
    namespace RSA
    {
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
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
    }


    namespace EC256
    {

        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
        {
            return RSA::verify(publicKey,signature,message);
        }
    }



    namespace EC25519
    {

        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message )
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
}

