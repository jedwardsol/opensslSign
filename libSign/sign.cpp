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
        Signature sign(OpenSSL::PrivateKey const &privateKey, Message message)
        {
            auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};
 
            OpenSSL::checkBool(context,"EVP_MD_CTX_new");

            auto result     = EVP_MD_CTX_init(context.get());

            OpenSSL::checkResult(result,"EVP_MD_CTX_init");

            result          = EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, privateKey.get());
 
            OpenSSL::checkResult(result,"EVP_DigestSignInit");

            result          = EVP_DigestSignUpdate(context.get(), message.data(), message.size());
 
            OpenSSL::checkResult(result,"EVP_DigestSignUpdate");

            auto sigLen     = size_t{};
            result          = EVP_DigestSignFinal(context.get(), nullptr, &sigLen);

            OpenSSL::checkResult(result,"EVP_DigestSignFinal");

            auto signature  = Signature(sigLen,0);

            result          = EVP_DigestSignFinal(context.get(), signature.data(), &sigLen);

            OpenSSL::checkResult(result,"EVP_DigestSignFinal");

            signature.resize(sigLen);                                   // could've shrunk : happens when signing with an EC key
    
            return signature;
        }
    }


    namespace EC256
    {

        Signature sign(OpenSSL::PrivateKey const &privateKey, Message message)
        {
            return RSA::sign(privateKey,message);
        }
    }



    namespace EC25519
    {

        Signature sign(OpenSSL::PrivateKey const &privateKey, Message message)
        {
            auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};
 
            OpenSSL::checkBool(context,"EVP_MD_CTX_new");

            auto result     = EVP_MD_CTX_init(context.get());

            OpenSSL::checkResult(result,"EVP_MD_CTX_init");

            result          = EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, privateKey.get());
 
            OpenSSL::checkResult(result,"EVP_DigestSignInit");



            auto sigLen     = size_t{};
            result          = EVP_DigestSign(context.get(), nullptr, &sigLen, reinterpret_cast<uint8_t const*>(message.data()), message.size());

            OpenSSL::checkResult(result,"EVP_DigestSignFinal");

            auto signature  = Signature(sigLen,0);

            result          = EVP_DigestSign(context.get(), signature.data(), &sigLen, reinterpret_cast<uint8_t const*>(message.data()), message.size());

            OpenSSL::checkResult(result,"EVP_DigestSignFinal");

            signature.resize(sigLen);                                   // could've shrunk : happens when signing with an EC key
    
            return signature;
        }
    }
}

