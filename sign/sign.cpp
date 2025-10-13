#include <print>
#include <vector>
#include <span>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "key.h"
#include "openssl_cpp.h"


void checkResult(int result, char const *name)
{
    if(result <= 0)
    {
        throw OpenSSL::openssl_error{name};
    }
};

void checkBool(auto const &b, char const *name)
{
    if(!b)
    {
        throw OpenSSL::openssl_error{name};
    }
};


namespace Keys
{
    auto loadPublicKey(std::span<unsigned char const> const &bytes)
    {
        auto data           = bytes.data();
        auto publicKey      = d2i_PUBKEY( nullptr, &data, static_cast<long>(bytes.size()));

        checkBool(publicKey,"d2i_PUBKEY");

        return OpenSSL::Key{publicKey};
    }


    auto loadPrivateKey(int keyType, std::span<unsigned char const> const &bytes)
    {
        auto privateKey = OpenSSL::Key{EVP_PKEY_new()};

        checkBool(privateKey,"EVP_PKEY_new");

        auto result     = EVP_PKEY_set_type(privateKey.get(), keyType);

        checkResult(result,"EVP_PKEY_set_type");

        auto data       = bytes.data();
        auto key        = d2i_PrivateKey(keyType, std::out_ptr(privateKey), &data, static_cast<long>(bytes.size()));

        checkBool(key,"d2i_PrivateKey");

        return privateKey;
    }


    namespace RSA
    {
        auto load()
        {
            return std::make_pair(loadPublicKey(rsaPublicKeyBytes),loadPrivateKey(EVP_PKEY_RSA,rsaPrivateKeyBytes));
        }
    }

    namespace EC
    {
        auto load()
        {
            return std::make_pair(loadPublicKey(ecPublicKeyBytes),loadPrivateKey(EVP_PKEY_EC,ecPrivateKeyBytes));
        }
    }
}


auto sign(OpenSSL::Key const &privateKey, std::string_view message)
{
    auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};
 
    checkBool(context,"EVP_MD_CTX_new");

    auto result     = EVP_MD_CTX_init(context.get());

    checkResult(result,"EVP_MD_CTX_init");

    result          = EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, privateKey.get());
 
    checkResult(result,"EVP_DigestSignInit");

    result          = EVP_DigestSignUpdate(context.get(), message.data(), message.size());
 
    checkResult(result,"EVP_DigestSignUpdate");

    auto sigLen     = size_t{};
    result          = EVP_DigestSignFinal(context.get(), nullptr, &sigLen);

    checkResult(result,"EVP_DigestSignFinal");

    auto signature  = std::vector<unsigned char>(sigLen,0);

    result          = EVP_DigestSignFinal(context.get(), signature.data(), &sigLen);

    checkResult(result,"EVP_DigestSignFinal");

    signature.resize(sigLen);              // could've shrunk
    
    return signature;
}


bool verify(OpenSSL::Key const &publicKey, std::vector<unsigned char> const &signature, std::string_view message )
{
    auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};

    checkBool(context,"EVP_MD_CTX_new");

    auto result     = EVP_MD_CTX_init(context.get());

    checkResult(result,"EVP_MD_CTX_init");

    result          = EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, publicKey.get());

    checkResult(result,"EVP_DigestVerifyInit");

    result          = EVP_DigestVerifyUpdate(context.get(), message.data(), message.size());

    checkResult(result,"EVP_DigestVerifyUpdate");

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


void go(std::pair<OpenSSL::Key,OpenSSL::Key> const &keys)
try
{
    auto correct = "'Twas brillig, and the slithy toves";
    auto wrong   = "'Twas brillig, and the slithy taves";

 //---
 
    auto const signature = sign(keys.second, correct);

    std::print("Signature Size - {}\n",signature.size());
 
 //---

    std::print("{} : {}\n",correct,verify(keys.first,signature,correct));
    std::print("{} : {}\n",wrong,  verify(keys.first,signature,wrong));

}
catch(std::exception const &e)
{
    std::print("{} : {}\n",__func__,e.what());
}



int main()
try
{
    auto rsaKeys = Keys::RSA::load();
    auto ecKeys  = Keys::EC::load();

    std::print("\nEC\n");
    go(ecKeys);

    std::print("\nRSA\n");
    go(rsaKeys);


}
catch(std::exception const &e)
{
    std::print("{} : {}\n",__func__,e.what());
}
