#include <print>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>

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



auto makePublicKey()
{
    auto publicKey  = OpenSSL::Key{EVP_PKEY_new()};

    checkBool(publicKey,"EVP_PKEY_new");

    auto result     = EVP_PKEY_set_type(publicKey.get(), EVP_PKEY_RSA);

    checkResult(result,"EVP_PKEY_set_type");

    auto data       = publicKeyBytes.data();
    auto key        = d2i_PublicKey(EVP_PKEY_RSA, std::out_ptr(publicKey), &data, static_cast<long>(publicKeyBytes.size()));

    checkBool(key,"d2i_PublicKey");

    return publicKey;
}


auto makePrivateKey()
{
    auto privateKey = OpenSSL::Key{EVP_PKEY_new()};

    checkBool(privateKey,"EVP_PKEY_new");

    auto result     = EVP_PKEY_set_type(privateKey.get(), EVP_PKEY_RSA);

    checkResult(result,"EVP_PKEY_set_type");

    auto data       = privateKeyBytes.data();
    auto key        = d2i_PrivateKey(EVP_PKEY_RSA, std::out_ptr(privateKey), &data, static_cast<long>(privateKeyBytes.size()));

    checkBool(key,"d2i_PrivateKey");

    return privateKey;
}



auto sign(std::string_view message)
{
    auto privateKey = makePrivateKey();

    checkBool(privateKey,"makePrivateKey");

    auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};
 
    checkBool(context,"EVP_MD_CTX_new");

    auto result     = EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, privateKey.get());
 
    checkResult(result,"EVP_DigestSignInit");

    result          = EVP_DigestSignUpdate(context.get(), message.data(), message.size());
 
    checkResult(result,"EVP_DigestSignUpdate");

    auto sigLen     = size_t{};
    result          = EVP_DigestSignFinal(context.get(), nullptr, &sigLen);

    checkResult(result,"EVP_DigestSignFinal");

    auto signature  = std::vector<unsigned char>(sigLen,0);

    result          = EVP_DigestSignFinal(context.get(), signature.data(), &sigLen);

    checkResult(result,"EVP_DigestSignFinal");

    return signature;

}


void verify(std::string_view message, std::vector<unsigned char> const &signature)
{
    auto publicKey  = makePublicKey();

    checkBool(publicKey,"makePublicKey");

    auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};

    checkBool(context,"EVP_MD_CTX_new");

    auto result     = EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, publicKey.get());

    checkResult(result,"EVP_DigestVerifyInit");

    result          = EVP_DigestVerifyUpdate(context.get(), message.data(), message.size());

    checkResult(result,"EVP_DigestVerifyUpdate");

    result          = EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size());

    checkResult(result,"EVP_DigestVerifyFinal");
}


int main()
try
{
    auto correct = "'Twas brillig, and the slithy toves";
    auto wrong   = "'Twas brillig, and the slithy taves";

 //---
 
    auto const signature = sign(correct);
 
 //---

    std::print("{}\n",correct);
    verify(correct,signature);


    std::print("{}\n",wrong);
    verify(wrong,signature);

}
catch(std::exception const &e)
{
    std::print("Caught : {}\n",e.what());
}