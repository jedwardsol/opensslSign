#include <print>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>

#include "key.h"
#include "openssl_raii.h"

auto makePublicKey()
{
    auto publicKey  = OpenSSL::Key{EVP_PKEY_new()};

    auto result     = EVP_PKEY_set_type(publicKey.get(), EVP_PKEY_RSA);

    auto data       = publicKeyBytes.data();
    auto key        = d2i_PublicKey(EVP_PKEY_RSA, std::out_ptr(publicKey), &data, static_cast<long>(publicKeyBytes.size()));

    return publicKey;
}


auto makePrivateKey()
{
    auto privateKey = OpenSSL::Key{EVP_PKEY_new()};

    auto result     = EVP_PKEY_set_type(privateKey.get(), EVP_PKEY_RSA);

    auto data       = privateKeyBytes.data();
    auto key        = d2i_PrivateKey(EVP_PKEY_RSA, std::out_ptr(privateKey), &data, static_cast<long>(privateKeyBytes.size()));

    return privateKey;
}



auto sign(std::string_view message)
{
    auto privateKey = makePrivateKey();

    auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};
 
    auto result     = EVP_DigestSignInit(context.get(), nullptr, EVP_sha256(), nullptr, privateKey.get());
 
    result          = EVP_DigestSignUpdate(context.get(), message.data(), message.size());
 
    auto sigLen     = size_t{};
    result          = EVP_DigestSignFinal(context.get(), nullptr, &sigLen);

    auto signature  = std::vector<unsigned char>(sigLen,0);

    result          = EVP_DigestSignFinal(context.get(), signature.data(), &sigLen);

    return signature;

}


bool verify(std::string_view message, std::vector<unsigned char> const &signature)
{
    auto publicKey  = makePublicKey();

    auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};

    auto result     = EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, publicKey.get());

    result          = EVP_DigestVerifyUpdate(context.get(), message.data(), message.size());

    result          = EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size());

    return !!result;        
}


int main()
{
    auto correct = "'Twas brillig, and the slithy toves";
    auto wrong   = "'Twas brillig, and the slithy taves";

 //---
 
    auto const signature = sign(correct);
 
 //---

    auto ok = verify(correct,signature);

    std::print("{}\n",ok);

    ok = verify(wrong,signature);

    std::print("{}\n",ok);
}