#include <print>
#include <vector>

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


namespace RSAKeys
{
    auto makePublicKey()
    {
        auto publicKey  = OpenSSL::Key{EVP_PKEY_new()};

        checkBool(publicKey,"EVP_PKEY_new");

        auto result     = EVP_PKEY_set_type(publicKey.get(), EVP_PKEY_RSA);

        checkResult(result,"EVP_PKEY_set_type");

        auto data       = rsaPublicKeyBytes.data();
        auto key        = d2i_PublicKey(EVP_PKEY_RSA, std::out_ptr(publicKey), &data, static_cast<long>(rsaPublicKeyBytes.size()));

        checkBool(key,"d2i_PublicKey");

        return publicKey;
    }

    auto makePrivateKey()
    {
        auto privateKey = OpenSSL::Key{EVP_PKEY_new()};

        checkBool(privateKey,"EVP_PKEY_new");

        auto result     = EVP_PKEY_set_type(privateKey.get(), EVP_PKEY_RSA);

        checkResult(result,"EVP_PKEY_set_type");

        auto data       = rsaPrivateKeyBytes.data();
        auto key        = d2i_PrivateKey(EVP_PKEY_RSA, std::out_ptr(privateKey), &data, static_cast<long>(rsaPrivateKeyBytes.size()));

        checkBool(key,"d2i_PrivateKey");

        return privateKey;
    }

    auto makeKeys()
    {
        return std::make_pair(makePublicKey(),makePrivateKey());
    }
}


namespace ECKeys
{
    auto makePublicKey()
    {
        auto publicKey  = OpenSSL::Key{EVP_PKEY_new()};

        checkBool(publicKey,"EVP_PKEY_new");
    
        auto nid = NID_X9_62_prime256v1; // change to the curve you used

        auto group = EC_GROUP_new_by_curve_name(nid);
        checkBool(group,"EC_GROUP_new_by_curve_name");

        auto eckey = OpenSSL::Key{EVP_PKEY_new()};
        checkBool(eckey,"EC_KEY_new");

        checkBool(EC_KEY_set_group(eckey.get(), group),"EC_KEY_set_group");

        auto point = EC_POINT_new(group);
        checkBool(point,"EC_POINT_new");

        if(1 != EC_POINT_oct2point(group, point, ecPublicKeyBytes.data(), ecPublicKeyBytes.size(), nullptr))
            throw OpenSSL::openssl_error{"EC_POINT_oct2point"};




        checkBool(EC_KEY_set_public_key(eckey, point),"EC_KEY_set_public_key");

        // create a temp EVP_PKEY and copy the EC_KEY into it (increments ref)
        auto tmpPkey = OpenSSL::Key{EVP_PKEY_new()};
        checkBool(tmpPkey,"EVP_PKEY_new");

        if(1 != EVP_PKEY_set1_EC_KEY(tmpPkey.get(), eckey))
            throw OpenSSL::openssl_error{"EVP_PKEY_set1_EC_KEY"};

        // cleanup EC structures we created (EVP_PKEY has its own reference)
        EC_POINT_free(point);
        EC_KEY_free(eckey);
        EC_GROUP_free(group);



        return tmpPkey;
    }

    auto makePrivateKey()
    {
        auto privateKey = OpenSSL::Key{EVP_PKEY_new()};

        checkBool(privateKey,"EVP_PKEY_new");

        auto result     = EVP_PKEY_set_type(privateKey.get(), EVP_PKEY_EC);

        checkResult(result,"EVP_PKEY_set_type");

        auto data       = ecPrivateKeyBytes.data();
        auto key        = d2i_PrivateKey(EVP_PKEY_EC, std::out_ptr(privateKey), &data, static_cast<long>(ecPrivateKeyBytes.size()));

        checkBool(key,"d2i_PrivateKey");

        return privateKey;
    }

    auto makeKeys()
    {
        return std::make_pair(makePublicKey(),makePrivateKey());
    }
}



auto sign(OpenSSL::Key const &privateKey, std::string_view message)
{
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


void verify(OpenSSL::Key const &publicKey, std::vector<unsigned char> const &signature, std::string_view message )
{
    auto context    = OpenSSL::DigestContext{EVP_MD_CTX_new()};

    checkBool(context,"EVP_MD_CTX_new");

    auto result     = EVP_DigestVerifyInit(context.get(), nullptr, EVP_sha256(), nullptr, publicKey.get());

    checkResult(result,"EVP_DigestVerifyInit");

    result          = EVP_DigestVerifyUpdate(context.get(), message.data(), message.size());

    checkResult(result,"EVP_DigestVerifyUpdate");

    result          = EVP_DigestVerifyFinal(context.get(), signature.data(), signature.size());

    checkResult(result,"EVP_DigestVerifyFinal");
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

    std::print("{}\n",correct);
    verify(keys.first,signature,correct);
    std::print("verified\n");

    std::print("{}\n",wrong);
    verify(keys.first,signature,wrong);
    std::print("verified\n");
}
catch(std::exception const &e)
{
    std::print("{} : {}\n",__func__,e.what());
}



int main()
try
{
    auto rsaKeys = RSAKeys::makeKeys();
    auto ecKeys  = ECKeys::makeKeys();

    std::print("\nRSA\n");
    go(rsaKeys);

    std::print("\nEC\n");
    go(ecKeys);

}
catch(std::exception const &e)
{
    std::print("{} : {}\n",__func__,e.what());
}
