#include <print>
#include <vector>

#include "openssl_cpp.h"
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>


// makes RSA and EC key pairs and writes them to stdout,  for redirecting to a keys.h



void write(std::string const &name, std::vector<uint8_t> const &data)
{
    std::print("constinit auto const {}Bytes = std::array<uint8_t const ,{}>\n{{",name, data.size());

    for(int i=0;i < data.size(); i++)
    {
        if((i%16) == 0)
        {
            std::print("\n    ");
        }

        std::print("0x{:02x}, ",data[i]);
    }

    std::print("\n}};\n\n");
}



void write(std::string const &prefix, OpenSSL::Key const &key)
{
// --- write public
    {
        auto publicKeyLen   = i2d_PUBKEY(key.get(),nullptr);

        OpenSSL::checkResult(publicKeyLen,"i2d_PUBKEY");

        auto publicKey      = std::vector<uint8_t>(publicKeyLen, 0);
        auto data           = publicKey.data();

        publicKeyLen        = i2d_PUBKEY(key.get(),&data);

        OpenSSL::checkResult(publicKeyLen,"i2d_PUBKEY");

        write(prefix + "PublicKey", publicKey);
    }

// --- write private
    {
        auto privateKeyLen  = i2d_PrivateKey(key.get(),nullptr);

        OpenSSL::checkResult(privateKeyLen,"i2d_PrivateKey");

        auto privateKey     = std::vector<uint8_t>(privateKeyLen, 0);
        auto data           = privateKey.data();

        privateKeyLen       = i2d_PrivateKey(key.get(),&data);

        OpenSSL::checkResult(privateKeyLen,"i2d_PrivateKey");

        write(prefix + "PrivateKey", privateKey);
    }

}

    
void genRSA()
{
    auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};

    checkBool(keyContext,"EVP_PKEY_CTX_new_id");


    auto result     = EVP_PKEY_keygen_init(keyContext.get());

    OpenSSL::checkResult(result,"EVP_PKEY_keygen_init");

    result          = EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 2048);
  
    OpenSSL::checkResult(result,"EVP_PKEY_CTX_set_rsa_keygen_bits");

//
// ---
//

    auto key        = OpenSSL::Key{};

    result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));

    OpenSSL::checkResult(result,"EVP_PKEY_keygen");

    write("rsa",key);
}


void genEC256()
{
    auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};

    OpenSSL::checkBool(keyContext,"EVP_PKEY_CTX_new_id");


    auto result     = EVP_PKEY_keygen_init(keyContext.get());

    OpenSSL::checkResult(result,"EVP_PKEY_keygen_init");

    result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyContext.get(), NID_X9_62_prime256v1);
    
    OpenSSL::checkResult(result,"EVP_PKEY_CTX_set_ec_paramgen_curve_nid");

//
// ---
//

    auto key        = OpenSSL::Key{};

    result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));

    OpenSSL::checkResult(result,"EVP_PKEY_keygen");

    write("ec256",key);
}



void genEC25519()
{
    auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(NID_ED25519, nullptr)};

    OpenSSL::checkBool(keyContext,"EVP_PKEY_CTX_new_id");


    auto result     = EVP_PKEY_keygen_init(keyContext.get());

    OpenSSL::checkResult(result,"EVP_PKEY_keygen_init");


//
// ---
//

    auto key        = OpenSSL::Key{};

    result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));

    OpenSSL::checkResult(result,"EVP_PKEY_keygen");

    write("ec25519",key);
}




int main()
try
{
    std::puts(R"(
#pragma once
// generated with the `keygen` program
#include <array>
#include <cstdint>

namespace Keys
{
    )");

    genRSA();
    genEC256();
    genEC25519();

    std::puts("\n}\n");
}
catch(std::exception const &e)
{
    std::print("Caught : {}\n",e.what());
}
