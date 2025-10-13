#include <print>
#include <vector>

#include "openssl_cpp.h"
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>


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




void write(std::string const &name, std::vector<unsigned char> const &data)
{
    std::print("auto {}Bytes = std::array<unsigned char const,{}>\n{{",name, data.size());

    for(int i=0;i < data.size(); i++)
    {
        if((i%32) == 0)
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

        checkResult(publicKeyLen,"i2d_PUBKEY");

        auto publicKey      = std::vector<unsigned char>(publicKeyLen, 0);
        auto data           = publicKey.data();

        publicKeyLen        = i2d_PUBKEY(key.get(),&data);

        checkResult(publicKeyLen,"i2d_PUBKEY");

        write(prefix + "PublicKey", publicKey);
    }

// --- write private
    {
        auto privateKeyLen  = i2d_PrivateKey(key.get(),nullptr);

        checkResult(privateKeyLen,"i2d_PrivateKey");

        auto privateKey     = std::vector<unsigned char>(privateKeyLen, 0);
        auto data           = privateKey.data();

        privateKeyLen       = i2d_PrivateKey(key.get(),&data);

        checkResult(privateKeyLen,"i2d_PrivateKey");

        write(prefix + "PrivateKey", privateKey);
    }

}

    
void genRSA()
{
    auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};

    checkBool(keyContext,"EVP_PKEY_CTX_new_id");


    auto result     = EVP_PKEY_keygen_init(keyContext.get());

    checkResult(result,"EVP_PKEY_keygen_init");

    result          = EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 2048);
  
    checkResult(result,"EVP_PKEY_CTX_set_rsa_keygen_bits");


    auto key        = OpenSSL::Key{};

    result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));

    checkResult(result,"EVP_PKEY_keygen");

    write("rsa",key);
}


void genEC()
{
    auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};

    checkBool(keyContext,"EVP_PKEY_CTX_new_id");


    auto result     = EVP_PKEY_keygen_init(keyContext.get());

    checkResult(result,"EVP_PKEY_keygen_init");

    result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyContext.get(), NID_X9_62_prime256v1);
    
    checkResult(result,"EVP_PKEY_CTX_set_ec_paramgen_curve_nid");

    auto key        = OpenSSL::Key{};

    result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));

    checkResult(result,"EVP_PKEY_keygen");

    write("ec",key);
}




int main()
try
{
    std::print("#pragma once\n");
    std::print("// generated with the `keygen` program\n");
    std::print("#include <array>\n\n");

    genRSA();
    genEC();

}
catch(std::exception const &e)
{
    std::print("Caught : {}\n",e.what());
}
