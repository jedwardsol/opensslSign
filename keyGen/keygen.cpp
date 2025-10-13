#include <print>
#include <vector>


#include "openssl_raii.h"

void write(char const *name, std::vector<unsigned char> const &data)
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


int main()
{
    auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};

    auto result     = EVP_PKEY_keygen_init(keyContext.get());

    result          = EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 2048);
  
    auto key        = OpenSSL::Key{};

    result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));



// --- write public
    auto publicKeyLen   = i2d_PublicKey(key.get(),nullptr);
    auto publicKey      = std::vector<unsigned char>(publicKeyLen, 0);
    auto data           = publicKey.data();

    i2d_PublicKey(key.get(),&data);


    std::print("#pragma once\n");
    std::print("// generated with the `keygen` program\n");
    std::print("#include <array>\n\n");

    write("publicKey", publicKey);

// --- write private


    auto privateKeyLen  = i2d_PrivateKey(key.get(),nullptr);

    auto privateKey     = std::vector<unsigned char>(privateKeyLen, 0);
    data                = privateKey.data();

    i2d_PrivateKey(key.get(),&data);

    write("privateKey", privateKey);

}