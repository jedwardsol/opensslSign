#include <print>
#include <vector>
#include <string>
#include <string_view>
using namespace std::literals;


#include "openssl_cpp.h"
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#include "libSign/libSign.h"

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



void write(std::string_view prefix, OpenSSL::Key const &key)
{
// --- write public
    {
        auto publicKeyLen   = i2d_PUBKEY(key.get(),nullptr);

        OpenSSL::checkResult(publicKeyLen,"i2d_PUBKEY");

        auto publicKey      = std::vector<uint8_t>(publicKeyLen, 0);
        auto data           = publicKey.data();

        publicKeyLen        = i2d_PUBKEY(key.get(),&data);

        OpenSSL::checkResult(publicKeyLen,"i2d_PUBKEY");

        write(std::string{prefix} + "PublicKey"s, publicKey);
    }

// --- write private
    {
        auto privateKeyLen  = i2d_PrivateKey(key.get(),nullptr);

        OpenSSL::checkResult(privateKeyLen,"i2d_PrivateKey");

        auto privateKey     = std::vector<uint8_t>(privateKeyLen, 0);
        auto data           = privateKey.data();

        privateKeyLen       = i2d_PrivateKey(key.get(),&data);

        OpenSSL::checkResult(privateKeyLen,"i2d_PrivateKey");

        write(std::string{prefix} + "PrivateKey", privateKey);
    }
}


void generate(std::string_view prefix, LibSign::KeyGenerator    generator)
{
    auto key        = generator();
    write(prefix,key);
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

    generate("rsa",     LibSign::RSA::funcs().generateKeys);
    generate("ec256",   LibSign::EC256::funcs().generateKeys);
    generate("ed25519", LibSign::ED25519::funcs().generateKeys);
    generate("dsa",     LibSign::DSA::funcs().generateKeys);
    generate("slhdsa",  LibSign::SLHDSA::funcs().generateKeys);

    std::puts("\n}\n");
}
catch(std::exception const &e)
{
    std::print("Caught : {}\n",e.what());
}
