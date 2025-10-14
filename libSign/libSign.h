#pragma once

#include <vector>
#include <functional>
#include <span>
#include <string_view>
#include <ranges>
#include "openssl_cpp.h"


namespace LibSign
{
    using Signature = std::vector<uint8_t>;
    using Message   = std::span<uint8_t const>;

    inline
    Message AsMessage(std::string_view string)
    {
        return Message{reinterpret_cast<uint8_t const*>(string.data()), string.size()};
    }


    using Loader   = std::function<OpenSSL::KeyPair()>;
    using Signer   = std::function<Signature(OpenSSL::PrivateKey const &, Message)>;
    using Verifier = std::function<bool(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message)>;

    struct Funcs 
    {
        Loader      loader;
        Signer      signer;
        Verifier    verifier;
    };


    namespace RSA
    {
        OpenSSL::KeyPair load();
        Signature sign(OpenSSL::PrivateKey const &privateKey, Message message);      
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message);

        inline Funcs funcs() { return{load,sign,verify}; };
    }

    namespace EC256
    {
        OpenSSL::KeyPair load();
        Signature sign(OpenSSL::PrivateKey const &privateKey, Message message);      
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message);

        inline Funcs funcs() { return{load,sign,verify}; };
    }

    namespace EC25519
    {
        OpenSSL::KeyPair load();
        Signature sign(OpenSSL::PrivateKey const &privateKey, Message message);      
        bool verify(OpenSSL::PublicKey const &publicKey, Signature const &signature, Message message);

        inline Funcs funcs() { return{load,sign,verify}; };
    }
}

#pragma comment(lib,"libSign")