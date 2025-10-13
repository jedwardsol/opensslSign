#pragma once

#include <memory>
#include <exception>
#include <string>   

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>


namespace OpenSSL
{
    struct KeyContextDeleter
    {
        void operator()(EVP_PKEY_CTX *context)
        {
            EVP_PKEY_CTX_free(context);
        }
    };

    struct DigestContextDeleter
    {
        void operator()(EVP_MD_CTX *context)
        {
            EVP_MD_CTX_free(context);
        }
    };

    struct KeyDeleter
    {
        void operator()(EVP_PKEY *key)
        {
            EVP_PKEY_free(key);
        }
    };

    using KeyContext    = std::unique_ptr<EVP_PKEY_CTX, KeyContextDeleter>;
    using DigestContext = std::unique_ptr<EVP_MD_CTX,   DigestContextDeleter>;
    using Key           = std::unique_ptr<EVP_PKEY,     KeyDeleter>;
}


namespace OpenSSL
{
    struct openssl_error : std::runtime_error
    {
        openssl_error() : std::runtime_error{getMessage()}
        {}

        openssl_error(std::string name) : std::runtime_error{name + " " + getMessage()}
        {}

        static std::string getMessage()
        {
            char message[512]{};
            ERR_error_string_n(ERR_get_error(), message, 512);
            return message;
        }
    };

}

