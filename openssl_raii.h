#pragma once

#include <memory>

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