#include <print>
#include <vector>
#include <span>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "openssl_cpp.h"
#include "libSign.h"

#include "keys.h"


namespace LibSign
{


    namespace RSA
    {
        OpenSSL::Key generate()
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

            return key;
        }
    }

    namespace EC256
    {
        OpenSSL::Key generate()
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

            return key;
        }
    }

    namespace ED25519
    {
        OpenSSL::Key generate()
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

            return key;
        }
    }

    namespace DSA
    {
        OpenSSL::Key generate()
        {
            auto paramContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr)};

            checkBool(paramContext,"EVP_PKEY_CTX_new_id");


            auto result     = EVP_PKEY_paramgen_init(paramContext.get());

            OpenSSL::checkResult(result,"EVP_PKEY_paramgen_init");

            result          = EVP_PKEY_CTX_set_dsa_paramgen_bits(paramContext.get(), 2048);
  
            OpenSSL::checkResult(result,"EVP_PKEY_CTX_set_dsa_paramgen_bits");


            auto keyParams  = OpenSSL::Key{};

            EVP_PKEY_paramgen(paramContext.get(), std::out_ptr(keyParams));

        //
        // ---
        //

            auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new(keyParams.get(), nullptr)};

            checkBool(keyContext,"EVP_PKEY_CTX_new");

            result          = EVP_PKEY_keygen_init(keyContext.get());

            OpenSSL::checkResult(result,"EVP_PKEY_keygen_init");

        //
        // ---
        //

            auto key        = OpenSSL::Key{};

            result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));

            OpenSSL::checkResult(result,"EVP_PKEY_keygen");

            return key;
        }
    }

    namespace SLHDSA
    {
        OpenSSL::Key generate()
        {
            auto keyContext = OpenSSL::KeyContext{EVP_PKEY_CTX_new_id(EVP_PKEY_SLH_DSA_SHAKE_128S, nullptr)};

            OpenSSL::checkBool(keyContext,"EVP_PKEY_CTX_new_id");

            auto result     = EVP_PKEY_keygen_init(keyContext.get());

            OpenSSL::checkResult(result,"EVP_PKEY_keygen_init");


        //
        // ---
        //

            auto key        = OpenSSL::Key{};

            result          = EVP_PKEY_keygen(keyContext.get(), std::out_ptr(key));

            OpenSSL::checkResult(result,"EVP_PKEY_keygen");

            return key;
        }
    }
}