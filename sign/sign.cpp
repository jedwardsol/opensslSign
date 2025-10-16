#include <print>
#include <vector>
#include <span>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "openssl_cpp.h"
#include "libSign/libSign.h"




void go(LibSign::Funcs const &funcs)
try
{
    auto correct = "'Twas brillig, and the slithy toves";
    auto wrong   = "'Twas brillig, and the slithy taves";

    //---

    auto const keys         = funcs.loadKeys();
 
    auto const signature    = funcs.sign(keys.second, LibSign::AsMessage(correct));

    std::print("Signature Size - {}\n",signature.size());
 
    //---

    std::print("{} : {}\n",correct,funcs.verify(keys.first,signature,LibSign::AsMessage(correct)));
    std::print("{} : {}\n",wrong,  funcs.verify(keys.first,signature,LibSign::AsMessage(wrong)));

}
catch(std::exception const &e)
{
    std::print("{} : {}\n",__func__,e.what());
}




int main()
try
{
    std::print("OpenSSL Version: {}\n", OpenSSL_version(OPENSSL_VERSION));
  
    std::print("\nRSA\n");
    go(LibSign::RSA::funcs());

    std::print("\nEC256\n");
    go(LibSign::EC256::funcs());

    std::print("\nED25519\n");
    go(LibSign::ED25519::funcs());

    std::print("\nDSA\n");
    go(LibSign::DSA::funcs());

    std::print("\nSLH-DSA\n");
    go(LibSign::SLHDSA::funcs());

}
catch(std::exception const &e)
{
    std::print("{} : {}\n",__func__,e.what());
}
