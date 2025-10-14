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

#include <chrono>
namespace chr = std::chrono;
using Clock = chr::steady_clock;



constexpr auto messageSize  = 40*1024;
constexpr auto iterations   = 100'000;




void go(LibSign::Funcs const &funcs)
try
{
    auto string = std::string(messageSize,'J');

    //---
 
    auto const keys         = funcs.loader();
    auto const signature    = funcs.signer(keys.second, LibSign::AsMessage(string));
 
    //---

    auto start = Clock::now();

    for(int i=0;i<iterations;i++)
    {
        auto verified = funcs.verifier(keys.first,signature,LibSign::AsMessage(string));
            
        OpenSSL::checkBool(verified,"verification");

    }

    auto end = Clock::now();

    std::print("{} verifications of {} bytes in {}\n",iterations,messageSize,chr::duration_cast<chr::seconds>(end-start));

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

    std::print("\nEC25519\n");
    go(LibSign::EC25519::funcs());
}
catch(std::exception const &e)
{
    std::print("{} : {}\n",__func__,e.what());
}
