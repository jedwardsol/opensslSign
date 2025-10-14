# opensslSign

Build `keygen` and run

    x64\debug\keygen > libSign/keys.h

This generates a 2048 bit RSA key,   and 2 EC keys based on 2 different curves.    

    
    
Build `sign` and run `sign`

    OpenSSL Version: OpenSSL 3.5.2 5 Aug 2025

    RSA
    Signature Size - 256
    'Twas brillig, and the slithy toves : true
    'Twas brillig, and the slithy taves : false

    EC256
    Signature Size - 72
    'Twas brillig, and the slithy toves : true
    'Twas brillig, and the slithy taves : false

    EC25519
    Signature Size - 64
    'Twas brillig, and the slithy toves : true
    'Twas brillig, and the slithy taves : false



RSA 
* large signature
* slower to sign compared to EC
* faster to verify compared to EC

EC256 
* small signature
* faster to sign compared to RSA
* slower to verify compared to RSA
* Standard key
* Backdoored by the NSA (allegedly!)

EC25519
* small signature
* faster to sign compared to RSA
* slower to verify compared to RSA
* Standard alternative to EC256




To verify the internet's assertions about verification speed

Run x64\Release\signTimings which signs a 40Kb message and then verifies it 100,000 times    (EVM content is 40Kb uncompressed,  6Kb compressed)

    OpenSSL Version: OpenSSL 3.5.2 5 Aug 2025

    RSA
    100000 verifications of 40960 bytes in 2s

    EC256
    100000 verifications of 40960 bytes in 6s

    EC25519
    100000 verifications of 40960 bytes in 10s