# opensslSign

Build `keygen` and run

    x64\debug\keygen > libSign/keys.h

This generates a 

* 2048 bit RSA key,  
* key based on an Elliptic curve
* key based on an Edwards curve
* a 2048 bit DSA key,  
* and a SLH-DSA key

    
    
Build `sign` and run `sign`

    OpenSSL Version: OpenSSL 3.5.2 5 Aug 2025

    RSA
    Signature Size - 256
    'Twas brillig, and the slithy toves : true
    'Twas brillig, and the slithy taves : false

    EC256
    Signature Size - 71
    'Twas brillig, and the slithy toves : true
    'Twas brillig, and the slithy taves : false

    ED25519
    Signature Size - 64
    'Twas brillig, and the slithy toves : true
    'Twas brillig, and the slithy taves : false

    DSA
    Signature Size - 62
    'Twas brillig, and the slithy toves : true
    'Twas brillig, and the slithy taves : false

    SLH-DSA
    Signature Size - 7856
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

ED25519
* small signature
* faster to sign compared to RSA
* slower to verify compared to RSA
* Standard alternative to EC256

DSA
* small signature
* slowe to verify compared to RSA
* Designed for signatures

SHL-DSA
* huge signature
* slowest to verify compared to RSA
* Post-quantum



To verify the internet's assertions about verification speed

Run x64\Release\signTimings which signs a 40Kb message and then verifies it 100,000 times.

    OpenSSL Version: OpenSSL 3.5.2 5 Aug 2025

    RSA
    100000 verifications of 40960 bytes in 3s

    EC256
    100000 verifications of 40960 bytes in 6s

    ED25519
    100000 verifications of 40960 bytes in 10s

    DSA
    100000 verifications of 40960 bytes in 21s    

    SLH-DSA
    100000 verifications of 40960 bytes in 61s    
