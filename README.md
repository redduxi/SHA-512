# SHA-512
C++ Implementation of SHA-512 and SHA-384 hashing algorithm

[RFC Documentation](https://tools.ietf.org/html/rfc4634)


## Usage
#### SHA-512
```c++
#include "SHA512CryptoServiceProvider.h"
////
SHA512CryptoServiceProvider s;
string hash = s.Hashing("a");
```
#### SHA-384
```c++
#include "SHA384CryptoServiceProvider.h"
////
SHA384CryptoServiceProvider s;
string hash = s.Hashing("a");
```
