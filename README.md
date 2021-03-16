# SHA-512
C++ Implementation of SHA-512 and SHA-384 hashing algorithm

[RFC Documentation](https://tools.ietf.org/html/rfc4634)


## Usage

```c++
#include "SHA512.h"
////
SHA512CryptoServiceProvider s;
string hash = s.Hashing("a");
```
```c++
#include "SHA384.h"
////
SHA384CryptoServiceProvider s;
string hash = s.Hashing("a");
```