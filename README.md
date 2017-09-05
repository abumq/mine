﷽

![banner]

Mine is fast, single-header minimal cryptography implementation for small-medium projects that cannot afford to link to external libraries.

[![Build Status](https://img.shields.io/travis/muflihun/mine/develop.svg)](https://travis-ci.org/muflihun/mine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/muflihun/mine/blob/master/LICENCE)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/MuflihunDotCom/25)

# Overview
It all started with [ripe](https://github.com/muflihun/ripe) that depends on third-party library (initially OpenSSL then Crypto++) linked statically. However after deploying [residue](https://github.com/muflihun/residue) with ripe to older distributions of linux, we realized that portability is an issue for ripe as _minimal_ library. So we started to implement standards forming _Mine_.

We are very careful with our implementations and have [unit tests](/test/) in place.

# Installation
Simply copy `mine.h` and `mine.cc` from [`package/`](/package/) directory to your project or your local machine.

Alternatively, feel free to link it as shared or static library (you will need to compile yourself)
 
# Features
Mine supports following features:

 * Base16 Encoding
 * Base64 Encoding
 * RSA [[RFC-3447](https://tools.ietf.org/html/rfc3447)]
 * AES [[FIPS Pub. 197](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)]
 * ZLib (Depends upon libz)
 
This is what we are aiming for _minimal_ crypto library.

# Notes

 * It is natively developed on macOS and Linux operating systems
 * It is extremely fast with compiler optimization level 1 (or higher)
 * RSA needs big number implementation, for unit tests we use [Integer from Crypto++](https://www.cryptopp.com/wiki/Integer)
 * RSA currently does not support signing & verification or reading keys from PEM files

# Contribution
You can contribute to the project by testing on various platforms (e.g, Windows, Android etc)

# License

```
Copyright 2017 Muflihun Labs

https://github.com/muflihun/
https://muflihun.github.io
https://muflihun.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

  [banner]: https://raw.githubusercontent.com/muflihun/mine/develop/mine.png
