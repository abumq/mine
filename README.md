﷽

![banner]

Mine is single-header minimal cryptography implementation for small-medium projects that cannot afford to link to external libraries.

[![Build Status](https://img.shields.io/travis/muflihun/mine/develop.svg)](https://travis-ci.org/muflihun/mine)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/muflihun/mine/blob/master/LICENCE)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/MuflihunDotCom/25)

# Overview
It all started with [ripe](https://github.com/muflihun/ripe) that is dependent upon third-party library (initially OpenSSL then Crypto++) statically linked. However after deploying [residue](https://github.com/muflihun/residue) (which used ripe until mine came to life) to older distributions of linux, we realized that portability is an issue for ripe as _minimal_ library. So we started to implement the standards ourselves, forming _Mine_. 

# Installation
Simply copy `mine.h` and `mine.cc` from [`package/`](/package/) directory to your project or your local machine.

# Status
Currently, it is not production ready. It depends upon third-party library. We are actively working on the development and implementation of RFC. We cannot guarantee the timeframe as all the contributors are full time workers and only do this project in their spare time.

We are very careful with our implementations and have [unit tests](/test/) in place. 

# Features
Mine _will_ support following features:

 * RSA (Encrypt, Decrypt, Sign and Verify) [[RFC-3447](https://tools.ietf.org/html/rfc3447)]
 * AES-CBC [[RFC-3602](https://tools.ietf.org/html/rfc3602)]
 * ZLib (Depend upon libz, eventually implement [RFC-1950](https://tools.ietf.org/html/rfc3602))
 * Base16 (Encode, Decode)
 * Base64 (Encode, Decode)
 
For _minimal_ library this is what we are aiming.

# Contribution
You can only contribute by testing on various platforms and reporting the issues. We are not accepting any pull requests until first release.

# License
```
Copyright 2017 Muflihun Labs

https://github.com/muflihun/
https://muflihun.com
https://muflihun.github.io

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
