﷽

# Mine
Mine is minimal cryptography implementation of [RFC-3447](https://tools.ietf.org/html/rfc3447) and [RFC-3602](https://tools.ietf.org/html/rfc3602).

[![Build Status (Develop)](https://img.shields.io/travis/muflihun/mine/develop.svg)](https://travis-ci.org/muflihun/mine)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/muflihun/mine/blob/master/LICENCE)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/MuflihunDotCom/25)

# Introduction
It all started with [ripe](https://github.com/muflihun/ripe) that is dependent upon third-party library (initially OpenSSL then Crypto++) statically linked. However after using it for a while in [residue](https://github.com/muflihun/residue), we realized that portability became an issue for _minimal_ library. So we decided to start implementing the standards ourself, forming _mine_. 

# Status
Currently, it is not production ready. It depends upon third-party library. We are actively working on the development and implementation of RFC. We cannot guarantee the timeframe as all the contributors are full time workers and only do this project in their spare time.

# Features
Mine _will_ support following features:

 * RSA (Encrypt, Decrypt, Sign and Verify) [[RFC-3447](https://tools.ietf.org/html/rfc3447)]
 * AES-CBC [[RFC-3602](https://tools.ietf.org/html/rfc3602)]
 * ZLib (Depend upon libz, eventually implement [[RFC-1950](https://tools.ietf.org/html/rfc3602)]
 * Base-64 (Encode, Decode)
 * Hex (Encode, Decode)
 
For _minimal_ library this is what we are aiming.

# Contribution
We are currently not accepting any pull requests for this project but if you have security concerns or see an issue in implementation please let us know via github issues.

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
