<p align="center">
  ﷽
</p>

<p align="center">
    <a href="https://github.com/abumq/mine">
      <img width="400px" src="https://github.com/abumq/mine/raw/master/mine.png?" />
    </a>
    <p align="center">Minimal and single-header cryptography library (AES, RSA, Base16, Base64, ZLib)</p>
</p>

<p align="center">
  <a aria-label="Version" href="https://github.com/abumq/mine/releases/latest">
    <img alt="" src="https://img.shields.io/github/release/abumq/mine.svg?style=for-the-badge&labelColor=000000">
  </a>
  <a aria-label="License" href="https://github.com/abumq/mine/blob/master/LICENSE">
    <img alt="Apache 2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=for-the-badge&labelColor=220000">
  </a>
</p>

Mine is fast, memory-efficient, single-header minimal cryptography implementation for small-medium projects that cannot afford to link to external libraries.

# Overview
It all started with [ripe](https://github.com/abumq/ripe) that depends on third-party library (initially OpenSSL then Crypto++) linked statically. However after deploying [residue](https://github.com/abumq/residue) with ripe to older distributions of linux, we learnt that portability is an issue for ripe as _minimal_ library (because of it's dependencies). So we started to implement standards forming _Mine_.

We are very careful with our implementations and have over 50 [test cases](/test/) in-place.

# Installation (API)
Simply copy `mine.h` and `mine.cc` from [`package/`](/package/) directory to your project or your local machine.

Alternatively, feel free to link it as shared or static library (you will need to compile yourself)

# Installation (CLI Tool)
You can either download binary for your platform via [releases](https://github.com/abumq/mine/releases) page or using NPM

```
npm install -g mine-linux@latest
sudo ln -s `which mine-linux` /usr/local/bin/mine
```

```
npm install -g mine-darwin@latest
sudo ln -s `which mine-darwin` /usr/local/bin/mine
```

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

# Quick Reference

### Base16

 * `mine::Base16::encode(str);`
 * `mine::Base16::encode(str.begin(), str.end());`
 * `mine::Base16::decode(encoding);`

### Base64

 * `mine::Base64::encode(str);`
 * `mine::Base64::encode(str.begin(), str.end());`
 * `mine::Base64::decode(encoding);`
 * `mine::Base64::decode(encoding.begin(), encoding.end());`
 * `mine::Base64::expectedLength(n);`

### AES

 ```c++
 std::string random256BitKey = mine::AES::generateRandomKey(256);

 mine::AES aesManager;
 aesManager.encrypt(b16Input, hexKey, mine::MineCommon::Encoding::Base16, mine::MineCommon::Encoding::Base64); // takes base16, encrypts and returns base64

 aesManager.setKey(random256BitKey); // now use this key
 aesManager.encr(b16Input, mine::MineCommon::Encoding::Base16, mine::MineCommon::Encoding::Base64); // don't need key with requests
 aesManager.decr(b64Input, mine::MineCommon::Encoding::Base64, mine::MineCommon::Encoding::Raw); // Returns raw string
 ```

### ZLib

 * `mine::ZLib::compressString(str);`
 * `mine::ZLib::decompressString(str);`
 * `mine::ZLib::decompressFile(outputFile, inputFile);`

# Contribution
You can contribute to the project by testing on various platforms (e.g, Windows, Android etc)

# License

```
Copyright 2017-present @abumq (Majid Q.)

https://github.com/abumq/mine

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

  [banner]: https://raw.githubusercontent.com/abumq/mine/master/mine.png
