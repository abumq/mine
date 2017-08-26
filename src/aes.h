//
//  aes.h
//  Part of Mine crypto library
//
//  You should not use this file, use mine.h
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright (c) 2017 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#ifndef AES_H
#define AES_H

#include <string>
#include <array>
#include <vector>

namespace mine {

using byte = unsigned char;
using Word = std::array<byte, 4>;
using Key = std::array<byte, 16>;
using RoundKeys = std::vector<Key>;

///
/// \brief Provides AES crypto functionalities
///
class AES {
public:

    static void transposeBytes(byte input[], std::size_t len);
private:

    ///
    /// \brief State as described in FIPS.197 Sec. 3.4
    /// \see kNb
    ///
    using CipherState = byte[4][4 /* Nb */];

    ///
    /// \brief AES works on 16 bit block at a time
    ///
    static const uint8_t kBlockSize = 16;

    ///
    /// \brief As defined in FIPS. 197 Sec. 5.1.1
    ///
    static const byte kSBox[256];

    ///
    /// \brief As defined in FIPS. 197 Sec. 5.3.2
    ///
    static const byte kSBoxInverse[256];

    static const byte kRoundConstant[11];

    ///
    /// \brief Nb
    /// \note we make it constant as FIPS.197 p.9 says
    /// "For this standard, Nb=4."
    ///
    static const uint8_t kNb = 4;

    ///
    /// \brief Raw encryption function
    /// \param output Byte array for desitnation
    /// \param input Byte array of input
    /// \param key Byte array of key
    /// \return cipher text (byte array)
    ///
    static void cipher(byte output[], byte input[], std::size_t len, byte key[], std::size_t keySize = 128);

    static void getKeyParams(std::size_t keySize, uint8_t* keyExSize, uint8_t* Nk, uint8_t* Nr);

    ///
    /// \brief generateRoundKeys
    /// \param output
    /// \param keySchedule
    ///
    static RoundKeys keyExpansion(byte key[], std::size_t keySize);

    ///
    /// \brief Prints bytes in hex format in 4x4 matrix fashion
    ///
    static void printBytes(byte b[], std::size_t len);

    AES() = delete;
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;

    friend class AESTest_SimpleCipher_Test;
};
} // end namespace mine

#endif // AES_H
