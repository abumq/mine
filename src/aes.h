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
#include <unordered_map>

namespace mine {

using byte = unsigned char;

///
/// \brief Provides AES crypto functionalities
///
class AES {
public:
    using ByteArray = std::vector<byte>;
    using Key = ByteArray;

    static void transposeBytes(byte input[], std::size_t len);
private:
    using Word = std::array<byte, 4>;

    ///
    /// \brief KeySchedule is linear array of 4-byte words
    /// \ref FIPS.197 Sec 5.2
    ///
    using KeySchedule = std::unordered_map<int, Word>;

    ///
    /// \brief State as described in FIPS.197 Sec. 3.4
    ///
    using State = std::array<std::array<byte, 4>, 4>;

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
    /// \brief Raw encryption function - not for public use
    /// \param input 128-bit Byte array of input.
    /// If array is bigger it's chopped and if it's smaller, it's padded
    /// please use alternative functions if your array is bigger. Those
    /// function will handle all the bytes correctly.
    /// \param key Byte array of key
    /// \return cipher text (byte array)
    ///
    static ByteArray cipher(const ByteArray& input, const Key* key);

    static void getKeyParams(std::size_t keySize, uint8_t* keyExSize, uint8_t* Nk, uint8_t* Nr);

    ///
    /// \brief Key expansion function as described in FIPS.197
    ///
    static KeySchedule keyExpansion(const Key* key);

    ///
    /// \brief Adds round to the state using specified key schedule
    ///
    static void addRoundKey(State* state, const KeySchedule* keySchedule, int round);

    ///
    /// \brief Substitution step for state (Sec. 5.1.1)
    ///
    static void subBytes(State* state);

    ///
    /// \brief Shifting rows step for the state (Sec. 5.1.2)
    ///
    static void shiftRows(State* state);

    ///
    /// \brief Mixing columns for the state  (Sec. 5.1.3)
    ///
    static void mixColumns(State* state);

    ///
    /// \brief Multiply two numbers in the GF(2^8) finite field defined
    ///
    static byte finiteFieldMultiply(byte a, byte b);

    ///
    /// \brief Prints bytes in hex format in 4x4 matrix fashion
    ///
    static void printBytes(const ByteArray& b);

    ///
    /// \brief Prints state for debugging
    ///
    static void printState(const State*);

    AES() = delete;
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;

    friend class AESTest_RawCipher_Test;
    friend class AESTest_FiniteFieldMultiply_Test;
    friend class AESTest_KeyExpansion_Test;
    friend class AESTest_AddRoundKey_Test;
};
} // end namespace mine

#endif // AES_H
