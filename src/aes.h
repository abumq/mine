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
#include <vector>
#include "src/rsa.h"

namespace mine {

using byte = unsigned char;

///
/// \brief Handy safe byte array
///
using ByteArray = std::vector<byte>;

///
/// \brief Provides AES crypto functionalities
///
/// This is validated against NIST test data and all
/// the corresponding tests under test/ directory
/// are from NIST themselves.
///
/// Please make sure to use public functions and do not
/// use private functions especially in production as
/// you may end up using them incorrectly. However
/// the source code for AES class is heavily commented for
/// verification on implementation.
///
class AES {
public:

    ///
    /// \brief A key is a byte array
    ///
    using Key = ByteArray;

    ///
    /// \brief Ciphers the input with specified hex key
    /// \param key Hex key
    /// \return Base16 encoded cipher
    ///
    static std::string cipher(const std::string& input, const std::string& key);

private:

    ///
    /// \brief A word is array of 4 byte
    ///
    using Word = std::array<byte, 4>;

    ///
    /// \brief KeySchedule is linear array of 4-byte words
    /// \ref FIPS.197 Sec 5.2
    ///
    using KeySchedule = std::unordered_map<uint8_t, Word>;

    ///
    /// \brief State as described in FIPS.197 Sec. 3.4
    ///
    using State = std::array<Word, 4>;

    ///
    /// \brief AES works on 16 bit block at a time
    ///
    static const uint8_t kBlockSize = 16;

    ///
    /// \brief Defines the key params to it's size
    ///
    static const std::unordered_map<uint8_t, std::vector<uint8_t>> kKeyParams;

    ///
    /// \brief As defined in FIPS. 197 Sec. 5.1.1
    ///
    static const byte kSBox[];

    ///
    /// \brief As defined in FIPS. 197 Sec. 5.3.2
    ///
    static const byte kSBoxInverse[];

    ///
    /// \brief Round constant is constant for each round
    /// it contains 10 values each defined in
    /// Appendix A of FIPS.197 in column Rcon[i/Nk] for
    /// each key size, we add all of them in one array for
    /// ease of access
    ///
    static const byte kRoundConstant[];

    ///
    /// \brief Nb
    /// \note we make it constant as FIPS.197 p.9 says
    /// "For this standard, Nb=4."
    ///
    static const uint8_t kNb = 4;

    ///
    /// \brief Initializes the state with input. This function
    /// also pads the input if needed (i.e, input is not block of 128-bit)
    ///
    static void initState(State* state, ByteArray input);

    ///
    /// \brief Raw encryption function - not for public use
    /// \param input 128-bit plain input
    /// If array is bigger it's chopped and if it's smaller, it's padded
    /// please use alternative functions if your array is bigger. Those
    /// function will handle all the bytes correctly.
    /// \param key Byte array of key
    /// \return 128-bit cipher text
    ///
    static ByteArray cipher(const ByteArray& input, const Key* key);

    ///
    /// \brief Raw decryption function - not for public use
    /// \param input 128-bit cipher input
    /// If array is bigger it's chopped and if it's smaller, it's padded
    /// please use alternative functions if your array is bigger. Those
    /// function will handle all the bytes correctly.
    /// \param key Byte array of key
    /// \return 128-bit plain text
    ///
    static ByteArray decipher(const ByteArray& input, const Key* key);

    ///
    /// \brief Converts 4x4 byte state matrix in to linear 128-bit byte array
    ///
    static ByteArray stateToByteArray(const State* state);

    ///
    /// \brief Key expansion function as described in FIPS.197
    ///
    static KeySchedule keyExpansion(const Key* key);

    ///
    /// \brief Adds round to the state using specified key schedule
    ///
    static void addRoundKey(State* state, const KeySchedule* keySchedule, int round);

    ///
    /// \brief Substitution step for state
    /// \ref Sec. 5.1.1
    ///
    static void subBytes(State* state);

    ///
    /// \brief Shifting rows step for the state
    /// \ref Sec. 5.1.2
    ///
    static void shiftRows(State* state);

    ///
    /// \brief Mixing columns for the state
    /// \ref Sec. 5.1.3
    ///
    static void mixColumns(State* state);

    ///
    /// \brief Transformation in the Inverse Cipher
    /// that is the inverse of subBytes()
    /// \ref Sec. 5.3.2
    ///
    static void invSubBytes(State* state);

    ///
    /// \brief  Transformation in the Inverse Cipher that is
    /// the inverse of shiftRows()
    /// \ref Sec. 5.3.1
    ///
    static void invShiftRows(State* state);

    ///
    /// \brief Transformation in the Inverse Cipher
    /// that is the inverse of mixColumns()
    /// \ref Sec. 5.3.3
    ///
    static void invMixColumns(State* state);

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
    friend class AESTest_RawSimpleCipher_Test;
    friend class AESTest_FiniteFieldMultiply_Test;
    friend class AESTest_KeyExpansion_Test;
    friend class AESTest_AddRoundKey_Test;
};
} // end namespace mine

#endif // AES_H
