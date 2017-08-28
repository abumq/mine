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
    /// \brief Convert mode for various functions
    ///
    enum class ConvertMode {
        Plain,
        Base16,
        Base64
    };

    ///
    /// \brief A key is a byte array
    ///
    using Key = ByteArray;

    ///
    /// \brief Ciphers the input with specified hex key
    /// \param key Hex key
    /// \param inputMode the type of input. Defaults to Plain
    /// \param outputEncoding Type of encoding for cipher
    /// \return Base16 encoded cipher
    ///
    static std::string cipher(const std::string& input, const std::string& key, ConvertMode inputMode = ConvertMode::Plain, ConvertMode outputEncoding = ConvertMode::Base16);

    ///
    /// \brief Ciphers the input with specified hex key using CBC mode
    /// \param key Hex key
    /// \param iv Initialization vector, passed by reference. If empty a random is generated and passed in
    /// \param inputMode the type of input. Defaults to Plain
    /// \param outputEncoding Type of encoding for cipher
    /// \return Base16 encoded cipher
    ///
    static std::string cipher(const std::string& input, const std::string& key, std::string& iv, ConvertMode inputMode = ConvertMode::Plain, ConvertMode outputEncoding = ConvertMode::Base16);

    ///
    /// \brief Deciphers the input with specified hex key
    /// \param key Hex key
    /// \param inputMode the type of input. Defaults to base16
    /// \param outputEncoding Type of encoding for result
    /// \return Base16 encoded cipher
    ///
    static std::string decipher(const std::string& input, const std::string& key, ConvertMode inputMode = ConvertMode::Base16, ConvertMode outputEncoding = ConvertMode::Plain);

    ///
    /// \brief Deciphers the input with specified hex key using CBC mode
    /// \param key Hex key
    /// \param iv Initialization vector
    /// \param inputMode the type of input. Defaults to base16
    /// \param outputEncoding Type of encoding for result
    /// \return Base16 encoded cipher
    ///
    static std::string decipher(const std::string& input, const std::string& key, const std::string& iv, ConvertMode inputMode = ConvertMode::Base16, ConvertMode outputEncoding = ConvertMode::Plain);

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
    /// \ref Sec. 4.2.1
    ///
    static byte xtime(byte x);

    ///
    /// \ref Sec. 4.2.1
    ///
    static byte multiply(byte x, byte y);

    ///
    /// \brief Mixing columns for the state
    /// \ref Sec. 5.1.3
    ///
    static void mixColumns(State* state);

    ///
    /// \brief Transformation in the Inverse Cipher
    /// that is the reverse of subBytes()
    /// \ref Sec. 5.3.2
    ///
    static void invSubBytes(State* state);

    ///
    /// \brief  Transformation in the Inverse Cipher that is
    /// the reverse of shiftRows()
    /// \ref Sec. 5.3.1
    ///
    static void invShiftRows(State* state);

    ///
    /// \brief Transformation in the Inverse Cipher
    /// that is the reverse of mixColumns()
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

    ///
    /// \brief Initializes the state with input. This function
    /// also pads the input if needed (i.e, input is not block of 128-bit)
    ///
    static void initState(State* state, ByteArray input);

    ///
    /// \brief Generates random bytes of length
    ///
    static ByteArray generateRandomBytes(const std::size_t len);

    ///
    /// \brief Creates byte array from input based on input mode
    ///
    static ByteArray resolveInputMode(const std::string& input, ConvertMode inputMode);

    ///
    /// \brief Creates string from byte array based on convert mode
    ///
    static std::string resolveOutputMode(const ByteArray& input, ConvertMode outputMode);

    ///
    /// \brief Exclusive XOR with arr
    ///
    static ByteArray* xorWith(ByteArray* input, const ByteArray* arr);

    ///
    /// \brief Raw encryption function - not for public use
    /// \param input 128-bit plain input
    /// If array is bigger it's chopped and if it's smaller, it's padded
    /// please use alternative functions if your array is bigger. Those
    /// function will handle all the bytes correctly.
    /// \param key Pointer to a valid AES key
    /// \note This does not do any key or input validation
    /// \return 128-bit cipher text
    ///
    static ByteArray rawCipher(const ByteArray& input, const Key* key);

    ///
    /// \brief Raw decryption function - not for public use
    /// \param input 128-bit cipher input
    /// If array is bigger it's chopped and if it's smaller, it's padded
    /// please use alternative functions if your array is bigger. Those
    /// function will handle all the bytes correctly.
    /// \param key Byte array of key
    /// \return 128-bit plain text
    ///
    static ByteArray rawDecipher(const ByteArray& input, const Key* key);

    ///
    /// \brief Ciphers with ECB-Mode, the input can be as long as user wants
    /// \param input Plain input of any length
    /// \param key Pointer to a valid AES key
    /// \param iv Initialization vector
    /// \return Cipher text byte array
    ///
    static ByteArray cipher(const ByteArray& input, const Key* key);

    ///
    /// \brief Deciphers with ECB-Mode, the input can be as long as user wants
    /// \param input Plain input of any length
    /// \param key Pointer to a valid AES key
    /// \param iv Initialization vector
    /// \return Cipher text byte array
    ///
    static ByteArray decipher(const ByteArray& input, const Key* key);

    ///
    /// \brief Ciphers with CBC-Mode, the input can be as long as user wants
    /// \param input Plain input of any length
    /// \param key Pointer to a valid AES key
    /// \param iv Initialization vector
    /// \return Cipher text byte array
    ///
    static ByteArray cipher(const ByteArray& input, const Key* key, ByteArray& iv);

    ///
    /// \brief Deciphers with CBC-Mode, the input can be as long as user wants
    /// \param input Plain input of any length
    /// \param key Pointer to a valid AES key
    /// \param iv Initialization vector
    /// \return Cipher text byte array
    ///
    static ByteArray decipher(const ByteArray& input, const Key* key, ByteArray& iv);

    ///
    /// \brief Converts 4x4 byte state matrix in to linear 128-bit byte array
    ///
    static ByteArray stateToByteArray(const State* state);

    AES() = delete;
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;

    friend class AESTest_RawCipher_Test;
    friend class AESTest_RawCipherPlain_Test;
    friend class AESTest_RawCipherBase64_Test;
    friend class AESTest_RawSimpleCipher_Test;
    friend class AESTest_RawSimpleDecipher_Test;
    friend class AESTest_SubByte_Test;
    friend class AESTest_InvSubByte_Test;
    friend class AESTest_ShiftRows_Test;
    friend class AESTest_InvShiftRows_Test;
    friend class AESTest_MixColumns_Test;
    friend class AESTest_InvMixColumns_Test;
    friend class AESTest_KeyExpansion_Test;
    friend class AESTest_AddRoundKey_Test;
    friend class AESTest_CbcCipher_Test;
};
} // end namespace mine

#endif // AES_H
