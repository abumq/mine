//
//  Bismillah ar-Rahmaan ar-Raheem
//
//  Mine (Unreleased)
//  Single header minimal cryptography library
//
//  Copyright (c) 2017 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//  https://muflihun.github.io/mine
//  https://muflihun.com
//
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <iterator>
#include <random>

#include "mine.h"

using namespace mine;


const std::string Base16::kValidChars = "0123456789ABCDEF";

const std::unordered_map<byte, byte> Base16::kDecodeMap = {
    {0x30, 0x00}, {0x31, 0x01}, {0x32, 0x02}, {0x33, 0x03},
    {0x34, 0x04}, {0x35, 0x05}, {0x36, 0x06}, {0x37, 0x07},
    {0x38, 0x08}, {0x39, 0x09}, {0x41, 0x0A}, {0x42, 0x0B},
    {0x43, 0x0C}, {0x44, 0x0D}, {0x45, 0x0E}, {0x46, 0x0F}
};

ByteArray Base16::fromString(const std::string& hex)
{
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Invalid base-16 encoding");
    }

    ByteArray byteArr;
    for (std::size_t i = 0; i < hex.length(); i += 2) {
        byteArr.push_back(encode(hex.substr(i, 2).c_str()));
    }
    return byteArr;
}

std::string Base16::toRawString(const ByteArray& input)
{
    std::ostringstream ss;
    std::copy(input.begin(), input.end(), std::ostream_iterator<char>(ss));
    return ss.str();
}

void Base16::decode(char a, char b, std::ostringstream& ss)
{
    int b0 = a & 0xff;
    int b1 = b & 0xff;
    try {
        ss << static_cast<byte>((b0 << 4) | kDecodeMap.at(b1));
    } catch (const std::exception&) {
        throw std::invalid_argument("Invalid base-16 encoding");
    }
}


const std::string Base64::kValidChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

const std::unordered_map<byte, byte> Base64::kDecodeMap = {
    {0x41, 0x00}, {0x42, 0x01}, {0x43, 0x02}, {0x44, 0x03},
    {0x45, 0x04}, {0x46, 0x05}, {0x47, 0x06}, {0x48, 0x07},
    {0x49, 0x08}, {0x4A, 0x09}, {0x4B, 0x0A}, {0x4C, 0x0B},
    {0x4D, 0x0C}, {0x4E, 0x0D}, {0x4F, 0x0E}, {0x50, 0x0F},
    {0x51, 0x10}, {0x52, 0x11}, {0x53, 0x12}, {0x54, 0x13},
    {0x55, 0x14}, {0x56, 0x15}, {0x57, 0x16}, {0x58, 0x17},
    {0x59, 0x18}, {0x5A, 0x19}, {0x61, 0x1A}, {0x62, 0x1B},
    {0x63, 0x1C}, {0x64, 0x1D}, {0x65, 0x1E}, {0x66, 0x1F},
    {0x67, 0x20}, {0x68, 0x21}, {0x69, 0x22}, {0x6A, 0x23},
    {0x6B, 0x24}, {0x6C, 0x25}, {0x6D, 0x26}, {0x6E, 0x27},
    {0x6F, 0x28}, {0x70, 0x29}, {0x71, 0x2A}, {0x72, 0x2B},
    {0x73, 0x2C}, {0x74, 0x2D}, {0x75, 0x2E}, {0x76, 0x2F},
    {0x77, 0x30}, {0x78, 0x31}, {0x79, 0x32}, {0x7A, 0x33},
    {0x30, 0x34}, {0x31, 0x35}, {0x32, 0x36}, {0x33, 0x37},
    {0x34, 0x38}, {0x35, 0x39}, {0x36, 0x3A}, {0x37, 0x3B},
    {0x38, 0x3C}, {0x39, 0x3D}, {0x2B, 0x3E}, {0x2F, 0x3F},
    {0x3D, 0x40}
};

std::size_t Base64::countChars(const std::string& str) noexcept
{
    std::size_t result = 0UL;
    for (auto it = str.begin(); it <= str.end();) {
        int c = *it & 0xff;
        int charCount = 0;
        if (c == 0x0) {
            // \0
            ++it; // we increment iter manually
        } else if (c <= 0x7f) {
            charCount = 1;
        } else if (c <= 0x7ff) {
            charCount = 2;
        } else if (c <= 0xffff) {
            charCount = 3;
        } else {
            charCount = 4;
        }
        result += charCount;
        it += charCount;
    }
    return result;
}

#define MINE_PROFILING 1
#if MINE_PROFILING
#   include <chrono>
#   include <iostream>
#endif


const byte AES::kSBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const byte AES::kSBoxInverse[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint8_t AES::kRoundConstant[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

const byte AES::kRandomBytesList[256] = {
    0x6f, 0x48, 0x15, 0x46, 0x77, 0x58, 0x05, 0x0b, 0x02, 0x6f, 0x20, 0x66, 0x18, 0x5a, 0x17, 0x27,
    0x45, 0x6c, 0x0f, 0x33, 0x08, 0x58, 0x2a, 0x54, 0x75, 0x53, 0x1e, 0x2a, 0x09, 0x13, 0x0f, 0x20,
    0x49, 0x49, 0x4b, 0x18, 0x3c, 0x1f, 0x06, 0x0e, 0x58, 0x52, 0x7c, 0x25, 0x58, 0x7d, 0x33, 0x27,
    0x14, 0x47, 0x66, 0x3f, 0x68, 0x66, 0x49, 0x27, 0x77, 0x10, 0x33, 0x26, 0x6c, 0x34, 0x10, 0x4e,
    0x10, 0x48, 0x07, 0x7c, 0x11, 0x06, 0x60, 0x61, 0x28, 0x29, 0x47, 0x5b, 0x3b, 0x16, 0x75, 0x74,
    0x14, 0x4a, 0x4a, 0x78, 0x21, 0x35, 0x77, 0x50, 0x17, 0x74, 0x3c, 0x26, 0x05, 0x31, 0x65, 0x36,
    0x48, 0x3c, 0x29, 0x4c, 0x1e, 0x78, 0x5e, 0x51, 0x16, 0x7f, 0x0b, 0x6d, 0x14, 0x41, 0x6e, 0x15,
    0x35, 0x7a, 0x4c, 0x59, 0x52, 0x5e, 0x0c, 0x22, 0x29, 0x7d, 0x6f, 0x0b, 0x73, 0x55, 0x0c, 0x44,
    0x3d, 0x70, 0x15, 0x33, 0x71, 0x23, 0x34, 0x77, 0x39, 0x68, 0x04, 0x6d, 0x2b, 0x4b, 0x52, 0x4d,
    0x30, 0x03, 0x38, 0x09, 0x5b, 0x58, 0x09, 0x5f, 0x4b, 0x54, 0x5d, 0x53, 0x35, 0x6b, 0x48, 0x43,
    0x3e, 0x58, 0x7d, 0x48, 0x7e, 0x6d, 0x71, 0x28, 0x14, 0x0e, 0x41, 0x58, 0x20, 0x7b, 0x48, 0x14,
    0x1f, 0x68, 0x07, 0x6d, 0x62, 0x4a, 0x72, 0x34, 0x7d, 0x66, 0x3e, 0x42, 0x79, 0x47, 0x36, 0x11,
    0x37, 0x08, 0x1f, 0x0a, 0x08, 0x2f, 0x66, 0x11, 0x2b, 0x0e, 0x03, 0x33, 0x14, 0x66, 0x25, 0x3e,
    0x08, 0x6f, 0x6e, 0x69, 0x71, 0x1e, 0x1c, 0x02, 0x09, 0x0a, 0x45, 0x24, 0x73, 0x58, 0x4b, 0x43,
    0x5a, 0x53, 0x4f, 0x0e, 0x39, 0x71, 0x13, 0x0c, 0x02, 0x46, 0x66, 0x2a, 0x56, 0x4c, 0x2b, 0x37,
    0x34, 0x45, 0x6e, 0x01, 0x4d, 0x12, 0x35, 0x4a, 0x29, 0x66, 0x30, 0x5b, 0x31, 0x4f, 0x6e, 0x3d
};

const std::unordered_map<uint8_t, std::vector<uint8_t>> AES::kKeyParams = {
    { 16, {{ 4, 10 }} },
    { 24, {{ 6, 12 }} },
    { 32, {{ 8, 14 }} }
};

void AES::printBytes(const ByteArray& b)
{
    for (std::size_t i = 1; i <= b.size(); ++i) {
        std::cout << "0x" << (b[i - 1] < 10 ? "0" : "") << Base16::encode(b[i - 1]) << "  ";
        if (i % 4 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << std::endl << "------" << std::endl;
}

void AES::printState(const State* state)
{
    for (std::size_t i = 0; i < kNb; ++i) {
        for (std::size_t j = 0; j < kNb; ++j) {
            byte b = state->at(j)[i];
            std::cout << "0x" << (b < 10 ? "0" : "") << Base16::encode(b) << "  ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

AES::KeySchedule AES::keyExpansion(const Key* key)
{

    // rotateWord function is specified in FIPS.197 Sec. 5.2:
    //      The function RotWord() takes a
    //      word [a0,a1,a2,a3] as input, performs a cyclic permutation,
    //      and returns the word [a1,a2,a3,a0]. The
    //      round constant word array
    //
    // Our definition:
    //      We swap the first byte
    //      to last one causing it to shift to the left
    //      i.e,
    //           [a1]      [a2]
    //           [a2]      [a3]
    //           [a3]  =>  [a4]
    //           [a4]      [a1]
    //
    auto rotateWord = [](Word* w) -> Word* {
        byte t = w->at(0);
        w->at(0) = w->at(1);
        w->at(1) = w->at(2);
        w->at(2) = w->at(3);
        w->at(3) = t;
        return w;
    };

    // this function is also specified in FIPS.197 Sec. 5.2:
    //      SubWord() is a function that takes a four-byte
    //      input word and applies the S-box
    //      to each of the four bytes to produce an output word.
    //
    // Out definition:
    // It's a simple substition with kSbox for corresponding byte
    // index
    //
    auto substituteWord = [](Word* w) -> Word* {
        for (uint8_t i = 0; i < 4; ++i) {
            w->at(i) = kSBox[w->at(i)];
        }
        return w;
    };

    std::size_t keySize = key->size();

    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw std::invalid_argument("Invalid AES key size");
    }

    uint8_t Nk = kKeyParams.at(keySize)[0],
            Nr = kKeyParams.at(keySize)[1];

    KeySchedule words(kNb * (Nr+1));

    uint8_t i = 0;
    // copy main key as is for the first round
    for (; i < Nk; ++i) {
        words[i] = {{
                        (*key)[(i * 4) + 0],
                        (*key)[(i * 4) + 1],
                        (*key)[(i * 4) + 2],
                        (*key)[(i * 4) + 3],
                    }};
    }

    for (; i < kNb * (Nr + 1); ++i) {
        Word temp = words[i - 1];

        if (i % Nk == 0) {
            rotateWord(&temp);
            substituteWord(&temp);
            // xor with rcon
            temp[0] ^= kRoundConstant[(i / Nk) - 1];
        } else if (Nk == 8 && i % Nk == 4) {
            // See note for 256-bit keys on Sec. 5.2 on FIPS.197
            substituteWord(&temp);
        }


        // xor previous column of new key with corresponding column of
        // previous round key
        Word correspondingWord = words[i - Nk];
        byte b0 = correspondingWord[0] ^ temp[0];
        byte b1 = correspondingWord[1] ^ temp[1];
        byte b2 = correspondingWord[2] ^ temp[2];
        byte b3 = correspondingWord[3] ^ temp[3];

        words[i] = {{ b0, b1, b2, b3 }};
    }

    return words;
}

///
/// Adding round key is simply a xor operation on
/// corresponding key for the round
/// which is generated during key expansion
///
/// Let's say we have state and a key
///
/// [ df  c3  e2  9c ]         [ ef  d4  49  11 ]
/// | 0f  ad  1f  ca |         | 1f  ad  ac  fa |
/// | 0c  9d  8d  fa |    ^    | cc  9e  15  dd |
/// [ fe  ef  cc  b2 ]         [ fe  ea  02  dc ]
///
///
/// [ df^ef   c3^d4   e2^49   9c^11 ]
/// | 0f^1f   ad^ad   1f^ac   ca^fa |
/// | 0c^cc   9d^9e   8d^15   fa^dd |
/// [ fe^fe   ef^ea   cc^02   b2^dc ]
///
void AES::addRoundKey(State* state, const KeySchedule* keySchedule, int round)
{
    for (std::size_t i = 0; i < kNb; ++i) {
        for (std::size_t j = 0; j < kNb; ++j) {
            state->at(i)[j] ^= keySchedule->at((round * kNb) + i)[j];
        }
    }
}

///
/// Simple substition for the byte
/// from sbox - i.e, for 0x04 we will replace with the
/// byte at index 0x04 => 0xf2
///
void AES::subBytes(State* state)
{
    for (std::size_t i = 0; i < kNb; ++i) {
        for (std::size_t j = 0; j < kNb; ++j) {
            state->at(i)[j] = kSBox[state->at(i)[j]];
        }
    }
}

///
/// A simple substition of bytes using kSBoxInverse
///
void AES::invSubBytes(State* state)
{
    for (std::size_t i = 0; i < kNb; ++i) {
        for (std::size_t j = 0; j < kNb; ++j) {
            state->at(i)[j] = kSBoxInverse[state->at(i)[j]];
        }
    }
}

///
/// Shifting rows is beautifully explained by diagram
/// that helped in implementation as well
///
/// Let's say we have state
///
/// [ df  c3  e2  9c ]
/// | 0f  ad  1f  ca |
/// | 0c  9d  8d  fa |
/// [ fe  ef  cc  b2 ]
///
/// shifting means
///
///              [ df  c3  e2  9c ]
///           0f | ad  1f  ca |
///       0c  9d | 8d  fa |
///   fe  ef  cc [ b2 ]
///
/// and filling the spaces with shifted rows
///
/// [ df  c3  e2  9c ]
/// | ad  1f  ca  0f |
/// | 8d  fa  0c  9d |
/// [ b2  fe  ef  cc ]
///
void AES::shiftRows(State *state)
{
    // row 1
    std::swap(state->at(0)[1], state->at(3)[1]);
    std::swap(state->at(0)[1], state->at(1)[1]);
    std::swap(state->at(1)[1], state->at(2)[1]);

    // row 2
    std::swap(state->at(0)[2], state->at(2)[2]);
    std::swap(state->at(1)[2], state->at(3)[2]);

    // row 3
    std::swap(state->at(0)[3], state->at(1)[3]);
    std::swap(state->at(2)[3], state->at(3)[3]);
    std::swap(state->at(0)[3], state->at(2)[3]);
}

///
/// This is reverse of shift rows operation
///
/// Let's say we have state
///
/// [ df  c3  e2  9c ]
/// | ad  1f  ca  0f |
/// | 8d  fa  0c  9d |
/// [ b2  fe  ef  cc ]
///
/// shifting means
///
/// [ df  c3  e2  9c  ]
///      | ad  1f  ca | 0f
///          | 8d  fa | 0c  9d
///              [ b2 | fe  ef  cc
///
/// and filling the spaces with shifted rows
///
/// [ df  c3  e2  9c ]
/// | 0f  ad  1f  ca |
/// | 0c  9d  8d  fa |
/// [ fe  ef  cc  b2 ]
///
void AES::invShiftRows(State *state)
{
    // row 1
    std::swap(state->at(0)[1], state->at(1)[1]);
    std::swap(state->at(0)[1], state->at(2)[1]);
    std::swap(state->at(0)[1], state->at(3)[1]);

    // row 2
    std::swap(state->at(0)[2], state->at(2)[2]);
    std::swap(state->at(1)[2], state->at(3)[2]);

    // row 3
    std::swap(state->at(0)[3], state->at(3)[3]);
    std::swap(state->at(0)[3], state->at(2)[3]);
    std::swap(state->at(0)[3], state->at(1)[3]);
}

///
/// Finds the product of {02} and the argument to
/// xtime modulo {1b}
///
byte AES::xtime(byte x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x11b));
}

///
/// Multiplies numbers in the GF(2^8) field
///
byte AES::multiply(byte x, byte y)
{
    return (((y & 0x01) * x) ^
            ((y >> 1 & 0x01) * xtime(x)) ^
            ((y >> 2 & 0x01) * xtime(xtime(x))) ^
            ((y >> 3 & 0x01) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 0x01) * xtime(xtime(xtime(xtime(x))))));
}

///
/// multiplies in GF(2^8) field selected column from state
/// with constant matrix defined by publication
///
/// [ 02  03  01  01 ]
/// | 01  02  03  01 |
/// | 01  01  02  03 |
/// [ 03  01  01  02 ]
///
void AES::mixColumns(State* state)
{
    for (int col = 0; col < 4; ++col) {
        Word column = state->at(col);
        // let's take example from publication, col: [212, 191, 93, 48]
        // t == 6
        byte t = column[0] ^ column[1] ^ column[2] ^ column[3];
        // see Sec. 4.2.1 and Sec. 5.1.3 for more details
        state->at(col)[0] ^= xtime(column[0] ^ column[1]) ^ t;
        state->at(col)[1] ^= xtime(column[1] ^ column[2]) ^ t;
        state->at(col)[2] ^= xtime(column[2] ^ column[3]) ^ t;
        state->at(col)[3] ^= xtime(column[3] ^ column[0]) ^ t;
    }
}

///
/// Inverse multiplication with inverse matrix defined on Sec. 5.3.3
///
/// [ 0e  0b  0d  09 ]
/// | 09  0e  0b  0d |
/// | 0d  09  0e  0b |
/// [ 0b  0d  09  0e ]
///
void AES::invMixColumns(State* state)
{
    for (int col = 0; col < 4; ++col) {
        Word column = state->at(col);
        // see Sec. 4.2.1 and Sec. 5.3.3 for more details
        state->at(col)[0] = multiply(column[0], 0x0e) ^ multiply(column[1], 0x0b) ^ multiply(column[2], 0x0d) ^ multiply(column[3], 0x09);
        state->at(col)[1] = multiply(column[0], 0x09) ^ multiply(column[1], 0x0e) ^ multiply(column[2], 0x0b) ^ multiply(column[3], 0x0d);
        state->at(col)[2] = multiply(column[0], 0x0d) ^ multiply(column[1], 0x09) ^ multiply(column[2], 0x0e) ^ multiply(column[3], 0x0b);
        state->at(col)[3] = multiply(column[0], 0x0b) ^ multiply(column[1], 0x0d) ^ multiply(column[2], 0x09) ^ multiply(column[3], 0x0e);
    }
}

void AES::initState(State* state, ByteArray input)
{
    // Pad the input if needed
    if (input.size() < kBlockSize) {
        std::fill_n(input.end(), kBlockSize - input.size(), 0);
    }

    // assign it to state for processing
    for (std::size_t i = 0; i < kNb; ++i) {
        for (std::size_t j = 0; j < kNb; ++j) {
            (*state)[i][j] = input[(kNb * i) + j];
        }
    }
}

ByteArray AES::stateToByteArray(const State *state)
{

#if MINE_PROFILING
    auto start = std::chrono::steady_clock::now();
#endif
    ByteArray result(kBlockSize);
    int k = 0;
    for (std::size_t i = 0; i < kNb; ++i) {
        for (std::size_t j = 0; j < kNb; ++j) {
            result[k++] = state->at(i)[j];
        }
    }
#if MINE_PROFILING
    auto end = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << (diff.count()) << " ms for stateToByteArray" << std::endl;
#endif

    return result;
}

ByteArray AES::generateRandomBytes(const std::size_t len)
{
    ByteArray result(len, 'x');
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> uni(0, kRandomBytesCount - 1);
    std::generate(result.begin(), result.end(), [&] {
        return kRandomBytesList[uni(rng)];
    });
    return result;
}

ByteArray* AES::xorWith(ByteArray* input, const ByteArray* arr)
{
    for (std::size_t i = 0; i < kBlockSize; ++i) {
        input->at(i) ^= arr->at(i);
    }
    return input;
}

ByteArray* AES::xorWithIter(ByteArray* input, const ByteArray::const_iterator& beg, const ByteArray::const_iterator& end)
{
    int i = 0;
    for (auto iter = beg; iter < end; ++iter, ++i) {
        input->at(i) ^= *iter;
    }
    return input;
}

ByteArray AES::rawCipher(const ByteArray& input, const Key* key, const KeySchedule* keySchedule)
{

    if (key == nullptr || keySchedule == nullptr) {
        throw std::invalid_argument("AES raw encryption requires key");
    }

    State state;
    initState(&state, input);

    uint8_t kTotalRounds = kKeyParams.at(key->size())[1];

    int round = 0;

#if MINE_PROFILING
    auto start = std::chrono::steady_clock::now();
#endif

    // initial round
    addRoundKey(&state, keySchedule, round++);

    // intermediate round
    while (round < kTotalRounds) {
        subBytes(&state);
        shiftRows(&state);
        mixColumns(&state);
        addRoundKey(&state, keySchedule, round++);
    }

    // final round
    subBytes(&state);
    shiftRows(&state);
    addRoundKey(&state, keySchedule, round++);

#if MINE_PROFILING
    auto end = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << (diff.count()) << " ms for encryption" << std::endl;
#endif

    return stateToByteArray(&state);

}

ByteArray AES::rawDecipher(const ByteArray& input, const Key* key, const KeySchedule* keySchedule)
{

    if (key == nullptr || keySchedule == nullptr) {
        throw std::invalid_argument("AES raw decryption requires key");
    }

    State state;
    initState(&state, input);

    uint8_t kTotalRounds = kKeyParams.at(key->size())[1];

    int round = kTotalRounds;

    // initial round
    addRoundKey(&state, keySchedule, round--);

    // intermediate round
    while (round > 0) {
        invShiftRows(&state);
        invSubBytes(&state);
        addRoundKey(&state, keySchedule, round--);
        invMixColumns(&state);
    }

    // final round
    invShiftRows(&state);
    invSubBytes(&state);
    addRoundKey(&state, keySchedule, round);

    return stateToByteArray(&state);
}

ByteArray AES::resolveInputMode(const std::string& input, Encoding inputMode)
{
    if (inputMode == Encoding::Raw) {
        return Base16::fromString(Base16::encode(input));
    } else if (inputMode == Encoding::Base16) {
        return Base16::fromString(input);
    }
    // base64
    return Base16::fromString(Base16::encode(Base64::decode(input)));
}

std::string AES::resolveOutputMode(const ByteArray& input, Encoding outputMode)
{
    if (outputMode == Encoding::Raw) {
        return Base16::toRawString(input);
    } else if (outputMode == Encoding::Base16) {
        return Base16::encode(input.begin(), input.end());
    }
    // base64
    return Base64::encode(input.begin(), input.end());
}

// public

ByteArray AES::cipher(const ByteArray& input, const Key* key)
{

    std::size_t keySize = key->size();

    // key size validation
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw std::invalid_argument("Invalid AES key size");
    }

    const std::size_t inputSize = input.size();

    KeySchedule keySchedule = keyExpansion(key);

    ByteArray result;

    for (std::size_t i = 0; i < inputSize; i += kBlockSize) {
        ByteArray inputBlock(kBlockSize, 0);

        // don't use copy_n as we are setting the values
        for (std::size_t j = 0; j < kBlockSize && inputSize > j + i; ++j) {
            inputBlock.at(j) = input.at(j + i);
        }

        ByteArray outputBlock = rawCipher(inputBlock, key, &keySchedule);
        std::copy(outputBlock.begin(), outputBlock.end(), std::back_inserter(result));
    }
    return result;
}

ByteArray AES::decipher(const ByteArray& input, const Key* key)
{

    std::size_t keySize = key->size();

    // key size validation
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw std::invalid_argument("Invalid AES key size");
    }

    KeySchedule keySchedule = keyExpansion(key);

    const std::size_t inputSize = input.size();
    ByteArray result;

    for (std::size_t i = 0; i < inputSize; i += kBlockSize) {
        ByteArray inputBlock(kBlockSize, 0);

        std::size_t j = 0;
        // don't use copy_n here as we are setting the values
        for (; j < kBlockSize && inputSize > j + i; ++j) {
            inputBlock.at(j) = input.at(j + i);
        }

        ByteArray outputBlock = rawDecipher(inputBlock, key, &keySchedule);

        std::copy_n(outputBlock.begin(), j, std::back_inserter(result));
    }
    return result;
}

ByteArray AES::cipher(const ByteArray& input, const Key* key, ByteArray& iv)
{

    std::size_t keySize = key->size();

    // key size validation
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw std::invalid_argument("Invalid AES key size");
    }

    if (!iv.empty() && iv.size() != 16) {
        throw std::invalid_argument("Invalid IV, it should be 128-bit");
    } else if (iv.empty()) {
        // generate IV
        iv = generateRandomBytes(16);
    }

    KeySchedule keySchedule = keyExpansion(key);
    const std::size_t inputSize = input.size();

    ByteArray result;
    ByteArray::const_iterator nextXorWithBeg = iv.begin();
    ByteArray::const_iterator nextXorWithEnd = iv.end();

#if MINE_PROFILING
    auto start = std::chrono::steady_clock::now();
#endif
    for (std::size_t i = 0; i < inputSize; i += kBlockSize) {
        ByteArray inputBlock(kBlockSize, 0);

        // don't use copy_n as we are setting the values
        for (std::size_t j = 0; j < kBlockSize && inputSize > j + i; ++j) {
            inputBlock.at(j) = input.at(j + i);
        }

        xorWithIter(&inputBlock, nextXorWithBeg, nextXorWithEnd);

        ByteArray outputBlock = rawCipher(inputBlock, key, &keySchedule);
        std::copy(outputBlock.begin(), outputBlock.end(), std::back_inserter(result));
        nextXorWithBeg = result.end() - kBlockSize;
        nextXorWithEnd = result.end();
    }

#if MINE_PROFILING
    auto end = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << (diff.count()) << " ms for block encryption" << std::endl;
#endif
    return result;
}

ByteArray AES::decipher(const ByteArray& input, const Key* key, ByteArray& iv)
{

    std::size_t keySize = key->size();

    // key size validation
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw std::invalid_argument("Invalid AES key size");
    }

    KeySchedule keySchedule = keyExpansion(key);
    const std::size_t inputSize = input.size();
    ByteArray result;

    ByteArray nextXorWith = iv;


    for (std::size_t i = 0; i < inputSize; i += kBlockSize) {
        ByteArray inputBlock(kBlockSize, 0);

        std::size_t j = 0;
        // don't use copy_n as we are setting the values
        for (; j < kBlockSize && inputSize > j + i; ++j) {
            inputBlock.at(j) = input.at(j + i);
        }

        ByteArray outputBlock = rawDecipher(inputBlock, key, &keySchedule);

        xorWith(&outputBlock, &nextXorWith);

        nextXorWith = inputBlock;

        std::copy_n(outputBlock.begin(), j, std::back_inserter(result));
    }
    return result;
}

static std::string normalizeBase16(std::string enc)
{
    enc.erase(std::remove_if(enc.begin(), enc.end(), iswspace), enc.end());
    return enc;
}

std::string AES::cipher(const std::string& input, const std::string& key, Encoding inputEncoding, Encoding outputEncoding)
{
    Key keyArr = Base16::fromString(normalizeBase16(key));
    ByteArray inp = resolveInputMode(input, inputEncoding);
    ByteArray result = cipher(inp, &keyArr);
    return resolveOutputMode(result, outputEncoding);
}

std::string AES::cipher(const std::string& input, const std::string& key, std::string& iv, Encoding inputEncoding, Encoding outputEncoding)
{
    Key keyArr = Base16::fromString(normalizeBase16(key));
    ByteArray inp = resolveInputMode(input, inputEncoding);
    ByteArray ivec = Base16::fromString(normalizeBase16(iv));
    bool ivecGenerated = iv.empty();
    ByteArray result = cipher(inp, &keyArr, ivec);
    if (ivecGenerated) {
        iv = Base16::encode(ivec.begin(), ivec.end());
    }
    return resolveOutputMode(result, outputEncoding);
}

std::string AES::decipher(const std::string& input, const std::string& key, Encoding inputEncoding, Encoding outputEncoding)
{
    Key keyArr = Base16::fromString(normalizeBase16(key));
    ByteArray inp = resolveInputMode(input, inputEncoding);
    ByteArray result = decipher(inp, &keyArr);
    return resolveOutputMode(result, outputEncoding);
}

std::string AES::decipher(const std::string& input, const std::string& key, const std::string& iv, Encoding inputEncoding, Encoding outputEncoding)
{
    Key keyArr = Base16::fromString(normalizeBase16(key));
    ByteArray inp = resolveInputMode(input, inputEncoding);
    ByteArray ivec = Base16::fromString(iv);
    ByteArray result = decipher(inp, &keyArr, ivec);
    return resolveOutputMode(result, outputEncoding);
}

std::string AES::generateRandomKey(const std::size_t len)
{
    if (len != 128 && len != 192 && len != 256) {
        throw std::invalid_argument("Please choose valid key length of 128, 192 or 256 bits");
    }
    ByteArray bytes = generateRandomBytes(len / 8);
    return Base16::encode(bytes.begin(), bytes.end());
}


