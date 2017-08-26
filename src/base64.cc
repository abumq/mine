//
//  base64.cc
//  Part of Mine crypto library
//
//  You should not use this file, use mine.cc
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

#include <sstream>
#include <stdexcept>
#include "src/base64.h"

using namespace mine;

const std::string Base64::kValidChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

const std::unordered_map<uint8_t, uint8_t> Base64::kDecodeMap = {
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

std::string Base64::encode(const std::string& raw) noexcept
{
    std::string padding;
    std::stringstream ss;
    for (auto it = raw.begin(); it < raw.end(); it += 3) {

        //
        // we use example following example for implementation basis
        // Bits              01100001   01100010  01100011
        // 24-bit stream:    011000   010110   001001   100011
        // result indices     24        22       9        35
        //

        int c = static_cast<int>(*it & 0xff);
        ss << static_cast<char>(static_cast<char>(kValidChars[(c >> 2) & 0x3f])); // first 6 bits from first bitset
        if (it + 1 < raw.end()) {
            int c2 = static_cast<int>(*(it + 1) & 0xff);
            ss << static_cast<char>(kValidChars[((c << 4) | // remaining 2 bits from first bitset - shift them left to get 4-bit spaces 010000
                                                 (c2 >> 4) // first 4 bits of second bitset - shift them right to get 2 spaces and bitwise
                                                                  // to add them 000110
                                                 ) & 0x3f]);      // must be within 63 --
                                                                  // 010000
                                                                  // 000110
                                                                  // --|---
                                                                  // 010110
                                                                  // 111111
                                                                  // ---&--
                                                                  // 010110 ==> 22
            if (it + 2 < raw.end()) {
                int c3 = static_cast<int>(*(it + 2) & 0xff);
                ss << static_cast<char>(kValidChars[((c2 << 2) | // remaining 4 bits from second bitset - shift them to get 011000
                                                     (c3 >> 6)   // the first 2 bits from third bitset - shift them right to get 000001
                                                     ) & 0x3f]);
                                                                         // the rest of the explanation is same as above
                ss << static_cast<char>(kValidChars[c3 & 0x3f]); // all the remaing bits
            } else {
                ss << static_cast<char>(kValidChars[(c2 << 2) & 0x3f]); // we have 4 bits left from last byte need space for two 0-bits
                ss << kPaddingChar;
            }
        } else {
            ss << static_cast<char>(kValidChars[(c << 4) & 0x3f]); // remaining 2 bits from single byte
            ss << kPaddingChar << kPaddingChar;
        }
    }
    return ss.str() + padding;
}

std::string Base64::decode(const std::string& enc)
{
    //
    // we use example following example for implementation basis
    // Bits              01100001   01100010  01100011
    // 24-bit stream:    011000   010110   001001   100011
    // result indices     24        22       9        35
    //

    if (enc.size() % 4 != 0) {
        throw std::runtime_error("Invalid base64 encoding. Padding is required");
    }
    const int kPadding = kDecodeMap.at(static_cast<int>(kPaddingChar));
    std::stringstream ss;
    for (auto it = enc.begin(); it != enc.end(); it += 4) {
        try {
            int b0 = kDecodeMap.at(static_cast<int>(*it & 0xff));
            if (b0 == kPadding || b0 == '\0') {
                throw std::runtime_error("Invalid base64 encoding. No data available");
            }
            int b1 = kDecodeMap.at(static_cast<int>(*(it + 1) & 0xff));
            int b2 = kDecodeMap.at(static_cast<int>(*(it + 2) & 0xff));
            int b3 = kDecodeMap.at(static_cast<int>(*(it + 3) & 0xff));

            ss << static_cast<byte>(b0 << 2 |     // 011000 << 2 ==> 01100000
                                    b1 >> 4); // 000001 >> 4 ==> 01100001 ==> 11000001 = 97

            if (b1 != kPadding && b1 != '\0') {
                if (b2 == kPadding || (b2 == '\0' && b3 == '\0')) {
                    // second biteset is 'partial byte'
                    ss << static_cast<byte>((b1 & ~(1 << 5) & ~(1 << 4)) << 4);
                } else {
                    ss << static_cast<byte>((b1 & ~(1 << 5) & ~(1 << 4)) << 4 |     // 010110 ==> 000110 << 4 ==> 1100000
                                                                                    // first we clear the bits at pos 4 and 5
                                                                                    // then we concat with next bit
                                             b2 >> 2); // 001001 >> 2 ==> 00000010 ==> 01100010 = 98
                    if (b3 == kPadding || b3 == '\0') {
                        // third bitset is 'partial byte'
                        ss << static_cast<byte>((b2 & ~(1 << 5) & ~(1 << 4) & ~(1 << 3) & ~(1 << 2)) << 6);
                                                // first we clear first 4 bits
                    } else {
                        ss << static_cast<byte>((b2 & ~(1 << 5) & ~(1 << 4) & ~(1 << 3) & ~(1 << 2)) << 6 |     // 001001 ==> 000001 << 6 ==> 01000000
                                                // first we clear first 4 bits
                                                // then concat with last byte as is
                                                 b3); // as is
                    }
                }
            }
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid base64 character");
        }
    }
    return ss.str();
}
