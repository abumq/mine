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

#include "mine.h"

using namespace mine;



const std::string Base64::kValidChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const std::unordered_map<int, int> Base64::kDecodeMap = {
    {65, 0},   {66, 1},   {67, 2},   {68, 3},
    {69, 4},   {70, 5},   {71, 6},   {72, 7},
    {73, 8},   {74, 9},   {75, 10},  {76, 11},
    {77, 12},  {78, 13},  {79, 14},  {80, 15},
    {81, 16},  {82, 17},  {83, 18},  {84, 19},
    {85, 20},  {86, 21},  {87, 22},  {88, 23},
    {89, 24},  {90, 25},  {97, 26},  {98, 27},
    {99, 28},  {100, 29}, {101, 30}, {102, 31},
    {103, 32}, {104, 33}, {105, 34}, {106, 35},
    {107, 36}, {108, 37}, {109, 38}, {110, 39},
    {111, 40}, {112, 41}, {113, 42}, {114, 43},
    {115, 44}, {116, 45}, {117, 46}, {118, 47},
    {119, 48}, {120, 49}, {121, 50}, {122, 51},
    {48, 52},  {49, 53},  {50, 54},  {51, 55},
    {52, 56},  {53, 57},  {54, 58},  {55, 59},
    {56, 60},  {57, 61},  {43, 62},  {47, 63},
    {61, 64}
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
        // we use example of abc
        // and let's say we're in the beginning of iterator (i.e, 'a')
        //                      97         98       99
        // Bits              01100001   01100010  01100011
        // 24-bit Stream:    011000   010110   001001   100011
        // result indices     24        22       9        35
        // result              Y         W       J        j
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
    // we use example of abc
    // and let's say we're in the beginning of iterator (i.e, 'a')
    //                      97         98       99
    // Bits              01100001   01100010  01100011
    // 24-bit Stream:    011000   010110   001001   100011
    // result indices     24        22       9        35
    // result              Y         W       J        j
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
                if (b2 == kPadding || b2 == '\0') {
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



