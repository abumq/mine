//
//  base64.cc
//  Part of Mine crypto library
//
//  You should not use this file, use include/mine.cc
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright 2017 Muflihun Labs
//
//  https://github.com/muflihun/mine
//

#include "src/base64.h"

using namespace mine;

const std::string Base64::kValidChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

std::size_t Base64::countChars(const std::string& str)
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

std::string Base64::base64Encode(const std::string& raw)
{
    std::string padding;
    std::stringstream ss;
    for (auto it = raw.begin(); it < raw.end(); it += 3) {

        // we use example of abc
        // and let's say we're in the beginning of iterator (i.e, 'a')
        //                      97         98       99
        // Bits              01100001   01100010  01100011
        // Stream            011000010110001001100011           =>  decimal: 6382179
        // 24-bit Stream:    011000   010110   001001   100011
        // result indices     24        22       9        35
        // result              Y         W       J        j
        //
        // ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
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
                ss << "=";
            }
        } else {
            ss << static_cast<char>(kValidChars[(c << 4) & 0x3f]); // remaining 2 bits from single byte
            ss << "==";
        }
    }
    return ss.str() + padding;
}
