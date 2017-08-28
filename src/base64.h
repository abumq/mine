//
//  base64.h
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

#ifndef Base64_H
#define Base64_H

#include <string>
#include <unordered_map>

// codecvt is not part of standard
// hence we leave it to user to enable/disable
// it depending on their
#ifdef MINE_BASE64_WSTRING_CONVERSION
#   include <locale>
#   include <codecvt>
#endif

namespace mine {

using byte = unsigned char;

///
/// \brief Provides base64 encoding / decoding implementation
///
/// This class also provides public interface to encode
/// the iterators for other containers like vector etc.
///
/// This also handles unicode characters
///
class Base64 {
public:

    ///
    /// \brief List of valid base64 encoding characters
    ///
    static const std::string kValidChars;

    ///
    /// \brief Map for fast lookup corresponding character
    /// std::unordered_map is O(1) for best case and linear in worst case
    /// which is better than kValidChars find_first_of() which is linear-pos
    /// in general
    /// \ref http://www.cplusplus.com/reference/unordered_map/unordered_map/at/
    /// \ref  http://www.cplusplus.com/reference/string/string/find_first_of/
    ///
    static const std::unordered_map<byte, byte> kDecodeMap;

    ///
    /// \brief Padding is must in mine implementation of base64
    ///
    static const char kPaddingChar = '=';

    ///
    /// \brief Replacement for better d.size() that consider unicode bytes too
    /// \see https://en.wikipedia.org/wiki/UTF-8#Description
    ///
    static std::size_t countChars(const std::string& d) noexcept;

#ifdef MINE_BASE64_WSTRING_CONVERSION
    ///
    /// \brief Converts it to std::string and calls countChars on it
    ///
    /// \note You need to include <locale> and <codecvt> headers before mine.h
    ///
    static std::size_t countChars(const std::wstring& raw) noexcept
    {
        std::string converted = std::wstring_convert
                <std::codecvt_utf8<wchar_t>, wchar_t>{}.to_bytes(raw);
        return countChars(converted);
    }
#endif

    ///
    /// \brief Encodes input of length to base64 encoding
    ///
    static std::string encode(const std::string& raw) noexcept
    {
        return encode(raw.begin(), raw.end());
    }

    ///
    /// \brief Encodes iterators
    ///
    template <class Iter>
    static std::string encode(const Iter& begin, const Iter& end) noexcept
    {
        std::string padding;
        std::stringstream ss;
        for (auto it = begin; it < end; it += 3) {

            //
            // we use example following example for implementation basis
            // Bits              01100001   01100010  01100011
            // 24-bit stream:    011000   010110   001001   100011
            // result indices     24        22       9        35
            //

            int c = static_cast<int>(*it & 0xff);
            ss << static_cast<char>(static_cast<char>(kValidChars[(c >> 2) & 0x3f])); // first 6 bits from first bitset
            if (it + 1 < end) {
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
                if (it + 2 < end) {
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

#ifdef MINE_BASE64_WSTRING_CONVERSION
    ///
    /// \brief Converts wstring to corresponding string and returns
    /// encoding
    /// \see encode(const std::string&)
    ///
    /// \note You need to include <locale> and <codecvt> headers before mine.h
    ///
    static std::string encode(const std::wstring& raw) noexcept
    {
        std::string converted = std::wstring_convert
                <std::codecvt_utf8<wchar_t>, wchar_t>{}.to_bytes(raw);
        return encode(converted);
    }
#endif

    ///
    /// \brief Decodes encoded base64
    /// \see decode(const Iter&, const Iter&)
    ///
    static std::string decode(const std::string& e)
    {
        if (e.size() % 4 != 0) {
            throw std::invalid_argument("Invalid base64 encoding. Padding is required");
        }
        return decode(e.begin(), e.end());
    }

    ///
    /// \brief Decodes base64 iterator from begin to end
    /// \throws std::invalid_argument if invalid encoding. Another time it is thrown
    /// is if no padding is found
    /// std::invalid_argument::what() is set according to the error
    ///
    template <class Iter>
    static std::string decode(const Iter& begin, const Iter& end)
    {
        //
        // we use example following example for implementation basis
        // Bits              01100001   01100010  01100011
        // 24-bit stream:    011000   010110   001001   100011
        // result indices     24        22       9        35
        //

        const int kPadding = kDecodeMap.at(static_cast<int>(kPaddingChar));
        std::stringstream ss;
        for (auto it = begin; it < end; it += 4) {
            try {
                int b0 = kDecodeMap.at(static_cast<int>(*it & 0xff));
                if (b0 == kPadding || b0 == '\0') {
                    throw std::invalid_argument("Invalid base64 encoding. No data available");
                }
                int b1 = kDecodeMap.at(static_cast<int>(*(it + 1) & 0xff));
                int b2 = kDecodeMap.at(static_cast<int>(*(it + 2) & 0xff));
                int b3 = kDecodeMap.at(static_cast<int>(*(it + 3) & 0xff));

                ss << static_cast<byte>(b0 << 2 |     // 011000 << 2 ==> 01100000
                                        b1 >> 4); // 000001 >> 4 ==> 01100001 ==> 11000001 = 97

                if (b1 != kPadding && b1 != '\0') {
                    if (b2 == kPadding || (b2 == '\0' && b3 == '\0')) {
                        // second bitset is only 4 bits

                        // note: this line was causing issue when we had plain text length 16
                        // b64 = uS2qrm5XdzsQZTcDrxJxbw==
                        // it was adding a nul term char
                        ss << static_cast<byte>((b1 & ~(1 << 5) & ~(1 << 4)) << 4);
                    } else {
                        ss << static_cast<byte>((b1 & ~(1 << 5) & ~(1 << 4)) << 4 |     // 010110 ==> 000110 << 4 ==> 1100000
                                                                                        // first we clear the bits at pos 4 and 5
                                                                                        // then we concat with next bit
                                                 b2 >> 2); // 001001 >> 2 ==> 00000010 ==> 01100010 = 98
                        if (b3 == kPadding || b3 == '\0') {
                            // third bitset is only 4 bits
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
                throw std::invalid_argument("Invalid base64 character");
            }
        }
        return ss.str();
    }

#ifdef MINE_BASE64_WSTRING_CONVERSION
    ///
    /// \brief Helper method to decode base64 encoding as wstring (basic_string<wchar_t>)
    /// \see decode(const std::string&)
    /// \note We do not recommend using it, instead have your own conversion function from
    /// std::string to wstring as it can give you invalid results with characters that are
    /// 5+ bytes long e.g, \x1F680. If you don't use such characters then it should be safe
    /// to use this
    ///
    /// \note You need to include <locale> and <codecvt> headers before mine.h
    ///
    static std::wstring decodeAsWString(const std::string& e)
    {
        std::string result = decode(e);
        std::wstring converted = std::wstring_convert
                <std::codecvt_utf8_utf16<wchar_t>>{}.from_bytes(result);
        return converted;
    }
#endif

    ///
    /// \brief expectedBase64Length Returns expected base64 length
    /// \param n Length of input (plain data)
    ///
    inline static std::size_t expectedLength(std::size_t n) noexcept
    {
        return ((4 * n / 3) + 3) & ~0x03;
    }

    ///
    /// \brief Calculates the length of string
    /// \see countChars()
    ///
    template <typename T = std::string>
    inline static std::size_t expectedLength(const T& str) noexcept
    {
        return expectedLength(countChars(str));
    }

    ///
    /// \brief Finds whether data is base64 encoded. This is done
    /// by finding non-base64 character. So it is not necessary
    /// a valid base64 encoding.
    ///
    inline static bool isBase64(const std::string& data) noexcept
    {
        return data.find_first_not_of(kValidChars) == std::string::npos;
    }

private:
    Base64() = delete;
    Base64(const Base64&) = delete;
    Base64& operator=(const Base64&) = delete;
};
} // end namespace mine


#endif // Base64_H
