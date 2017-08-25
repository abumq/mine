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
#include <locale>
#include <codecvt>

namespace mine {

using byte = unsigned char;

///
/// \brief Provides base64 encoding / decoding implementation
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
    static const std::unordered_map<int, int> kDecodeMap;

    ///
    /// \brief Padding is must in mine implementation of base64
    ///
    static const char kPaddingChar = '=';

    ///
    /// \brief Replacement for better d.size() that consider unicode bytes too
    /// \see https://en.wikipedia.org/wiki/UTF-8#Description
    ///
    static std::size_t countChars(const std::string& d) noexcept;

    ///
    /// \brief Converts it to std::string and calls countChars on it
    ///
    static std::size_t countChars(const std::wstring& raw) noexcept
    {
        std::string converted = std::wstring_convert
                <std::codecvt_utf8<wchar_t>, wchar_t>{}.to_bytes(raw);
        return countChars(converted);
    }

    ///
    /// \brief Encodes input of length to base64 encoding
    ///
    static std::string encode(const std::string& raw) noexcept;

    ///
    /// \brief Converts wstring to corresponding string and returns
    /// encoding
    /// \see encode(const std::string&)
    ///
    static std::string encode(const std::wstring& raw) noexcept
    {
        std::string converted = std::wstring_convert
                <std::codecvt_utf8<wchar_t>, wchar_t>{}.to_bytes(raw);
        return encode(converted);
    }

    ///
    /// \brief Decodes encoded base64
    /// \throws std::runtime if invalid encoding. Another time it is thrown
    /// is if no padding is found
    /// std::runtime::what() is set according to the error
    ///
    static std::string decode(const std::string& e);

    ///
    /// \brief Helper method to decode base64 encoding as wstring (basic_string<wchar_t>)
    /// \see decode(const std::string&)
    /// \note We do not recommend using it, instead have your own conversion function from
    /// std::string to wstring as it can give you invalid results with characters that are
    /// 5+ bytes long e.g, \x1F680. If you don't use such characters then it should be safe
    /// to use this
    ///
    static std::wstring decodeAsWString(const std::string& e)
    {
        std::string result = decode(e);
        std::wstring converted = std::wstring_convert
                <std::codecvt_utf8_utf16<wchar_t>>{}.from_bytes(result);
        return converted;
    }

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
