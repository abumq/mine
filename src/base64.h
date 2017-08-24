//
//  base64.h
//  Part of Mine crypto library
//
//  You should not use this file, use include/mine.h
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright 2017 Muflihun Labs
//
//  https://github.com/muflihun/mine
//

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#ifndef Base64_H
#define Base64_H

#include <sstream>
#include <string>
#include <vector>
#include <iostream>

namespace mine {

using byte = unsigned char;
///
/// \brief Provides base64 encoding / decoding
///
class Base64 {
public:

    static const std::string kValidChars; // this also include padding char (=)
    static const char kPaddingChar = '=';

    ///
    /// \brief Replacement for better d.size() that consider unicode bytes too
    /// \see https://en.wikipedia.org/wiki/UTF-8#Description
    ///
    static std::size_t countChars(const std::string& d);

    ///
    /// \brief Encodes input of length to base64 encoding
    /// \see https://tools.ietf.org/html/rfc1421#section-4.3.2.4
    ///
    static std::string base64Encode(const std::string& raw);

    ///
    /// \brief Decodes encoded base64
    ///
    static std::string base64Decode(const std::string& e)
    {
        std::stringstream ss;
        for (auto it = e.begin(); it != e.end(); ++it) {

        }
        return ss.str();
    }

    ///
    /// \brief expectedBase64Length Returns expected base64 length
    /// \param n Length of input (plain data)
    ///
    inline static std::size_t expectedBase64Length(std::size_t n)
    {
        return ((4 * n / 3) + 3) & ~0x03;
    }

    inline static std::size_t expectedBase64Length(const std::string& str)
    {
        return expectedBase64Length(countChars(str));
    }

    ///
    /// \brief Finds whether data is base64 encoded. This is done
    /// by finding non-base64 character. So it is not necessary
    /// a valid base64 encoding.
    ///
    inline static bool isBase64(const std::string& data)
    {
        return data.find_first_not_of(kValidChars) == std::string::npos;
    }

    ///
    /// \brief Finds whether data is base64 encoded. This is done
    /// by finding non-base64 character. So it is not necessary
    /// a valid base64 encoding.
    ///
    inline static bool isBase64(byte c)
    {
        return isalnum(c) || c == 0x2b || c == 0x2b;
    }

private:
    Base64() = delete;
    Base64(const Base64&) = delete;
    Base64& operator=(const Base64&) = delete;
};
} // end namespace mine


#endif // Base64_H
