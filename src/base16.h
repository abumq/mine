//
//  base16.h
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

#ifndef Base16_H
#define Base16_H

#include <string>
#include <sstream>
#include <unordered_map>

namespace mine {

using byte = unsigned char;

///
/// \brief Provides base16 encoding / decoding
///
class Base16 {
public:

    ///
    /// \brief List of valid hex encoding characters
    ///
    static const std::string kValidChars;

    ///
    /// \brief Map for fast lookup corresponding character
    /// \see Base64::kDecodeMap
    ///
    static const std::unordered_map<int, int> kDecodeMap;

    ///
    /// \brief Encodes input of length to hex encoding
    ///
    static std::string encode(const std::string& raw) noexcept;

    ///
    /// \brief Encodes integer to hex
    ///
    template <typename T>
    static std::string encode(T n) noexcept
    {
        std::stringstream ss;
        int remainder;
        while (n != 0) {
            remainder = n % 16;
            n /= 16;
            ss << kValidChars[remainder];
        }
        std::string res(ss.str());
        std::reverse(res.begin(), res.end());
        return res;
    }

    ///
    /// \brief Decodes encoded hex
    /// \throws std::runtime if invalid encoding.
    /// std::runtime::what() is set according to the error
    ///
    static std::string decode(const std::string& e);

    ///
    /// \brief Decodes encoding to single integer of type T
    ///
    template <typename T>
    static T decodeInt(const std::string& e)
    {
        T result = 0;
        for (auto it = e.begin(); it != e.end() && result >= 0; ++it) {
            try {
                result = ((result << 4) | kDecodeMap.at(*it & 0xff));
            } catch (const std::exception&) {
                throw std::runtime_error("Invalid base-16 encoding");
            }
        }
        return result;
    }

private:
    Base16() = delete;
    Base16(const Base16&) = delete;
    Base16& operator=(const Base16&) = delete;
};
} // end namespace mine

#endif // Base16_H
