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

#include <algorithm>
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
    static const std::unordered_map<byte, byte> kDecodeMap;

    ///
    /// \brief Encodes input to hex encoding
    ///
    static inline std::string encode(const std::string& raw) noexcept
    {
        return encode(raw.begin(), raw.end());
    }

    ///
    /// \brief Encodes input iterator to hex encoding
    ///
    template <class Iter>
    static std::string encode(const Iter& begin, const Iter& end) noexcept
    {
        std::ostringstream ss;
        for (auto it = begin; it < end; ++it) {
            encode(*it, ss);
        }
        return ss.str();
    }

    ///
    /// \brief Encodes single byte
    ///
    static inline void encode(char b, std::ostringstream& ss) noexcept
    {
        int h = (b & 0xff);
        ss << kValidChars[(h >> 4) & 0xf] << kValidChars[(h & 0xf)];
    }

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
    /// std::runtime::what() is set accordingly
    ///
    static std::string decode(const std::string& enc)
    {
        if (enc.size() % 2 != 0) {
            throw std::runtime_error("Invalid base-16 encoding");
        }
        return decode(enc.begin(), enc.end());
    }

    ///
    /// \brief Encodes input iterator to hex encoding
    /// \note User should check for the valid size or use decode(std::string)
    /// \throws runtime_error if invalid base16-encoding
    ///
    template <class Iter>
    static std::string decode(const Iter& begin, const Iter& end)
    {
        std::ostringstream ss;
        for (auto it = begin; it != end; it += 2) {
            decode(*it, *(it + 1), ss);
        }
        return ss.str();
    }

    ///
    /// \brief Decodes single byte pair
    ///
    static void decode(char a, char b, std::ostringstream& ss);

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
