//
//  base16.cc
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
#include "src/base16.h"

using namespace mine;

const std::string Base16::kValidChars = "0123456789ABCDEF";

const std::unordered_map<uint8_t, uint8_t> Base16::kDecodeMap = {
    {0x30, 0x00}, {0x31, 0x01}, {0x32, 0x02}, {0x33, 0x03},
    {0x34, 0x04}, {0x35, 0x05}, {0x36, 0x06}, {0x37, 0x07},
    {0x38, 0x08}, {0x39, 0x09}, {0x41, 0x0A}, {0x42, 0x0B},
    {0x43, 0x0C}, {0x44, 0x0D}, {0x45, 0x0E}, {0x46, 0x0F}
};

std::string Base16::encode(const std::string& raw) noexcept
{
    std::stringstream ss;
    for (auto it = raw.begin(); it < raw.end(); ++it) {
        int h = (*it & 0xff);
        ss << kValidChars[(h >> 4) & 0xf] << kValidChars[(h & 0xf)];
    }
    return ss.str();
}

std::string Base16::decode(const std::string& enc)
{
    if (enc.size() % 2 != 0) {
        throw std::runtime_error("Invalid base-16 encoding");
    }
    std::stringstream ss;
    for (auto it = enc.begin(); it != enc.end(); it += 2) {
        int b0 = *it & 0xff;
        int b1 = *(it + 1) & 0xff;
        try {
            ss << static_cast<byte>((b0 << 4) | kDecodeMap.at(b1));
        } catch (const std::exception&) {
            throw std::runtime_error("Invalid base-16 encoding");
        }
    }
    return ss.str();
}
