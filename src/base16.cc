//
//  base16.cc
//  Part of Mine crypto library
//
//  You should not use this file, use mine.cc
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright (c) 2017-2018 Muflihun Labs
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

const std::unordered_map<byte, byte> Base16::kDecodeMap = {
    {0x30, 0x00}, {0x31, 0x01}, {0x32, 0x02}, {0x33, 0x03},
    {0x34, 0x04}, {0x35, 0x05}, {0x36, 0x06}, {0x37, 0x07},
    {0x38, 0x08}, {0x39, 0x09}, {0x41, 0x0A}, {0x42, 0x0B},
    {0x43, 0x0C}, {0x44, 0x0D}, {0x45, 0x0E}, {0x46, 0x0F},
    // lower case
    {0x61, 0x0A}, {0x62, 0x0B}, {0x63, 0x0C}, {0x64, 0x0D},
    {0x65, 0x0E}, {0x66, 0x0F}
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

void Base16::decode(char a, char b, std::ostringstream& ss)
{
    try {
        ss << static_cast<byte>((kDecodeMap.at(a & 0xff) << 4) | kDecodeMap.at(b & 0xff));
    } catch (const std::exception& e) {
        throw std::invalid_argument("Invalid base-16 encoding: " + std::string(e.what()));
    }
}
