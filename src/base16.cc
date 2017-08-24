//
//  base16.cc
//  Part of Mine crypto library
//
//  You should not use this file, use include/mine.cc
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
    std::string s;
    std::stringstream ss;
    for (auto it = enc.begin(); it != enc.end(); it += 2) {
        int b0 = *it & 0xff;
        int b1 = *(it + 1) & 0xff;
        // fixme: need to fix this!
        ss << static_cast<byte>(((b0 & 0xf) << 4) | (b1 & 0xf));
        s = ss.str();
    }
    return ss.str();
}
