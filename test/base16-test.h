#ifndef BASE16_TEST_H
#define BASE16_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "include/mine.h"
#else
#   include "src/base16.h"
#endif

namespace mine {

static TestData<std::string, std::string> Base16TestData = {
    TestCase("48656C6C6F20576F726C64", "Hello World"),
    TestCase("717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F6720515549434B2042524F574E20464F58204A554D5053204F56455220544845204C415A5920444F472031323334353637383930", "quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG 1234567890"),
};

static TestData<std::string> InvalidBase16EncodingData = {
    TestCase("48656C6C6F20576F726C64F"),
};

TEST(Base16Test, Encode)
{
    for (const auto& item : Base16TestData) {
        std::string encoded = Base16::encode(PARAM(1));
        ASSERT_STREQ(PARAM(0).c_str(), encoded.c_str());
    }
}

TEST(Base16Test, Decode)
{
    for (const auto& item : Base16TestData) {
        std::string decoded = Base16::decode(PARAM(0));
        ASSERT_STREQ(PARAM(1).c_str(), decoded.c_str());
    }
}

TEST(Base16Test, InvalidBase16Encoding)
{
    for (const auto& item : InvalidBase16EncodingData) {
        EXPECT_THROW(Base16::decode(PARAM(0)), std::runtime_error);
    }
}
}

#endif // BASE16_TEST_H
