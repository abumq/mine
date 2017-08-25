#ifndef BASE16_TEST_H
#define BASE16_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "package/mine.h"
#else
#   include "src/base16.h"
#endif

namespace mine {

static TestData<std::string, std::string> Base16TestData = {
    TestCase("68656C6F", "helo"),
    TestCase("48656C6C6F20576F726C6421", "Hello World!"),
    TestCase("616263313233213F242A262829272D3D407E", "abc123!?$*&()'-=@~"),
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
