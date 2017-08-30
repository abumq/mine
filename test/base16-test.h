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

//                plain             encoding
static TestData<std::vector<int>, std::string> Base16ByteArrayEncodingTestData = {
    TestCase(std::vector<int> { 72, 101, 108, 108, 111 }, "48656C6C6F"),
};

static TestData<std::string, unsigned long long> Base16IntTestData = {
    TestCase("22FD3", 143315ULL),
    TestCase("35639D3C8", 14331532232ULL),
    TestCase("3D8E08048D", 264375895181ULL),
};

static TestData<std::string> InvalidBase16EncodingData = {
    TestCase("48656C6C6F20576F726C64F"),
};

static TestData<std::string> EncodingDecodingData = {
    TestCase("C1"),
    TestCase("78DA2B492D2E0100045D01C1"),
};

TEST(Base16Test, Encode)
{
    for (const auto& item : Base16TestData) {
        std::string encoded = Base16::encode(PARAM(1));
        ASSERT_STREQ(PARAM(0).c_str(), encoded.c_str());
    }
}

TEST(Base16Test, EncodeDecodingTest)
{
    for (const auto& item : EncodingDecodingData) {
        std::string decoded = Base16::decode(PARAM(0));
        ASSERT_STREQ(PARAM(0).c_str(), Base16::encode(decoded).c_str());
    }
}

TEST(Base16Test, EncodeByteArray)
{
    for (const auto& item : Base16ByteArrayEncodingTestData) {
        std::string encoded = Base16::encode(PARAM(0).begin(), PARAM(0).end());
        ASSERT_STREQ(PARAM(1).c_str(), encoded.c_str());
    }
}


// hex str    hex arr     raw str
static TestData<std::string, ByteArray, std::string> Base16FromStringData = {
    TestCase("48656C6C6F", ByteArray { 0x48, 0x65, 0x6C, 0x6C, 0x6F }, "Hello"),
};

TEST(Base16Test, ConvertToByteArray)
{
    for (const auto& item : Base16FromStringData) {
        ByteArray result = Base16::fromString(PARAM(0));
        ASSERT_EQ(PARAM(1), result);
    }
}

TEST(Base16Test, ConvertToRaw)
{
    for (const auto& item : Base16FromStringData) {
        std::string result = Base16::toRawString(PARAM(1));
        ASSERT_EQ(PARAM(2), result);
    }
}

TEST(Base16Test, EncodeInt)
{
    for (const auto& item : Base16IntTestData) {
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

TEST(Base16Test, DecodeInt)
{
    for (const auto& item : Base16IntTestData) {
        unsigned long long decoded = Base16::decodeInt<unsigned long long>(PARAM(0));
        ASSERT_EQ(PARAM(1), decoded);
    }
}

TEST(Base16Test, InvalidBase16Encoding)
{
    for (const auto& item : InvalidBase16EncodingData) {
        EXPECT_THROW(Base16::decode(PARAM(0)), std::invalid_argument);
    }
}
}

#endif // BASE16_TEST_H
