#ifndef ZLIB_TEST_H
#define ZLIB_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "package/mine.h"
#else
#   include "src/zlib.h"
#   include "src/base64.h"
#   include "src/base16.h"
#endif

namespace mine {

static TestData<std::string, std::string> ZLibData = {
    TestCase("abcd", "eNpLTEpOAQAD2AGL"),
};

static TestData<std::string, std::string> ZLibDataHex = {
    TestCase("test", "78DA2B492D2E0100045D01C1"),
};

TEST(ZLibTest, Compress)
{
    for (const auto& item : ZLibData) {
        std::string encoded = ZLib::compressString(PARAM(0));
        ASSERT_EQ(PARAM(1), Base64::encode(encoded));
    }
}

TEST(ZLibTest, Decompress)
{
    for (const auto& item : ZLibData) {
        std::string decoded = ZLib::decompressString(Base64::decode(PARAM(1)));
        ASSERT_EQ(PARAM(0), decoded);
    }
}

TEST(ZLibTest, DecompressHex)
{
    for (const auto& item : ZLibDataHex) {
        std::string decoded = ZLib::decompressString(Base16::decode(PARAM(1)));
        ASSERT_EQ(PARAM(0), decoded);
    }
}

}

#endif // ZLIB_TEST_H
