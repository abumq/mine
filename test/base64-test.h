#ifndef BASE64_TEST_H
#define BASE64_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "package/mine.h"
#else
#   include "src/base64.h"
#endif

namespace mine {

static TestData<std::string, std::string> Base64TestData = {
    // examples from https://en.wikipedia.org/wiki/Base64#Output_padding
    TestCase("YWJjZA==", "abcd"),
    TestCase("YW55IGNhcm5hbCBwbGVhc3VyZS4=", "any carnal pleasure."),
    TestCase("YW55IGNhcm5hbCBwbGVhc3VyZQ==", "any carnal pleasure"),
    TestCase("YW55IGNhcm5hbCBwbGVhc3Vy", "any carnal pleasur"),
    TestCase("YW55IGNhcm5hbCBwbGVhc3U=", "any carnal pleasu"),
    TestCase("YW55IGNhcm5hbCBwbGVhcw==", "any carnal pleas"),
    // some manual examples
    TestCase("cGxhaW4gdGV4dA==", "plain text"),
    TestCase("SGVsbG8=", "Hello"),
    TestCase("YWJjMTIzIT8kKiYoKSctPUB+", "abc123!?$*&()'-=@~"),
    // Some unicode examples
    TestCase("SGVsbG/nq5w=", "Hello竜"),
    TestCase("4oKsNTA=", "€50"),
    TestCase("dGhpcyBpcyByb2NrZXQg8J+agCBhbmQgaSBsb3ZlIGl0", "this is rocket 🚀 and i love it"),
    TestCase("cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRw==", "quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG"),
    TestCase("cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRyAxMjM0NTY3ODkw", "quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG 1234567890"),
};

static TestData<std::string, std::wstring> Base64WStringTestData = {
    // examples from https://en.wikipedia.org/wiki/Base64#Output_padding
    TestCase("YWJjZA==", L"abcd"),
    TestCase("YW55IGNhcm5hbCBwbGVhc3VyZS4=", L"any carnal pleasure."),
    TestCase("YW55IGNhcm5hbCBwbGVhc3VyZQ==", L"any carnal pleasure"),
    TestCase("YW55IGNhcm5hbCBwbGVhc3Vy", L"any carnal pleasur"),
    TestCase("YW55IGNhcm5hbCBwbGVhc3U=", L"any carnal pleasu"),
    TestCase("YW55IGNhcm5hbCBwbGVhcw==", L"any carnal pleas"),
    // some manual examples
    TestCase("cGxhaW4gdGV4dA==", L"plain text"),
    TestCase("SGVsbG8=", L"Hello"),
    TestCase("YWJjMTIzIT8kKiYoKSctPUB+", L"abc123!?$*&()'-=@~"),
    // Some unicode examples
    TestCase("SGVsbG/nq5w=", L"Hello竜"),
    TestCase("4oKsNTA=", L"€50"),
    // Commenting and leaving it here on purpose, see note on decodeAsWString
    // TestCase("dGhpcyBpcyByb2NrZXQg8J+agCBhbmQgaSBsb3ZlIGl0", L"this is rocket 🚀 and i love it"),
    TestCase("cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRw==", L"quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG"),
    TestCase("cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRyAxMjM0NTY3ODkw", L"quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG 1234567890"),
};

static TestData<std::string> InvalidBase64EncodingData = {
    TestCase("YWJj,ZA=="),
    TestCase("YWJj,A=="),
    TestCase(",,,,"),
    TestCase("===="),
};

static TestData<std::string, bool> IsBase64Data = {
    TestCase("da024686f7f2da49da6c98253b42fe1c:erezutlgudgbtwza:i3eclcagfnUbK1B==", false),
    TestCase("da024686f7f2da49da6c98253b42fe1c:i3eclcagfnUbK1B==", false),
    TestCase("erezutlgudgbtwza:i3eclcagfnUbK1B==", false),
    TestCase("dGhpcyBpcyByb2NrZXQg8J+agCBhbmQgaSBsb3ZlIGl0", true),
    TestCase("SGVsbG/nq5w=", true),
    TestCase("i3eclcagfnUbK1B==", true),
};

TEST(Base64Test, Encode)
{
    for (const auto& item : Base64TestData) {
        std::string encoded = Base64::encode(PARAM(1));
        ASSERT_STREQ(PARAM(0).c_str(), encoded.c_str());
    }
}

TEST(Base64Test, Decode)
{
    for (const auto& item : Base64TestData) {
        std::string decoded = Base64::decode(PARAM(0));
        std::cout << decoded << std::endl;
        ASSERT_STREQ(PARAM(1).c_str(), decoded.c_str());
    }
}

TEST(Base64Test, EncodeWString)
{
    for (const auto& item : Base64WStringTestData) {
        std::string encoded = Base64::encode(PARAM(1));
        ASSERT_STREQ(PARAM(0).c_str(), encoded.c_str());
    }
}

TEST(Base64Test, DecodeWString)
{
    for (const auto& item : Base64WStringTestData) {
        std::wstring decoded = Base64::decodeAsWString(PARAM(0));
        std::wcout << std::wstring(decoded.begin(), decoded.end());
        std::wcout.clear(); // clear the stream in case of failbit or badbit
        std::cout << std::endl;
        ASSERT_STREQ(PARAM(1).c_str(), decoded.c_str());
    }
}

TEST(Base64Test, InvalidBase64Encoding)
{
    for (const auto& item : InvalidBase64EncodingData) {
        EXPECT_THROW(Base64::decode(PARAM(0)), std::runtime_error);
    }
}

TEST(Base64Test, ExpectedSize)
{
    for (const auto& item : Base64TestData) {
        std::size_t s = Base64::expectedLength(PARAM(1));
        ASSERT_EQ(PARAM(0).size(), s);
    }
}

TEST(Base64Test, ExpectedSizeWstring)
{
    for (const auto& item : Base64WStringTestData) {
        std::size_t s = Base64::expectedLength(PARAM(1));
        ASSERT_EQ(PARAM(0).size(), s);
    }
}

TEST(Base64Test, IsBase64)
{
    for (const auto& item : IsBase64Data) {
        auto first = PARAM(0);
        auto second = PARAM(1);
        ASSERT_EQ(Base64::isBase64(first), second);
    }
}

}

#endif // BASE64_TEST_H
