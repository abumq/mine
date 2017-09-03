#ifndef BASE64_TEST_H
#define BASE64_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "package/mine.h"
#else
#   include "src/base64.h"
#   include "src/base16.h"
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

static TestData<std::string, std::string> Base64OnlyDecodingTestData = {
    //TestCase("\nSGVs\nbG8=", "Hello"),
    TestCase("SGVsbG8=\n", "Hello"),
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

static TestData<std::vector<int>, std::string> Base64ByteArrayEncodingTestData = {
    TestCase(std::vector<int> { 72, 101, 108, 108, 111 }, "SGVsbG8="),
};


TEST(Base64Test, Encode)
{
    for (const auto& item : Base64TestData) {
        std::string encoded = Base64::encode(PARAM(1));
        ASSERT_STREQ(PARAM(0).c_str(), encoded.c_str());
    }
}


TEST(Base64Test, OnlyDecoding)
{
    for (const auto& item : Base64OnlyDecodingTestData) {
        std::string decoded = Base64::decode(PARAM(0));
        ASSERT_STREQ(PARAM(1).c_str(), decoded.c_str());
    }
}


TEST(Base64Test, ByteArrayEncode)
{
    for (const auto& item : Base64ByteArrayEncodingTestData) {
        std::string encoded = Base64::encode(PARAM(0).begin(), PARAM(0).end());
        ASSERT_STREQ(PARAM(1).c_str(), encoded.c_str());
    }
}

TEST(Base64Test, Decode)
{
    for (const auto& item : Base64TestData) {
        std::string decoded = Base64::decode(PARAM(0));
        //std::cout << decoded << std::endl;
        ASSERT_STREQ(PARAM(1).c_str(), decoded.c_str());
    }
}

static TestData<std::string, std::size_t, std::string> Base64RawTestData = {
    TestCase("dGhpcyBjb250YWlucyA9IHBhZGRpbmc=", 23, "7468697320636F6E7461696E73203D2070616464696E67"), // contains padding char
    TestCase("Z0BiQ8NcwknqzbGrWBjXqw==", 16, "67406243C35CC249EACDB1AB5818D7AB"),
    TestCase("EtYr5JFo/7kqYWxooMvU2DJ+upNhUMDii9X6IEHYxvUNXSVGk34IakT5H7GbyzL5/JIMMAQCLnUU824RI3ymgQ==", 64, "12D62BE49168FFB92A616C68A0CBD4D8327EBA936150C0E28BD5FA2041D8C6F50D5D2546937E086A44F91FB19BCB32F9FC920C3004022E7514F36E11237CA681")
};

TEST(Base64Test, DecodeRawSize)
{
    for (const auto& item : Base64RawTestData) {
        std::string decoded = Base64::decode(PARAM(0));
        ASSERT_EQ(PARAM(1), decoded.size());
        std::string b16 = Base16::encode(decoded);
        //std::cout << decoded << std::endl;
        ASSERT_STRCASEEQ(PARAM(2).c_str(), b16.c_str());
    }
}

#ifdef MINE_BASE64_WSTRING_CONVERSION
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
        //std::wcout << std::wstring(decoded.begin(), decoded.end());
        //std::wcout.clear(); // clear the stream in case of failbit or badbit
        //std::cout << std::endl;
        ASSERT_STREQ(PARAM(1).c_str(), decoded.c_str());
    }
}

TEST(Base64Test, ExpectedSizeWstring)
{
    for (const auto& item : Base64WStringTestData) {
        std::size_t s = Base64::expectedLength(PARAM(1));
        ASSERT_EQ(PARAM(0).size(), s);
    }
}
#endif

TEST(Base64Test, InvalidBase64Encoding)
{
    for (const auto& item : InvalidBase64EncodingData) {
        EXPECT_THROW(Base64::decode(PARAM(0)), std::invalid_argument);
    }
}

TEST(Base64Test, ExpectedSize)
{
    for (const auto& item : Base64TestData) {
        std::size_t s = Base64::expectedLength(PARAM(1));
        ASSERT_EQ(PARAM(0).size(), s);
    }
}

}

#endif // BASE64_TEST_H
