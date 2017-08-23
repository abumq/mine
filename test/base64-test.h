#ifndef BASE64_TEST_H
#define BASE64_TEST_H

#include "src/base64.h"
#include "test.h"

namespace mine {

static TestData<std::string, std::wstring> Base64TestData = {
    TestCase("cGxhaW4gdGV4dA==", L"plain text"),
    TestCase("cXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nIFFVSUNLIEJST1dOIEZPWCBKVU1QUyBPVkVSIFRIRSBMQVpZIERPRw==", L"quick brown fox jumps over the lazy dog QUICK BROWN FOX JUMPS OVER THE LAZY DOG"),
    TestCase("SGVsbG/nq5wK", L"Hello竜"),
    TestCase("5aSn5a625aW9Cg==", L"大家好"),
    TestCase("dGhpcyBpcyByb2NrZXQg8J+agCBhbmQgaSBsb3ZlIGl0", L"this is rocket 🚀 and i love it"),
};

static TestData<std::string, bool> IsBase64Data = {
    TestCase("da024686f7f2da49da6c98253b42fe1c:erezutlgudgbtwza:i3eclcagfnUbK1B==", false),
    TestCase("da024686f7f2da49da6c98253b42fe1c:i3eclcagfnUbK1B==", false),
    TestCase("erezutlgudgbtwza:i3eclcagfnUbK1B==", false),
    TestCase("i3eclcagfnUbK1B==", true),
};

TEST(Base64Test, Encode)
{
    for (const auto& item : Base64TestData) {
        std::string encoded = Base64::base64Encode(PARAM(1));
        ASSERT_STREQ(PARAM(0).c_str(), encoded.c_str());
    }
}

TEST(Base64Test, Decode)
{
    for (const auto& item : Base64TestData) {
        //std::string decoded = Base64::base64Decode(PARAM(0));
        //ASSERT_STREQ(PARAM(1), decoded);
    }
}

TEST(Base64Test, ExpectedSize)
{
    for (const auto& item : Base64TestData) {
        LOG(INFO) << PARAM(1) << " => " << PARAM(1).size();
        std::size_t s = Base64::expectedBase64Length(PARAM(1).size());
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
