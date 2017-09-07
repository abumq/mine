#ifndef BIG_INTEGER_TEST_H
#define BIG_INTEGER_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "package/mine.h"
#else
#   include "src/big-integer.h"
#endif

namespace mine {

TEST(BigIntegerTest, Construct)
{
    BigInteger b0("023");
    ASSERT_EQ(b0.str(), "23");

    BigInteger b(123);
    ASSERT_EQ(b.digits(), 3);

    BigInteger b2("1234");
    ASSERT_EQ(b2.digits(), 4);

    BigInteger b3("12345678901234567890123456789012");
    ASSERT_EQ(b3.digits(), 32);

    b = b2;
    ASSERT_EQ(b.str(), "1234");
    b = 123;
    ASSERT_EQ(b.str(), "123");

    ASSERT_EQ(b.toLong(), (long long) 123);

    BigInteger b4(b3);
    ASSERT_EQ(b4, b3);
    ASSERT_NE(b4, b2);

    BigInteger b5(std::move(b4));
    ASSERT_EQ(b4, 0);
    ASSERT_NE(b4, b2);
    ASSERT_EQ(b5, BigInteger("12345678901234567890123456789012"));


    BigInteger bneg("-23");
    ASSERT_EQ(bneg.str(), "-23");
    ASSERT_TRUE(bneg.isNegative());

    BigInteger bnegl(-23);
    ASSERT_EQ(bnegl.str(), "-23");
    ASSERT_TRUE(bnegl.isNegative());
}

static TestData<BigInteger, BigInteger, bool> BiggerThanData = {
    TestCase(123, 4563, false),
    TestCase(1234, 223, true),
    TestCase(-2332, 223, false),
    TestCase(2332, 223, true),
    TestCase(2332, -223, true),
    TestCase(-2332, -223, false),
    TestCase(-22, -223, true),
    TestCase(22, -22, true),
    TestCase(-22, 22, false),
    TestCase(-233, 22, false),
    TestCase(233, 22, true),
    TestCase(3, 22, false),
    TestCase(3123, -22, true),
    TestCase(-31, -22, false),
    TestCase(-22, -31, true),
};

TEST(BigIntegerTest, BiggerThan)
{
    for (const auto& item : BiggerThanData) {
        BigInteger a = PARAM(0);
        BigInteger b = PARAM(1);
        bool exp = PARAM(2);
        ASSERT_EQ(a > b, exp);
        bool smaller = a < b;
        bool smallerExp = !exp;
        ASSERT_EQ(smaller, smallerExp);
    }
}

static TestData<BigInteger, bool> OnerTestData = {
    TestCase(123, false),
    TestCase(1, true),
    TestCase(10, true),
    TestCase(1000, true),
    TestCase(21000, false),
};

TEST(BigIntegerTest, IsOnerTest)
{
    for (const auto& item : OnerTestData) {
        BigInteger a = PARAM(0);
        ASSERT_EQ(a.is1er(), PARAM(1));
    }
}

static TestData<BigInteger, BigInteger, BigInteger> AdditionData = {
    TestCase(123, 456, 579),
    TestCase(1235, 456, 1691),
    TestCase(123, 4560, 4683),
    TestCase(123, 45600, 45723),
    TestCase(BigInteger("023"), 45600, 45623),
    TestCase(BigInteger("-23"), 45600, -45577),
    TestCase(BigInteger("23"), -45600, -45577),
};

TEST(BigIntegerTest, Addition)
{
    for (const auto& item : AdditionData) {
        BigInteger a = PARAM(0);
        BigInteger b = PARAM(1);
        BigInteger exp = PARAM(2);
        ASSERT_EQ(a + b, exp);
        a += b;
        ASSERT_EQ(a, exp);
    }
}

static TestData<BigInteger, BigInteger, BigInteger> SubtractionData = {
    TestCase(0, 123, -123),
    TestCase(4560, 123, 4437),
    TestCase(123, 4560, -4437),
    TestCase(1, 4560, -4559),
    TestCase(-500, -1, -501),
};

TEST(BigIntegerTest, Subtraction)
{
    for (const auto& item : SubtractionData) {
        BigInteger a = PARAM(0);
        BigInteger b = PARAM(1);
        BigInteger exp = PARAM(2);
        ASSERT_EQ(a - b, exp);
        a -= b;
        ASSERT_EQ(a, exp);
    }
}

static TestData<BigInteger, BigInteger, BigInteger> MultiplyData = {
    TestCase(123, 27, 3321),
    TestCase(63, 67, 4221),
    TestCase(6, 67, 402),
    TestCase(3, 6701, 20103),
    TestCase(243, 993, 241299),
    TestCase(2439, 99, 241461),
    TestCase(BigInteger("24339221"), BigInteger("32212132"), BigInteger("784018199629172")),
    TestCase(2, 0, 0),
    TestCase(0, 0, 0),
    TestCase(2, 4, 8),
    TestCase(2439, -99, -241461),
    TestCase(-2439, -99, 241461),
};

TEST(BigIntegerTest, Multiplication)
{
    for (const auto& item : MultiplyData) {
        std::cout << PARAM(0) << " x " << PARAM(1) << " = " << PARAM(2) << std::endl;
        BigInteger result = BigInteger(PARAM(0)) * BigInteger(PARAM(1));
        BigInteger exp = PARAM(2);
        ASSERT_EQ(result, exp);
    }

    // one more test ;)
    BigInteger a = 65536;
    BigInteger exp("340282366920938463463374607431768211456");

    ASSERT_EQ(a * a * a * a * a * a * a * a, exp);

}

}

#endif // BIG_INTEGER_TEST_H
