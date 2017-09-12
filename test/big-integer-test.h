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

    BigInteger b16("0xff");
    ASSERT_EQ(b16.str(), "255");
    ASSERT_EQ(b16.base(), 16);
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
static TestData<BigInteger, long, BigInteger> PowerData = {
    TestCase(10, 0, 1),
    TestCase(10, 1, 10),
    TestCase(10, 19, BigInteger("10000000000000000000")),
};

TEST(BigIntegerTest, Power)
{
    for (const auto& item : PowerData) {
        BigInteger a = PARAM(0);
        long b = PARAM(1);
        BigInteger exp = PARAM(2);
        ASSERT_EQ(a ^ b, exp);
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
    TestCase(BigInteger("240171000090999121"), BigInteger("3221213232223221"), BigInteger("243392213323222342")),
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
    TestCase(BigInteger("243392213323222342"), BigInteger("3221213232223221"), BigInteger("240171000090999121")),
    TestCase(BigInteger("243392213323222342"), BigInteger("240171000090999121"), BigInteger("3221213232223221")),
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

static TestData<BigInteger, int, BigInteger> RightShiftData = {
    TestCase(4, 1, 2), // 100 => 10
    TestCase(10, 1, 5), // 1010 => 101
    TestCase(255, 1, 127),
    TestCase(BigInteger("34778223424"), 1, BigInteger("17389111712")),
};

TEST(BigIntegerTest, RightShift)
{
    for (const auto& item : RightShiftData) {
        BigInteger a = PARAM(0);
        int shiftBy = PARAM(1);
        BigInteger exp = PARAM(2);
        ASSERT_EQ(a >> shiftBy, exp);
    }
}

static TestData<BigInteger, int, BigInteger> LeftShiftData = {
    TestCase(2, 1, 4),
    TestCase(5, 1, 10),
    TestCase(127, 1, 254),
    TestCase(BigInteger("17389111712"), 1, BigInteger("34778223424")),
    TestCase(0xF, 1, 30),
};

TEST(BigIntegerTest, LeftShift)
{
    for (const auto& item : LeftShiftData) {
        BigInteger a = PARAM(0);
        int shiftBy = PARAM(1);
        BigInteger exp = PARAM(2);
        ASSERT_EQ(a << shiftBy, exp);
    }
}

static TestData<BigInteger, bool> BitwiseAndData = {
    TestCase(255, true),
    TestCase(127, true),
    TestCase(46, false),
    TestCase(47, true),
};

TEST(BigIntegerTest, BitwiseAnd)
{
    for (const auto& item : BitwiseAndData) {
        BigInteger a = PARAM(0);
        bool exp = PARAM(1);
        ASSERT_EQ(a & 1, exp);
    }
}

static TestData<BigInteger, int, BigInteger> BitwiseOrData = {
    TestCase(5, 6, 7),
    TestCase(40, 29, 61),
    TestCase(2932, 40, 2940),
};

TEST(BigIntegerTest, BitwiseOr)
{
    for (const auto& item : BitwiseOrData) {
        BigInteger a = PARAM(0);
        int b = PARAM(1);
        BigInteger exp = PARAM(2);
        ASSERT_EQ(a | b, exp);
    }
}

static TestData<BigInteger, BigInteger, BigInteger> MultiplyData = {
    TestCase(123, 27, 3321),
    TestCase(63, 67, 4221),
    TestCase(6, 67, 402),
    TestCase(3, 6701, 20103),
    TestCase(243, 993, 241299),
    TestCase(2439, 99, 241461),
    TestCase(BigInteger("243392213"), BigInteger("32212132"), BigInteger("7840182092928116")),
    TestCase(BigInteger("243392213323222342"), BigInteger("3221213232223221"), BigInteger("784018218176860754178652358403582")),
    TestCase(BigInteger("5080873441234413887"), BigInteger("2234638207523081573"), BigInteger("11353913919371701786996400886745004251")),
    TestCase(BigInteger("43879350166773359647071667116025080873441234413887"), BigInteger("71904842149664289633274572930135618242638207523081573"), BigInteger("3155137747371683847511707019689925546164918051142631554924123181885362208552200375950092400886745004251")),
    TestCase(BigInteger("108215449534587396558557488943879350166773359647071667116025080873441234413887"), BigInteger("91243493758612676931094271904842149664289633274572930135618242638207523081573"), BigInteger("9873955694194590232514048984970761535584766520827432398848323179877576914413107050563833143580841040071254924123181885362208552200375950092400886745004251")),
    TestCase(2, 0, 0),
    TestCase(0, 0, 0),
    TestCase(2, 4, 8),
    TestCase(2439, -99, -241461),
    TestCase(-2439, -99, 241461),
};

TEST(BigIntegerTest, Multiplication)
{
    auto printCalc = [](BigInteger x, BigInteger y, BigInteger exp) {
        std::cout << "    " << x << "\n x  " << y
                  << "\n-------------------------------------------------------\n =  "
                  << exp << std::endl;
        std::cout << std::endl;
    };

    for (const auto& item : MultiplyData) {
        printCalc(PARAM(1), PARAM(0), PARAM(2));
        BigInteger result = BigInteger(PARAM(0)) * BigInteger(PARAM(1));
        BigInteger exp = PARAM(2);
        ASSERT_EQ(result, exp);
    }

    // one more test ;)
    BigInteger a = 65536;
    BigInteger exp2("4294967296");
    BigInteger exp3("281474976710656");
    BigInteger exp4("18446744073709551616");
    BigInteger exp5("1208925819614629174706176");
    BigInteger exp6("79228162514264337593543950336");
    BigInteger exp7("5192296858534827628530496329220096");

    printCalc(a, a, exp2);
    ASSERT_EQ(a * a, exp2);

    printCalc(a, exp2, exp3);
    ASSERT_EQ(exp2 * a, exp3);

    printCalc(a, exp3, exp4);
    ASSERT_EQ(exp3 * a, exp4);

    printCalc(a, exp4, exp5);
    ASSERT_EQ(exp4 * a, exp5);

    printCalc(a, exp5, exp6);
    ASSERT_EQ(exp5 * a, exp6);

    printCalc(a, exp6, exp7);
    ASSERT_EQ(exp6 * a, exp7);

}

static TestData<BigInteger, BigInteger, BigInteger, BigInteger> DivisionData = {
    TestCase(BigInteger("6560926371163053827"), BigInteger("911249695"), BigInteger("7199921610"), BigInteger("26644877")),
    TestCase(BigInteger("193"), 91, BigInteger("2"), 11),
    TestCase(BigInteger("51922968580"), 10, BigInteger("5192296858"), 0),
    TestCase(BigInteger("519229685810"), 100, BigInteger("5192296858"), 10),
    TestCase(BigInteger("51922968580"), 100, BigInteger("519229685"), 80),
    TestCase(BigInteger("51922968580"), 100000, BigInteger("519229"), 68580),
    TestCase(BigInteger("51922968580"), BigInteger("100000000"), BigInteger("519"), BigInteger("22968580")),
    TestCase(BigInteger("5192296858534827628530496329220096"), BigInteger("79228162514264337593543950336"), BigInteger(65536), BigInteger("0")),
    TestCase(4, 2, 2, 0),
    TestCase(4, 3, 1, 1),
    TestCase(48, 32, 1, 16),
    TestCase(487, 32, 15, 7),
};

TEST(BigIntegerTest, Division)
{
    for (const auto& item : DivisionData) {
        BigInteger a = PARAM(0);
        BigInteger b = PARAM(1);
        BigInteger expQ = PARAM(2);
        BigInteger expR = PARAM(3);
        BigInteger q, r;
        a.divide(b, q, r);
        ASSERT_EQ(q, expQ);
        ASSERT_EQ(r, expR);
    }
}

}

#endif // BIG_INTEGER_TEST_H
