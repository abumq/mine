//
//  big-integer.cc
//  Part of Mine crypto library
//
//  You should not use this file, use mine.cc
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
#include <iostream>
#include <sstream>
#include <cmath>
#include <bitset>
#include "src/base16.h"
#include "src/big-integer.h"

using namespace mine;

const BigInteger BigInteger::kZero = BigInteger(0);
const BigInteger BigInteger::kOne = BigInteger(1);
const BigInteger BigInteger::kTwo = BigInteger(2);
const BigInteger BigInteger::kMinusOne = BigInteger(-1);
const BigInteger BigInteger::kSixteen = BigInteger(16);
const BigInteger BigInteger::kTwoFiftySix = BigInteger(256);

BigInteger::BigInteger() : m_negative(false), m_base(10)
{
    checkAndFixData();
}

BigInteger::BigInteger(const Container &d)
    : m_negative(false),
      m_data(d),
      m_base(10) {
    checkAndFixData();
}

BigInteger::BigInteger(const BigIntegerBitSet &d)
    : m_negative(false),
      m_base(10) {
    BigInteger r;
    for (std::size_t i = 0; i < d.size(); ++i) {
        if (d.test(i)) {
            r += twoPower(i);
        }
    }

    m_data = std::move(r.m_data);
}

BigInteger::BigInteger(const BigInteger& other)
{
    m_data = other.m_data;
    m_negative = other.m_negative;
    m_base = other.m_base;
    checkAndFixData();
}

BigInteger::BigInteger(BigInteger&& other)
{
    m_data = std::move(other.m_data);
    m_negative = other.m_negative;
    m_base = other.m_base;
    other.m_negative = false;
    checkAndFixData();
    other.checkAndFixData();
}

BigInteger& BigInteger::operator=(const BigInteger& other)
{
    if (this != &other) {
        m_data = other.m_data;
        m_negative = other.m_negative;
        m_base = other.m_base;
        checkAndFixData();
    }
    return *this;
}

BigInteger::BigInteger(const std::string& n)
{
    init(n);
}

BigInteger::BigInteger(int n)
{
    init(n);
}

BigInteger::BigInteger(unsigned long long n)
{
    init(n);
}

BigInteger& BigInteger::operator=(int n)
{
    init(n);
    return *this;
}

BigInteger& BigInteger::operator=(const std::string& n)
{
    init(n);
    return *this;
}

void BigInteger::init(int n)
{
    if (n < 0) {
        m_negative = true;
        n = -n;
    } else {
        m_negative = false;
    }
    m_base = 10;
    m_data.clear();
    do {
        m_data.insert(m_data.begin(), n % m_base);
        n /= m_base;
    } while (n);
    checkAndFixData();
}

void BigInteger::init(unsigned long long n)
{
    m_base = 10;
    m_data.clear();
    do {
        m_data.insert(m_data.begin(), n % m_base);
        n /= m_base;
    } while (n);
    checkAndFixData();
}

void BigInteger::init(const std::string& n)
{
    if (n.empty()) {
        throw std::invalid_argument("Invalid number");
    }
    m_base = 10;
    m_negative = n[0] == '-';
    int beginOffset = m_negative ? 1 : 0;
    if (n.size() > 2 && n[0] == '0' && (n[1] == 'x' || n[1] == 'X')) {
        m_base = 16;
        beginOffset += 2;
        std::string hex(n);
        hex.erase(hex.begin(), hex.begin() + beginOffset);
        std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);

        BigInteger r(Base16::decodeInt<BigInteger>(hex));
        m_data = std::move(r.m_data);
    } else {
        // base 10
        m_data.clear();

        bool firstNonZeroDigitFound = false;
        for (auto it = n.begin() + beginOffset; it < n.end(); ++it) {
            char c = *it;
            if (!isdigit(c)) {
                throw std::invalid_argument("Invalid number");
            }
            if (c == '0' && !firstNonZeroDigitFound) {
                continue;
            }
            firstNonZeroDigitFound = true;
            m_data.push_back(static_cast<int>(c) - '0');
        }
    }
    checkAndFixData();
}

void BigInteger::checkAndFixData()
{
    while (digits() > 1 && m_data[0] == 0) {
        m_data.erase(std::find_if_not(m_data.begin(), m_data.end(), [&](int c) -> bool {
            return c > 0;
        }));
    }
    if (m_data.empty()) {
        m_data.push_back(0);
        m_negative = false;
    }
    if (isZero() && m_negative) {
        m_negative = false;
    }
}

BigInteger BigInteger::operator+(const BigInteger& other) const
{
    if ((m_negative || other.m_negative) && m_negative != other.m_negative) {
        // we have negation instead of addition in reality
        BigInteger otherCopy(other);
        otherCopy.m_negative = false;
        BigInteger thisCopy(*this);
        thisCopy.m_negative = false;
        if (other.m_negative) {
            return thisCopy - otherCopy;
        }
        return otherCopy - thisCopy;
    } else if (other.isZero()) {
        return *this;
    } else if (isZero()) {
        return other;
    }

    Container data(std::max(digits(), other.digits()) + 1);

    const Container* first = digits() >= other.digits() ? &m_data : &other.m_data;
    const Container* second = digits() >= other.digits() ? &other.m_data : &m_data;

    int carry = 0;
    std::size_t i = data.size() - 1;
    for (auto itf = first->rbegin(), its = second->rbegin(); itf < first->rend(); ++itf, ++its) {
        int x = *itf;
        int y = (its >= second->rend()) ? 0 : *its;
        int z = (x + y) + carry;
        if (z > 9) {
            carry = 1;
            z -= 10;
        } else {
            carry = 0;
        }
        data[i--] = z;
    }

    data[0] = carry;

    if (data[0] == 0) {
        data.erase(std::find_if_not(data.begin(), data.end(), [&](int c) -> bool {
            return c > 0;
        }));
    }

    BigInteger result(data);
    result.m_negative = m_negative && other.m_negative;
    return result;
}

BigInteger BigInteger::operator-(const BigInteger& other) const
{
    if (other.isZero()) {
        return *this;
    } else if (isZero()) {
        BigInteger result(other);
        result.m_negative = true;
        return result;
    }
    if ((!m_negative && other.m_negative) || (m_negative && !other.m_negative)) {
        // we have addition instead of subtraction in reality

        BigInteger otherCopy(other);
        otherCopy.m_negative = false;
        BigInteger thisCopy(*this);
        thisCopy.m_negative = false;

        BigInteger result;
        if (thisCopy > otherCopy) {
            result = thisCopy + otherCopy;
        } else {
            result = otherCopy + thisCopy;
            result.m_negative = m_negative; // previously negative or not
        }
        return result;
    } else if (m_negative && other.m_negative) {
        BigInteger otherCopy(other);
        otherCopy.m_negative = false;
        BigInteger thisCopy(*this);
        thisCopy.m_negative = false;

        BigInteger result;
        if (thisCopy > otherCopy) {
            result = thisCopy - otherCopy;
            result.m_negative = true;
        } else {
            result = otherCopy - thisCopy;
        }
        return result;
    }
    Container data;
    bool neg = *this < other;

    const Container* first = digits() >= other.digits() ? &m_data : &other.m_data;
    const Container* second = digits() >= other.digits() ? &other.m_data : &m_data;

    int carry = 0;
    for (auto itf = first->rbegin(), its = second->rbegin(); itf < first->rend(); ++itf, ++its) {
        int x = (*itf) - carry;
        int y = (its >= second->rend()) ? 0 : *its;
        if (x < y) {
            carry = 1;
        } else {
            carry = 0;
        }
        int z = ((x + (carry * 10)) - y);
        data.insert(data.begin(), z);
    }

    // remove leading zeros
    data.erase(data.begin(), std::find_if_not(data.begin(), data.end(), [&](int x) {
        return x == 0;
    }));
    BigInteger result(data);
    result.m_negative = neg;
    return result;
}

#if 0
BigInteger BigInteger::operator*(const BigInteger& other) const
{
    if (*this < 10 && other < 10) {
        if (m_data.empty() || other.m_data.empty()) {
            return BigInteger(0);
        }
        return BigInteger(m_data[0] * other.m_data[0]);
    } else if (isZero() || other.isZero()) {
        return BigInteger(0);
    }

    const int B = 10;
    long greater = std::max(digits(), other.digits());
    long mid = greater / 2;
    BigInteger low1 = BigInteger(Container(m_data.begin(), m_data.begin() + mid));
    BigInteger high1 = BigInteger(Container(m_data.begin() + mid, m_data.end()));
    BigInteger low2 = BigInteger(Container(other.m_data.begin(), other.m_data.begin() + mid));
    BigInteger high2 = BigInteger(Container(other.m_data.begin() + mid, other.m_data.end()));

    BigInteger z0 = low1 * low2;
    BigInteger z1 = (low1 + high1) * (low2 + high2);
    BigInteger z2 = high1 * high2;
    BigInteger first = z2 * pow(B, 2 * mid);
    BigInteger second = (z1 - z2 - z0) * pow(B, mid);

    return (first + second + z0);
}
#elif 1
BigInteger BigInteger::operator*(const BigInteger& other) const
{
    return longMul(other);
}
#else

// we use temp this and then fix the one above (commented one)
BigInteger BigInteger::operator*(const BigInteger& other) const
{
    if (other.is1er()) {
        BigInteger result(*this);
        result.m_negative = (m_negative || other.m_negative) && m_negative != other.m_negative;
        result.m_data.resize(digits() + other.digits() - 1, 0);
        return result;
    } else if (*this >= 0 && other >= 0 && *this < 10 && other < 10) {
        if (m_data.empty() || other.m_data.empty()) {
            return BigInteger(0);
        }
        return BigInteger(m_data[0] * other.m_data[0]);
    } else if (isZero() || other.isZero()) {
        return BigInteger(0);
    } else if (other < 10) {
        return longMul(other);
    }
    BigInteger x = *this;
    BigInteger y = other;
    BigInteger result;
    while (!y.isZero()) {
        if (y.bin().test(0)) {
            result += x;
        }
        x <<= 1;
        y >>= 1;
    }
    result.m_negative = (m_negative || other.m_negative) && m_negative != other.m_negative;
    return result;
}
#endif

BigInteger BigInteger::longMul(const BigInteger& other) const
{
    if (other.is1er()) {
        BigInteger result(*this);
        result.m_negative = (m_negative || other.m_negative) && m_negative != other.m_negative;
        result.m_data.resize(digits() + other.digits() - 1, 0);
        return result;
    } else if (*this >= 0 && other >= 0 && *this < 10 && other < 10) {
        if (m_data.empty() || other.m_data.empty()) {
            return BigInteger(0);
        }
        return BigInteger(m_data[0] * other.m_data[0]);
    } else if (isZero() || other.isZero()) {
        return BigInteger(0);
    }
    // long multiply
    std::vector<BigInteger> tmps;
    for (auto itf = m_data.rbegin(); itf < m_data.rend(); ++itf) {
        Container dataTmp;
        int carry = 0;
        int y = *itf;
        for (auto its = other.m_data.rbegin(); its < other.m_data.rend(); ++its) {
            int x = *its;
            int z = (x * y) + carry;
            if (z < 10 || its >= other.m_data.rend() - 1) {
                carry = 0;
                while (z > 10) {
                    dataTmp.insert(dataTmp.begin(), z % 10);
                    z = ceil(z / 10);
                }
                dataTmp.insert(dataTmp.begin(), z);
            } else {
                carry = ceil(z / 10);
                z %= 10;
                dataTmp.insert(dataTmp.begin(), z);
            }
        }
        tmps.push_back(BigInteger(dataTmp));
    }

    BigInteger result;
    BigInteger p10(1);
    for (BigInteger b : tmps) {
        BigInteger bp10 = b * p10;
        result += bp10;
        p10 = p10 * 10;
    }
    result.m_negative = (m_negative || other.m_negative) && m_negative != other.m_negative;
    return result;
}

void BigInteger::divide(const BigInteger& d, BigInteger& q, BigInteger& r) const
{
    divide(*this, d, q, r);
}

BigInteger BigInteger::divide_(const BigInteger& dividend, const BigInteger& divisor, const BigInteger& originalDivisor, BigInteger& r) {
    BigInteger quotient = 1;
    bool isNeg = (dividend > 0 && divisor < 0) || (dividend < 0 && divisor > 0);

    BigInteger tdividend(dividend);
    tdividend.m_negative = false;
    BigInteger tdivisor(divisor);
    tdivisor.m_negative = false;
    if (tdividend == tdivisor) {
        r = 0;
        return isNeg ? -1 : 1;
    } else if (tdividend < tdivisor) {
        r = tdividend;
        r.m_negative = dividend.isNegative();
        return 0;
    }
    // add two checks to reduce unneeded shifting
    while (!tdivisor.isZero() && tdivisor << 1 <= tdividend) {
        tdivisor <<= 1;
        quotient <<= 1;
    }
    BigInteger next = tdividend - tdivisor;
    next.m_negative = isNeg;
    quotient.m_negative = isNeg;
    quotient += divide_(next, originalDivisor, originalDivisor, r);
    return quotient;
}

void BigInteger::divide(BigInteger n, BigInteger d, BigInteger& q, BigInteger& r)
{
    if (d.isZero()) {
        throw std::invalid_argument("Division by zero");
    }
    if (d < 0) {
        BigInteger d2(d);
        d2 *= kMinusOne;
        divide(n, d2, q, r);
        q.m_negative = !n.isNegative();
        return;
    }

    if (d < 10) {
        int di = static_cast<int>(d.toLong());
        int rem = 0;
        int quo = 0;
        for (auto i = n.m_data.begin(); i < n.m_data.end(); ++i) {
            int v = (rem * 10) + *i;
            if (n.isNegative()) {
                v = -v;
            }
            quo = v / di;
            rem = v % di;
            if (i == n.m_data.begin()) {
                q = quo;
            } else {
                q.m_data.push_back(quo);
            }
        }
        r = rem;
    } else {
#if 0
        q = divide_(n, d, d, r);
#else
        bool negative = false;
        if (n.isNegative()) {
            negative = true;
            n.m_negative = false;
        }
        q = 0;
        long long pos = -1;
        while (d <  n){
            d <<= 1;
            ++pos;
        }
        d >>= 1;
        while (pos > -1) {
            if (n >= d) {
                q += kOne << pos;
                n -= d;
            }
            d >>= 1;
            --pos;
        }
        r = n;
        q.m_negative = negative;
        r.m_negative = negative;
#endif
    }

    q.checkAndFixData();
    r.checkAndFixData();
}

BigInteger BigInteger::operator/(const BigInteger& d) const
{
    BigInteger q;
    BigInteger r;
    divide(d, q, r);
    return q;
}

BigInteger BigInteger::operator%(const BigInteger& other) const
{
    BigInteger q, r;
    divide(other, q, r);
    return r;
}

BigInteger BigInteger::power(long long e) const
{
    if (e == 0) {
        return 1;
    }
    if (e == 1) {
        return *this;
    }
#if 0
    if (*this == 2) {
        return twoPower(e);
    }
#endif
    BigInteger base = *this;
    BigInteger result = 1;
    while (e) {
        if (e & 1) {
            result *= base;
        }
        e >>= 1;
        base *= base;
    }

    return result;
}

BigInteger BigInteger::powerMod(BigInteger e, const BigInteger& m)
{
    BigInteger t(*this);
    BigInteger result = 1;
    while (!e.isZero() && !e.isNegative()) {
        if (!e.isEven()) {
            result *= t;
            result %= m;
        }
        t = (t * t) % m;
        e /= 2;
    }
    return result;
}

BigInteger BigInteger::twoPower(long long e)
{
#if 1
    return kTwo.power(e);
#else
    return kOne << e;
#endif
}

BigInteger BigInteger::operator>>(int e) const
{
    if (e <= 3) {
        return operator/(static_cast<int>(pow(2, e)));
    }
    return BigInteger(bin() >> e);
}

BigInteger BigInteger::operator<<(int e) const
{
    if (e <= 3) {
        return operator*(static_cast<int>(pow(2, e)));
    }
    return BigInteger(bin() << e);
}

BigInteger BigInteger::operator|(int e) const
{
    return BigInteger(bin() | BigIntegerBitSet(e));
}

BigInteger BigInteger::operator&(int e) const
{
    return BigInteger(bin() & BigIntegerBitSet(e));
}

BigInteger BigInteger::operator^(int e) const
{
    return BigInteger(bin() ^ BigIntegerBitSet(e));
}

// ------------------------------------ short hand operators ---------------------

BigInteger& BigInteger::operator+=(const BigInteger& other)
{
    BigInteger b = *this + other;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator-=(const BigInteger& other)
{
    BigInteger b = *this - other;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator*=(const BigInteger& other)
{
    BigInteger b = *this * other;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator/=(const BigInteger& d)
{
    BigInteger b = *this / d;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator%=(const BigInteger& d)
{
    BigInteger b = *this % d;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator^=(int e)
{
    BigInteger b = *this ^ e;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator>>=(int e)
{
    BigInteger b = *this >> e;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator<<=(int e)
{
    BigInteger b = *this << e;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator&=(int e)
{
    BigInteger b = *this & e;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator|=(int e)
{
    BigInteger b = *this | e;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

// ----------------------------- properties ----------------------------------------

bool BigInteger::is1er() const
{
    if (m_data.empty()) {
        return false;
    }
    auto iter = std::find_if_not(m_data.begin() + 1, m_data.end(), [&](int x) {
        return x == 0;
    });
    return m_data[0] == 1 && iter == m_data.end();
}

bool BigInteger::isZero() const
{
    auto iter = std::find_if_not(m_data.begin(), m_data.end(), [&](int x) {
        return x == 0;
    });
    return iter == m_data.end();
}

bool BigInteger::isEven() const
{
    return m_data[m_data.size() - 1] % 2 == 0;
}

unsigned int BigInteger::bitCount() const
{
    auto b = bin();
    unsigned int bits = 0;
    while (b.any()) {
        bits++;
        b >>= 1;
    }
    return bits;
}

// ----------------------------- comparison ----------------------------------------

int BigInteger::compare(const BigInteger& other) const
{
    if (!m_negative && other.m_negative) {
        return 1;
    }
    if (m_negative && !other.m_negative) {
        return -1;
    }

    int flag = 1;
    if (m_negative && other.m_negative) {
        flag = -1;
    }

    if (digits() < other.digits()) {
        return -1 * flag;
    }
    if (digits() > other.digits()) {
        return flag;
    }
    for (std::size_t i = 0; i < digits(); ++i) {
        if (m_data[i] < other.m_data[i]) {
            return -1 * flag;
        }
        if (m_data[i] > other.m_data[i]) {
            return flag;
        }
    }

    return 0;
}

bool BigInteger::operator>(const BigInteger& other) const
{
    return compare(other) == 1;
}

bool BigInteger::operator<(const BigInteger& other) const
{
    return compare(other) == -1;
}

bool BigInteger::operator<=(const BigInteger& other) const
{
    return *this == other || compare(other) == -1;
}

bool BigInteger::operator>=(const BigInteger& other) const
{
    return *this == other || compare(other) == 1;
}

// ----------------------------- conversion ----------------------------------------

std::string BigInteger::str() const
{
    std::ostringstream ss;
    if (m_negative) {
        ss << "-";
    }
    std::copy(m_data.begin(), m_data.end(), std::ostream_iterator<int>(ss));
    return ss.str();
}

std::string BigInteger::hex() const
{
    // we avoid Base16::encode<BigInteger>(*this)
    // as we can use divide for faster division
    std::stringstream ss;
    BigInteger n(*this);
    BigInteger q, r;
    while (!n.isZero()) {
        n.divide(kSixteen, q, r);
        n = std::move(q);
        ss << Base16::kValidChars[static_cast<int>(r)];
    }
    std::string res(ss.str());
    std::reverse(res.begin(), res.end());
    return res;
}

BigInteger::BigIntegerBitSet BigInteger::bin() const
{
    BigIntegerBitSet result;
    BigInteger next(m_data);
    BigInteger r, q;
    std::size_t i = 0;
    while (!next.isZero()) {
        next.divide(2, q, r);
        result[i++] = !r.isZero();
        next = std::move(q);
    }
    return result;
}

long long BigInteger::toLong() const
{
    std::ostringstream ss;
    std::copy(m_data.begin(), m_data.end(), std::ostream_iterator<int>(ss));
    return std::stol(ss.str()) * (m_negative ? -1 : 1);
}

unsigned long long BigInteger::toULongLong() const
{
    std::ostringstream ss;
    std::copy(m_data.begin(), m_data.end(), std::ostream_iterator<int>(ss));
    return std::stoull(ss.str());
}
