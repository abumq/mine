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

#include <sstream>
#include <cmath>
#include "src/big-integer.h"

using namespace mine;

BigInteger::BigInteger() : m_negative(false)
{
    m_data.push_back(0);
}

BigInteger::BigInteger(const BigInteger& other)
{
    m_data = other.m_data;
    m_negative = other.m_negative;
}

BigInteger::BigInteger(BigInteger&& other)
{
    m_data = std::move(other.m_data);
    m_negative = other.m_negative;
    other.m_data.push_back(0);
    other.m_negative = false;
}

BigInteger& BigInteger::operator=(const BigInteger& other)
{
    if (this != &other) {
        m_data = other.m_data;
        m_negative = other.m_negative;
    }
    return *this;
}

BigInteger::BigInteger(long long n)
{
    init(n);
}

BigInteger::BigInteger(const std::string& n)
{
    init(n);
}


BigInteger& BigInteger::operator=(long long n)
{
    init(n);
    return *this;
}

BigInteger& BigInteger::operator=(const std::string& n)
{
    init(n);
    return *this;
}

void BigInteger::init(long long n)
{
    if (n < 0) {
        m_negative = true;
        n = -n;
    } else {
        m_negative = false;
    }
    m_data.clear();
    do {
        m_data.insert(m_data.begin(), n % 10);
        n /= 10;
    } while (n);
}

void BigInteger::init(const std::string& n)
{
    if (n.empty()) {
        throw std::invalid_argument("Invalid number");
    }
    m_negative = n[0] == '-';
    int beginOffset = m_negative ? 1 : 0;

    m_data.clear();

    bool firstNonZeroDigitFound = false;
    for (auto it = n.begin() + beginOffset; it < n.end(); ++it) {
        char c = *it;
        if (!isnumber(c)) {
            throw std::invalid_argument("Invalid number");
        }
        if (c == '0' && !firstNonZeroDigitFound) {
            continue;
        }
        firstNonZeroDigitFound = true;
        m_data.push_back(static_cast<int>(c) - '0');
    }
}

BigInteger BigInteger::operator+(const BigInteger& other)
{
    if ((m_negative || other.m_negative) && m_negative != other.m_negative) {
        // we have negation instead of addition in reality
        return *this - other;
    }
    Container result(std::max(m_data.size(), other.m_data.size()) + 1);
    int carry = 0;

    const Container* first = m_data.size() > other.m_data.size() ? &m_data : &other.m_data;
    const Container* second = m_data.size() > other.m_data.size() ? &other.m_data : &m_data;

    std::size_t i = result.size() - 1;
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
        result[i--] = z;
    }

    result[0] = carry;

    if (result[0] == 0) {
        result.erase(std::find_if_not(result.begin(), result.end(), [&](int c) -> bool {
            return c > 0;
        }));
    }

    return BigInteger(result);
}

BigInteger& BigInteger::operator+=(const BigInteger& other)
{
    BigInteger b = *this + other;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator++()
{
    *this += BigInteger(1);
    return *this;
}

BigInteger BigInteger::operator-(const BigInteger& other)
{
    BigInteger result;
    return result;
}

BigInteger& BigInteger::operator-=(const BigInteger& other)
{
    BigInteger b = *this - other;
    m_data = std::move(b.m_data);
    m_negative = b.m_negative;
    return *this;
}

BigInteger& BigInteger::operator--()
{
    *this -= BigInteger(1);
    return *this;
}

BigInteger BigInteger::operator*(const BigInteger& other)
{
    if (isZero() || other.isZero()) {
        return BigInteger(0);
    }
    BigInteger result;
    return result;
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

std::string BigInteger::str() const
{
    std::ostringstream ss;
    std::copy(m_data.begin(), m_data.end(), std::ostream_iterator<int>(ss));
    return ss.str();
}

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

    if (m_data.size() < other.m_data.size()) {
        return -1 * flag;
    }
    if (m_data.size() > other.m_data.size()) {
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
