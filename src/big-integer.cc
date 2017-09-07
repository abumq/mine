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

bool BigInteger::is1er() const
{
    if (m_data.empty()) {
        return false;
    }
    bool firstIsOne = m_data[0] == 1;
    auto iter = std::find_if_not(m_data.begin() + 1, m_data.end(), [&](int x) {
        return x == 0;
    });
    bool allRestZero = iter == m_data.end();
    return firstIsOne && allRestZero;
}

BigInteger BigInteger::operator+(const BigInteger& other)
{
    if ((m_negative || other.m_negative) && m_negative != other.m_negative) {
        // we have negation instead of addition in reality
        BigInteger otherCopy(other);
        if (otherCopy.m_negative) {
            otherCopy.m_negative = false;
        }
        return *this - otherCopy;
    } else if (other.isZero()) {
        return *this;
    } else if (isZero()) {
        return other;
    }

    Container data(std::max(m_data.size(), other.m_data.size()) + 1);

    const Container* first = m_data.size() >= other.m_data.size() ? &m_data : &other.m_data;
    const Container* second = m_data.size() >= other.m_data.size() ? &other.m_data : &m_data;

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
    if (other.isZero()) {
        return *this;
    } else if (isZero()) {
        BigInteger result(other);
        result.m_negative = true;
        return result;
    }
    if (m_negative && other.m_negative) {
        // we have addition instead of subtraction in reality
        return *this + other;
    }
    Container data;
    bool neg = *this < other;

    const Container* first = m_data.size() >= other.m_data.size() ? &m_data : &other.m_data;
    const Container* second = m_data.size() >= other.m_data.size() ? &other.m_data : &m_data;

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

    BigInteger result(data);
    result.m_negative = neg;
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
/*
BigInteger BigInteger::operator*(const BigInteger& other)
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
}*/

// we use temp this and then fix the one above (commented one)
BigInteger BigInteger::operator*(const BigInteger& other)
{
    if (other.is1er()) {
        m_negative = (m_negative || other.m_negative) && m_negative != other.m_negative;
        m_data.resize(m_data.size() + other.m_data.size() - 1, 0);
        return *this;
    } else if (*this >= 0 && other >= 0 && *this < 10 && other < 10) {
        if (m_data.empty() || other.m_data.empty()) {
            return BigInteger(0);
        }
        return BigInteger(m_data[0] * other.m_data[0]);
    } else if (isZero() || other.isZero()) {
        return BigInteger(0);
    }
    std::vector<BigInteger> tmps;
    const Container* first = m_data.size() >= other.m_data.size() ? &m_data : &other.m_data;
    const Container* second = m_data.size() >= other.m_data.size() ? &other.m_data : &m_data;
    for (auto its = second->rbegin(); its < second->rend(); ++its) {
        Container dataTmp;
        int carry = 0;
        for (auto itf = first->rbegin(); itf < first->rend(); ++itf) {
            int x = *its;
            int y = *itf;
            int z = (x * y) + carry;
            if (z < 10 || itf >= first->rend() - 1) {
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
    int i = 0;
    for (BigInteger b : tmps) {
        result += b * pow(10, i);
        i++;
    }

    result.m_negative = (m_negative || other.m_negative) && m_negative != other.m_negative;
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
    if (m_negative) {
        ss << "-";
    }
    std::copy(m_data.begin(), m_data.end(), std::ostream_iterator<int>(ss));
    return ss.str();
}

long long BigInteger::toLong() const
{
    return std::stol(str()) * (m_negative ? -1 : 1);
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
