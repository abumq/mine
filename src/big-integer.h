//
//  big-integer.h
//  Part of Mine crypto library
//
//  You should not use this file, use mine.h
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

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#ifndef BIG_INTEGER_H
#define BIG_INTEGER_H

#include <iosfwd>
#include <vector>
#include <string>

namespace mine {

///
/// \brief Minimal big integer for Mine library.
///
/// This operates on base-10
///
/// ******************* THIS IS NOT PRODUCTION READY YET!!! **********************
/// ******************** DESIGN IS SUBJECT TO CHANGE ****************************
///
class BigInteger {
    using Container = std::vector<int>;
public:

    BigInteger();
    BigInteger(const BigInteger& other);
    BigInteger(const Container& d) : m_negative(false), m_data(d) {}
    BigInteger(BigInteger&& other);
    BigInteger& operator=(const BigInteger& other);
    BigInteger(long long);
    BigInteger(const std::string&);
    virtual ~BigInteger() = default;

    // construct
    void init(long long);
    void init(const std::string&);

    // assign
    BigInteger& operator=(long long);
    BigInteger& operator=(const std::string&);

    // maths
    BigInteger operator+(const BigInteger& other);
    BigInteger& operator+=(const BigInteger& other);
    BigInteger& operator++();

    BigInteger operator-(const BigInteger& other);
    BigInteger& operator-=(const BigInteger& other);
    BigInteger& operator--();

    BigInteger operator*(const BigInteger& other);

    // compare
    bool operator>(const BigInteger& other) const;
    bool operator>=(const BigInteger& other) const;
    bool operator<(const BigInteger& other) const;
    bool operator<=(const BigInteger& other) const;
    inline bool operator==(const BigInteger& other) const
    {
        return m_data == other.m_data && m_negative == other.m_negative;
    }

    inline bool operator!=(const BigInteger& other) const
    {
        return m_data != other.m_data || m_negative != other.m_negative;
    }

    // properties
    inline bool isNegative() const { return m_negative; }
    inline std::size_t digits() const { return m_data.size(); }
    inline bool isZero() const { return m_data.size() == 1 && m_data[0] == 0; }

    // string

    std::string str() const;

    friend inline std::ostream& operator<<(std::ostream& os, const BigInteger& b)
    {
        os << b.str();
        return os;
    }
private:
    bool m_negative;
    Container m_data;

    int compare(const BigInteger&) const;
};

} // end namespace mine

#endif // BIG_INTEGER_H
