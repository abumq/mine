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
/// This operates on base-10 atm. Not for other uses as it does not contain
/// all the operators implemented. only the ones needed for Mine RSA
///
/// ******************* THIS IS NOT PRODUCTION READY YET!!! **********************
/// ******************** DESIGN IS SUBJECT TO CHANGE ****************************
///
class BigInteger {
    using Container = std::vector<int>;
public:
    const static BigInteger kZero;
    const static BigInteger kOne;
    const static BigInteger kMinusOne;
    const static BigInteger kTwoFiftySix;

    BigInteger();
    BigInteger(const BigInteger& other);
    BigInteger(const Container& d);
    BigInteger(BigInteger&& other);
    BigInteger& operator=(const BigInteger& other);
    BigInteger(int);
    BigInteger(const std::string&);
    virtual ~BigInteger() = default;

    // construct -----------------------------------------------------------
    void init(int);
    void init(const std::string&);
    inline void checkAndFixData()
    {
        if (m_data.empty()) {
            m_data.push_back(0);
            m_negative = false;
        }
    }

    // assign ---------------------------------------------------------------
    BigInteger& operator=(int);
    BigInteger& operator=(const std::string&);

    // maths ---------------------------------------------------------------

    // addition
    BigInteger operator+(const BigInteger& other) const;
    BigInteger& operator+=(const BigInteger& other);

    // subtraction
    BigInteger operator-(const BigInteger& other) const;
    BigInteger& operator-=(const BigInteger& other);

    // multiply
    BigInteger operator*(const BigInteger& other) const;
    BigInteger& operator*=(const BigInteger& other);

    // divide
    static void divide(const BigInteger& divisor, const BigInteger& divident, BigInteger& q, BigInteger& r);
    void divide(const BigInteger& divident, BigInteger& q, BigInteger& r) const;
    BigInteger operator/(const BigInteger& other) const;
    BigInteger& operator/=(const BigInteger& other);

    BigInteger operator%(const BigInteger& other) const;
    BigInteger& operator%=(const BigInteger& other);

    // power
    BigInteger operator^(long e) const;
    BigInteger& operator^=(long e);

    BigInteger operator>>(int e) const;
    BigInteger operator<<(int e) const;
    bool operator&(int e) const;
    BigInteger operator|(int e) const;

    // compare ---------------------------------------------------------------
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

    // properties ---------------------------------------------------------------
    inline bool isNegative() const { return m_negative; }
    inline std::size_t digits() const { return m_data.size(); }
    inline bool isZero() const;
    unsigned long bitCount() const;

    ///
    /// \return Whether it's 1, 10, 100, 1000, ...
    ///
    bool is1er() const;

    // conversion ---------------------------------------------------------------

    inline int base() const { return m_base; }
    std::string str() const;
    std::string hex() const;
    long long toLong() const;
    unsigned long long toULongLong() const;
    explicit operator long long() const { return toLong(); }
    explicit operator unsigned long long() const { return toULongLong(); }
    explicit operator int() const { return static_cast<int>(toLong()); }

    friend inline std::ostream& operator<<(std::ostream& os, const BigInteger& b)
    {
        os << b.str();
        return os;
    }
private:
    bool m_negative;
    Container m_data;
    int m_base;

    int compare(const BigInteger&) const;
};

} // end namespace mine

#endif // BIG_INTEGER_H
