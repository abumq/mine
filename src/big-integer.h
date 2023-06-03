//
//  big-integer.h
//  Part of Mine crypto library
//
//  You should not use this file, use mine.h
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright (c) 2017-present @abumq (Majid Q.)
//
//  This library is released under the Apache 2.0 license
//  https://github.com/abumq/mine/blob/master/LICENSE
//

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#ifndef BIG_INTEGER_H
#define BIG_INTEGER_H

#include <bitset>
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
    static const std::size_t kMaxSizeInBits = 4096; // todo: change to template
    using BigIntegerBitSet = std::bitset<kMaxSizeInBits>;
    using Container = std::vector<int>;
public:
    const static BigInteger kZero;
    const static BigInteger kOne;
    const static BigInteger kTwo;
    const static BigInteger kMinusOne;
    const static BigInteger kTwoFiftySix;
    const static BigInteger kSixteen;

    BigInteger();
    BigInteger(const BigInteger& other);
    BigInteger(const Container& d);
    BigInteger(const BigIntegerBitSet& d);
    BigInteger(BigInteger&& other);
    BigInteger& operator=(const BigInteger& other);
    BigInteger(int);
    BigInteger(unsigned long long);
    BigInteger(const std::string&);
    virtual ~BigInteger() = default;

    // construct -----------------------------------------------------------
    void init(int);
    void init(unsigned long long);
    void init(const std::string&);

    void checkAndFixData();

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
    BigInteger longMul(const BigInteger& other) const;
    BigInteger operator*(const BigInteger& other) const;
    BigInteger& operator*=(const BigInteger& other);

    // divide
    static void divide(BigInteger n, BigInteger d, BigInteger& q, BigInteger& r);
    void divide(const BigInteger& d, BigInteger& q, BigInteger& r) const;
    BigInteger operator/(const BigInteger& d) const;
    BigInteger& operator/=(const BigInteger& d);

    BigInteger operator%(const BigInteger& other) const;
    BigInteger& operator%=(const BigInteger& other);

    // power
    BigInteger power(long long e) const;
    static BigInteger twoPower(long long e);
    BigInteger powerMod(BigInteger e, const BigInteger& m);

    // bitwise op
    BigInteger operator>>(int e) const;
    BigInteger& operator>>=(int e);

    BigInteger operator<<(int e) const;
    BigInteger& operator<<=(int e);

    BigInteger operator&(int e) const;
    BigInteger& operator&=(int e);

    BigInteger operator|(int e) const;
    BigInteger& operator|=(int e);

    BigInteger operator^(int e) const;
    BigInteger& operator^=(int e);

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
    inline bool isEven() const;
    inline std::size_t digits() const { return m_data.size(); }
    inline bool isZero() const;
    inline bool isOne() const;
    unsigned int bitCount() const;

    ///
    /// \return Whether it's 1, 10, 100, 1000, ...
    ///
    bool is1er() const;

    // conversion ---------------------------------------------------------------
    inline BigIntegerBitSet bin() const;
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
    static void specialDivide(BigInteger n, BigInteger d, BigInteger& q, BigInteger& r);

};

} // end namespace mine

#endif // BIG_INTEGER_H
