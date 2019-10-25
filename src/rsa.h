//
//  rsa.h
//  Part of Mine crypto library
//
//  You should not use this file, use mine.h
//  instead which is automatically generated and includes this file
//  This is seperated to aid the development
//
//  Copyright (c) 2017-present Amrayn Web Services
//
//  This library is released under the Apache 2.0 license
//  https://github.com/amrayn/mine/blob/master/LICENSE
//
//  https://github.com/amrayn/mine
//  https://amrayn.com
//

#ifdef MINE_CRYPTO_H
#   error "Please use mine.h file. this file is only to aid the development"
#endif

#ifndef RSA_H
#define RSA_H

#include <cmath>
#include <iostream>
#include <stdexcept>
#include <map>
#include <string>
#include <sstream>
#include <vector>
#include "src/base16.h"
#include "src/mine-common.h"

namespace mine {

/// Here onwards start implementation for RSA - this contains
/// generic classes (templates).
/// User will provide their own implementation of big integer
/// or use existing one.
///
/// Compliant with PKCS#1 (v2.1)
/// https://tools.ietf.org/html/rfc3447#section-7.2
///
/// Big integer must support have following functions implemented
///  -  operator-() [subtraction]
///  -  operator+() [addition]
///  -  operator+=() [short-hand addition]
///  -  operator*() [multiply]
///  -  operator/() [divide]
///  -  operator%() [mod]
///  -  operator>>() [right-shift]
///
/// Also you must provide proper implementation to Helper class
/// which will extend MathHelper and must implement
/// <code>MathHelper<BigIntegerT>::bigIntegerToByte</code>
/// function. The base function returns empty byte.
///


///
/// \brief Default exponent for RSA public key
///
static const unsigned int kDefaultPublicExponent = 65537;

///
/// \brief Simple raw string (a.k.a octet string)
///
using RawString = ByteArray;

///
/// \brief Contains helper functions for RSA throughout
///
template <class BigIntegerT>
class MathHelper {
public:

    static const BigIntegerT kBigIntegerT256;

    MathHelper() = default;
    virtual ~MathHelper() = default;

    ///
    /// \brief Implementation inverse mod
    ///
    virtual BigIntegerT modInverse(BigIntegerT a, BigIntegerT m) const
    {
        BigIntegerT x, y;
        BigIntegerT gcdResult = gcdExtended(a, m, &x, &y);
        if (gcdResult != 1) {
            throw std::invalid_argument("Inverse does not exist");
        }
        /*std::cout << x << std::endl;
        std::cout << (x % m) << std::endl;
        std::cout << (x % m) + m << std::endl;
        std::cout << ((x % m) + m) % m << std::endl;*/
        return ((x % m) + m) % m;
    }

    ///
    /// \brief Fast GCD
    ///
    virtual BigIntegerT gcd(BigIntegerT a, BigIntegerT b) const
    {
        BigIntegerT c;
        while (a != 0) {
            c = a;
            a = b % a;
            b = c;
        }
        return b;
    }

    ///
    /// \brief Extended GCD
    /// \see https://en.wikipedia.org/wiki/Euclidean_algorithm#Extended_Euclidean_algorithm
    ///
    virtual BigIntegerT gcdExtended(BigIntegerT a, BigIntegerT b, BigIntegerT* x, BigIntegerT* y) const
    {
        // Base case
        if (a == 0)
        {
            *x = 0, *y = 1;
            return b;
        }

        BigIntegerT x1, y1;
        BigIntegerT gcd = gcdExtended(b % a, a, &x1, &y1);

        /*std::cout << y1 << " - " << ((b / a) * x1) << " = " << (y1 - ((b / a) * x1)) << std::endl;
        std::cout << std::endl;*/
        *x = y1 - ((b / a) * x1);
        *y = x1;

        return gcd;
    }

    ///
    /// \brief Simple (b ^ e) mod m implementation
    /// \param b Base
    /// \param e Exponent
    /// \param m Mod
    ///
    virtual BigIntegerT powerMod(BigIntegerT b, BigIntegerT e, const BigIntegerT& m) const
    {
        BigIntegerT res = 1;
        while (e > 0) {
            if (e % 2 != 0) {
                res = (b * res) % m;
            }
            b = (b * b) % m;
            e /= 2;
        }
        return res;
    }

    ///
    /// \brief Power of numb i.e, b ^ e
    ///
    virtual BigIntegerT power(BigIntegerT b, BigIntegerT e) const
    {
        BigIntegerT result = 1;
        while (e > 0) {
            if (e % 2 == 1) {
                // we decrement exponent to make it even
                e = e - 1;
                // store this multiplication directly to the
                // result
                result *= b;
                // we modify this alg to ignore the next multiplication
                // if we have already reached 0 (for speed)
                // here are details and what we changed and how it all works
                //
                // Let's say we have case of 2 ^ 4 [expected answer = 16]
                // 2 ^ 4 -- b = 4, e = 2 [result = 1]
                // 2 ^ 2 -- b = 16, e = 1 [result = 1]
                // 2 ^ 1 -- e = 0 [result = 1 * 16]
                //
                // here is what we changed here
                // now we have result set and we have e set to zero
                // doing another b ^= b means b = 16 * 16 = 256 (in our case)
                // which is useless so we end here
                if (e == 0) {
                    break;
                }
            }
            e /= 2;
            b *= b;
        }
        return result;
    }

    ///
    /// \brief Counts number of bits in big integer
    ///
    virtual unsigned int countBits(const BigIntegerT& b) const
    {
        BigIntegerT bc(b);
        unsigned int bits = 0;
        while (bc > 0) {
            bits++;
            bc = bc >> 1;
        }
        return bits;
    }

    ///
    /// \brief Count number of bytes in big integer
    ///
    virtual inline unsigned int countBytes(const BigIntegerT& b) const
    {
        return countBits(b) * 8;
    }

    ///
    /// Raw-string to integer (a.k.a os2ip)
    ///
    BigIntegerT rawStringToInteger(const RawString& x) const
    {
        BigIntegerT result = 0;
        std::size_t len = x.size();
        for (std::size_t i = len; i > 0; --i) {
            result += BigIntegerT(x[i - 1]) * power(kBigIntegerT256, BigIntegerT(static_cast<unsigned long long>(len - i)));
        }
        return result;
    }

    ///
    /// \brief Convert integer to raw string
    /// (this func is also known as i2osp)
    ///
    RawString integerToRaw(BigIntegerT x, int xlen = -1) const
    {
        xlen = xlen == -1 ? countBytes(x) : xlen;

        RawString ba(xlen);
        BigIntegerT r;
        BigIntegerT q;

        int i = 1;

        for (; i <= xlen; ++i) {
            divideBigInteger(x, power(kBigIntegerT256, BigIntegerT(xlen - i)), &q, &r);
            ba[i - 1] = bigIntegerToByte(q);
            x = r;
        }
        return ba;
    }

    ///
    /// \brief Divides big number
    /// You may override this function and call custom divisor from big integer class
    /// you are using.
    /// Result should be stored in quotient and remainder
    ///
    virtual void divideBigInteger(const BigIntegerT& divisor, const BigIntegerT& divident,
                                        BigIntegerT* quotient, BigIntegerT* remainder) const
    {
        *quotient = divisor / divident;
        *remainder = divisor % divident;
    }

    ///
    /// \brief Absolutely must override this - conversion from x to single byte
    ///
    virtual inline byte bigIntegerToByte(const BigIntegerT&) const
    {
        return static_cast<byte>(0);
    }

    ///
    /// \brief Converts big integer to hex
    ///
    virtual std::string bigIntegerToHex(BigIntegerT n) const
    {
        return Base16::encode(n);
    }

    ///
    /// \brief Converts big integer to hex
    ///
    virtual std::string bigIntegerToString(const BigIntegerT& b) const
    {
        std::stringstream ss;
        ss << b;
        return ss.str();
    }

    ///
    /// \brief Converts hex to big integer
    /// \param hex Hexadecimal without '0x' prefix
    ///
    virtual BigIntegerT hexToBigInteger(const std::string& hex) const
    {
        std::string readableMsg = "0x" + hex;
        return BigIntegerT(readableMsg.c_str());
    }
private:
    MathHelper(const MathHelper&) = delete;
    MathHelper& operator=(const MathHelper&) = delete;
};

///
/// \brief Big Integer = 256 (static declaration)
///
template <typename BigIntegerT>
const BigIntegerT MathHelper<BigIntegerT>::kBigIntegerT256 = 256;

template <class BigIntegerT, class Helper = MathHelper<BigIntegerT>>
class GenericBaseKey {
public:
    GenericBaseKey() = default;
    virtual ~GenericBaseKey() = default;

    inline std::size_t emBits() const { return (m_helper.countBits(m_n) + 7) >> 3; }
    inline std::size_t modBits() const { return 8 * m_k; }

    inline BigIntegerT n() const { return m_n; }
    inline unsigned int k() const { return m_k; }
    inline virtual bool empty() const = 0;

    void init(const BigIntegerT& n)
    {
        m_n = n;
        m_k = m_helper.countBytes(m_n);
        if (m_k < 11) {
            throw std::invalid_argument("Invalid prime. Length error.");
        }
    }

protected:
    BigIntegerT m_n;
    unsigned int m_k;
    Helper m_helper;
};

///
/// \brief Public key object with generic big integer
///
template <class BigIntegerT, class Helper = MathHelper<BigIntegerT>>
class GenericPublicKey : public GenericBaseKey<BigIntegerT, Helper> {
    using BaseKey = GenericBaseKey<BigIntegerT, Helper>;
public:

    GenericPublicKey() = default;

    GenericPublicKey(const GenericPublicKey& other)
    {
        this->m_n = other.m_n;
        this->m_e = other.m_e;
        this->m_k = other.m_k;
    }

    GenericPublicKey& operator=(const GenericPublicKey& other)
    {
        if (this != &other) {
            this->m_n = other.m_n;
            this->m_e = other.m_e;
            this->m_k = other.m_k;
        }
        return *this;
    }

    GenericPublicKey(BigIntegerT n, int e)
    {
        init(n, e);
    }

    void init(const BigIntegerT& n, int e = kDefaultPublicExponent)
    {
        BaseKey::init(n);
        m_e = e;
    }

    virtual ~GenericPublicKey() = default;

    inline int e() const { return m_e; }
    inline virtual bool empty() const { return m_e == 0 || BaseKey::m_n == 0; }

protected:
    int m_e;
};

///
/// \brief Private key object with generic big integer
///
template <class BigIntegerT, class Helper = MathHelper<BigIntegerT>>
class GenericPrivateKey : public GenericBaseKey<BigIntegerT, Helper> {
    using BaseKey = GenericBaseKey<BigIntegerT, Helper>;
public:

    GenericPrivateKey() = default;

    GenericPrivateKey(const GenericPrivateKey& other)
    {
        this->m_p = other.m_p;
        this->m_q = other.m_q;
        this->m_e = other.m_e;
        this->m_n = other.m_n;
        this->m_d = other.m_d;
        this->m_coeff = other.m_coeff;
        this->m_dp = other.m_dp;
        this->m_dq = other.m_dq;
        this->m_k = other.m_k;
    }

    GenericPrivateKey& operator=(const GenericPrivateKey& other)
    {
        if (this != &other) {
            this->m_p = other.m_p;
            this->m_q = other.m_q;
            this->m_e = other.m_e;
            this->m_n = other.m_n;
            this->m_d = other.m_d;
            this->m_coeff = other.m_coeff;
            this->m_dp = other.m_dp;
            this->m_dq = other.m_dq;
            this->m_k = other.m_k;
        }
        return *this;
    }

    GenericPrivateKey(const BigIntegerT& p, const BigIntegerT& q, int e = kDefaultPublicExponent)
    {
        init(p, q, e);
    }

    void init(const BigIntegerT& p, const BigIntegerT& q, int e = kDefaultPublicExponent)
    {
        if (p == q || p == 0 || q == 0) {
            throw std::invalid_argument("p and q must be prime numbers unique to each other");
        }
        m_p = p;
        m_q = q;
        m_e = e;

        const BigIntegerT pMinus1 = m_p - 1;
        const BigIntegerT qMinus1 = m_q - 1;
        const BigIntegerT phi = pMinus1 * qMinus1;

        if (BaseKey::m_helper.gcd(m_e, phi) != 1) {
            throw std::invalid_argument("Invalid exponent, it must not share factor with phi");
        }
        BaseKey::m_n = m_p * m_q;
        m_k = BaseKey::m_helper.countBytes(BaseKey::m_n);
        if (m_k < 11) {
            throw std::invalid_argument("Invalid prime. Length error.");
        }
        m_coeff = BaseKey::m_helper.modInverse(m_q, m_p);

        m_d = BaseKey::m_helper.modInverse(m_e, phi);

        // note:
        // https://tools.ietf.org/html/rfc3447#section-2 says to use m_e
        // openssl says to use m_d - which one?!
        //
        m_dp = BigIntegerT(m_d) % pMinus1;
        m_dq = BigIntegerT(m_d) % qMinus1;
    }

    virtual ~GenericPrivateKey() = default;

    inline BigIntegerT p() const { return m_p; }
    inline BigIntegerT q() const { return m_q; }
    inline BigIntegerT coeff() const { return m_coeff; }
    inline int e() const { return m_e; }
    inline BigIntegerT d() const { return m_d; }
    inline BigIntegerT dp() const { return m_dq; }
    inline BigIntegerT dq() const { return m_dp; }
    inline virtual bool empty() const { return m_p == 0 || m_q == 0; }

    friend std::ostream& operator<<(std::ostream& ss, const GenericPrivateKey<BigIntegerT, Helper>& k)
    {
        ss << "modulus: " << k.m_n << "\npublicExponent: " << k.m_e << "\nprivateExponent: " << k.m_d
           << "\nprime1: " << k.m_p << "\nprime2: " << k.m_q << "\nexponent1: " << k.m_dp << "\nexponent2: "
           << k.m_dq << "\ncoefficient: " << k.m_coeff;
        return ss;
    }

    ///
    /// \brief You can use this to export the key via
    /// openssl-cli using
    ///     openssl asn1parse -genconf exported.asn -out imp.der
    ///     openssl rsa -in imp.der -inform der -text -check
    ///   save the private key as pri.pem
    ///   export public key from it using
    ///     openssl rsa -in pri.pem -pubout > pub.pub
    ///
    virtual std::string exportASNSequence() const
    {
        std::stringstream ss;
        ss << "asn1=SEQUENCE:rsa_key\n\n";
        ss << "[rsa_key]\n";
        ss << "version=INTEGER:0\n";
        ss << "modulus=INTEGER:" << BaseKey::m_helper.bigIntegerToString(BaseKey::m_n) << "\n";
        ss << "pubExp=INTEGER:" << m_e << "\n";
        ss << "privExp=INTEGER:" << BaseKey::m_helper.bigIntegerToString(m_d) << "\n";
        ss << "p=INTEGER:" << BaseKey::m_helper.bigIntegerToString(m_p) << "\n";
        ss << "q=INTEGER:" << BaseKey::m_helper.bigIntegerToString(m_q) << "\n";
        ss << "e1=INTEGER:" << BaseKey::m_helper.bigIntegerToString(m_dp) << "\n";
        ss << "e2=INTEGER:" << BaseKey::m_helper.bigIntegerToString(m_dq) << "\n";
        ss << "coeff=INTEGER:" << BaseKey::m_helper.bigIntegerToString(m_coeff);
        return ss.str();
    }
protected:
    BigIntegerT m_p;
    BigIntegerT m_q;
    int m_e;
    BigIntegerT m_coeff;
    BigIntegerT m_d;
    BigIntegerT m_dp;
    BigIntegerT m_dq;
    unsigned int m_k;
};

///
/// \brief Key pair (containing public and private key objects) with generic big integer
///
template <class BigIntegerT, class Helper = MathHelper<BigIntegerT>>
class GenericKeyPair {
public:
    GenericKeyPair() = default;

    GenericKeyPair(const GenericKeyPair& other)
    {
        this->m_privateKey = other.m_privateKey;
        this->m_publicKey = other.m_publicKey;
    }

    GenericKeyPair& operator=(const GenericKeyPair& other)
    {
        if (this != &other) {
            this->m_privateKey = other.m_privateKey;
            this->m_publicKey = other.m_publicKey;
        }
        return *this;
    }

    GenericKeyPair(const BigIntegerT& p, const BigIntegerT& q, unsigned int exp = kDefaultPublicExponent)
    {
        init(p, q, exp);
    }

    void init(const BigIntegerT& p, const BigIntegerT& q, unsigned int exp = kDefaultPublicExponent)
    {
        m_publicKey = GenericPublicKey<BigIntegerT, Helper>(p * q, exp);
        m_privateKey = GenericPrivateKey<BigIntegerT, Helper>(p, q, exp);
    }

    virtual ~GenericKeyPair() = default;

    inline const GenericPublicKey<BigIntegerT, Helper>* publicKey() const { return &m_publicKey; }
    inline const GenericPrivateKey<BigIntegerT, Helper>* privateKey() const { return &m_privateKey; }

protected:
    GenericPublicKey<BigIntegerT, Helper> m_publicKey;
    GenericPrivateKey<BigIntegerT, Helper> m_privateKey;
};

///
/// \brief Provides RSA crypto functionalities
///
template <class BigIntegerT, class Helper = MathHelper<BigIntegerT>>
class GenericRSA {
public:

    using PublicKey = GenericPublicKey<BigIntegerT, Helper>;
    using PrivateKey = GenericPrivateKey<BigIntegerT, Helper>;

    GenericRSA() = default;
    GenericRSA(const GenericRSA&) = delete;
    GenericRSA& operator=(const GenericRSA&) = delete;

    ///
    /// \brief Helper method to encrypt wide-string messages using public key.
    /// \see encrypt<T>(const GenericPublicKey<BigIntegerT>* publicKey, const T& m)
    ///
    inline std::string encrypt(const PublicKey* publicKey,
                               const std::wstring& message)
    {
        return encrypt<decltype(message)>(publicKey, message);
    }

    ///
    /// \brief Helper method to encrypt std::string messages using public key.
    /// \see encrypt<T>(const GenericPublicKey<BigIntegerT>* publicKey, const T& m)
    ///
    inline std::string encrypt(const PublicKey* publicKey,
                               const std::string& message)
    {
        return encrypt<decltype(message)>(publicKey, message);
    }

    ///
    /// \brief Encrypts plain bytes using RSA public key
    /// \param publicKey RSA Public key for encryption
    /// \param m The message. This can be raw bytes or plain text
    /// T can of std::string or std::wstring or custom string type that has
    /// basic_stringstream implementation alongside it
    /// \note Mine uses pkcs#1 padding scheme
    /// \return hex of cipher
    ///
    template <class T>
    std::string encrypt(const PublicKey* publicKey, const T& m)
    {
        BigIntegerT paddedMsg = addPadding<T>(m, publicKey->emBits());
        BigIntegerT cipher = m_helper.powerMod(paddedMsg, publicKey->e(), publicKey->n());
        return m_helper.bigIntegerToHex(cipher);
    }

    ///
    /// \brief Decrypts RSA hex message using RSA private key
    /// \param privateKey RSA private key
    /// \param c Cipher in hex format (should not start with 0x)
    /// \return Plain result of TResult type
    ///
    template <class TResult = std::wstring>
    TResult decrypt(const PrivateKey* privateKey, const std::string& c)
    {
        BigIntegerT msg = m_helper.hexToBigInteger(c);
        int xlen = privateKey->emBits();
        if (msg >= m_helper.power(MathHelper<BigIntegerT>::kBigIntegerT256, BigIntegerT(xlen))) {
            throw std::runtime_error("Integer too large");
        }
        BigIntegerT decr = m_helper.powerMod(msg, privateKey->d(), privateKey->n());
        RawString rawStr = m_helper.integerToRaw(decr, xlen);
        return removePadding<TResult>(rawStr);
    }

    ///
    /// \brief Verifies signature for text using RSA public key
    /// \param message Base16 msg
    /// \param signature Base16 signature
    /// \see https://tools.ietf.org/html/rfc3447#section-8.1.2
    ///
    bool verify(const PublicKey* publicKey, const std::string& msg, const std::string& sign)
    {
        if (sign.size() != publicKey->k()) {
            //return false;
        }
        BigIntegerT signature = m_helper.rawStringToInteger(MineCommon::rawStringToByteArray(sign));
        try {
            BigIntegerT verifyPrimitive = createVerificationPrimitive(publicKey, signature);
            RawString em = m_helper.integerToRaw(verifyPrimitive, publicKey->emBits());
            return emsaPssVerify(msg, em, publicKey->modBits() - 1);
        } catch (const std::exception&) {
            return false;
        }
    }

    ///
    /// \brief Signs the message with private key
    /// \return Signature (base16)
    /// \see https://tools.ietf.org/html/rfc3447#section-8.1.1
    ///
    template <typename T>
    std::string sign(const PrivateKey* privateKey, const T& msg)
    {
        RawString encoded = emsaPssEncode(msg, privateKey->modBits() - 1);

        BigIntegerT m = m_helper.rawStringToInteger(encoded);

        BigIntegerT signPrimitive = createSignaturePrimitive(privateKey, m);
        return m_helper.integerToRaw(signPrimitive, privateKey->k());
    }

    ///
    /// \brief Maximum size of RSA block with specified key size
    /// \param keySize 2048, 1024, ...
    ///
    inline static unsigned int maxRSABlockSize(std::size_t keySize)
    {
        return (keySize / 8) - 11;
    }

    ///
    /// \brief Minimum size of RSA key to encrypt data of dataSize size
    ///
    inline static unsigned int minRSAKeySize(std::size_t dataSize)
    {
        return (dataSize + 11) * 8;
    }

private:
    Helper m_helper;

    ///
    /// \brief PKCS #1 padding
    /// \see https://tools.ietf.org/html/rfc3447#page-23
    /// \return corresponding nonnegative integer
    ///
    template <class T = std::wstring>
    BigIntegerT addPadding(const T& s, std::size_t n) {
        if (n < s.size() + 11) {
            throw std::runtime_error("Message too long");
        }
        RawString byteArray(n);
        long long i = s.size() - 1;
        while(i >= 0 && n > 0) {
            int c = static_cast<int>(s.at(i--));
            if (c <= 0x7f) {
                // utf
                byteArray[--n] = c;
            } else if (c <= 0x7ff) {
                byteArray[--n] = (c & 0x3f) | 128;
                byteArray[--n] = (c >> 6) | 192;
            } else if (c <= 0xffff) {
                // utf-16
                byteArray[--n] = (c & 0x3f) | 128;
                byteArray[--n] = ((c >> 6) & 63) | 128;
                byteArray[--n] = (c >> 12) | 224;
            } else {
                // utf-32
                byteArray[--n] = (c & 0x3f) | 128;
                byteArray[--n] = ((c >> 6) & 0x3f) | 128;
                byteArray[--n] = ((c >> 12) & 0x3f) | 128;
                byteArray[--n] = (c >> 18) | 240;
            }
        }

        // now padding i.e, 0x00 || 0x02 || PS || 0x00
        // see point #2 on https://tools.ietf.org/html/rfc3447#section-7.2.1 => EME-PKCS1-v1_5 encoding

        const int kLengthOfRandom = 127;

        byteArray[--n] = 0;

        srand(time(nullptr));
        int r = rand() % kLengthOfRandom + 1;
        while (n > 2) {
            r = 0;
            while (r == 0) {
                r = rand() % kLengthOfRandom + 1;
            }
            byteArray[--n] = r;
        }
        // first two bytes of padding are 0x2 (second) and 0x0 (first)
        byteArray[--n] = 2;
        byteArray[--n] = 0;
        return m_helper.rawStringToInteger(byteArray);
    }

    ///
    /// \brief PKCS #1 unpadding
    /// \see https://tools.ietf.org/html/rfc3447#section-4.1
    /// \return corresponding octet string of length n
    ///
    template <class T = std::wstring>
    T removePadding(const RawString& ba)
    {
        std::size_t baLen = ba.size();
        if (baLen <= 2 || ba[0] != 0 || ba[1] != 2) {
            throw std::runtime_error("Incorrect padding PKCS#1");
        }
        std::size_t i = 2; // passed first two characters (0x0 and 0x2) test
        // lets check for the <PS>

        // if we hit end while still we're still with non-zeros, it's a padding error
        // 0x0 (done) | 0x2 (done) | <PS> | 0x0
        while (ba[i] != 0) {
            if (++i >= baLen) { // already ended!
                throw std::runtime_error("Incorrect padding PKCS#1");
            }
        }
        // last zero
        ++i;

        // now we should be at the first non-zero byte
        // which is our first item, concat them as char | wchar_t

        using CharacterType = typename T::value_type;
        std::basic_stringstream<CharacterType> ss;

        for (; i < baLen; ++i) {
            // reference: http://en.cppreference.com/w/cpp/language/types -> range of values
            int c = ba[i] & 0xff;
            if (c <= 0x7f) {
                ss << static_cast<CharacterType>(c);
            } else if (c > 0xbf && c < 0xe0) {
                ss << static_cast<CharacterType>(
                          ((c & 0x1f) << 6) |
                          (ba[i+1] & 0x3f)
                      );
                ++i;
            } else if ((c < 0xbf) || (c >= 0xe0 && c < 0xf0)) { // utf-16 char
                ss << static_cast<CharacterType>(
                          ((c & 0xf) << 12) |
                          ((ba[i+1] & 0x3f) << 6) |
                          (ba[i+2] & 0x3f)
                        );
                i += 2;
            } else { // utf-32 char
                ss << static_cast<CharacterType>(
                          ((c & 0x7) << 18) |
                          ((ba[i+1] & 0x3f) << 12) |
                          ((ba[i+2] & 0x3f) << 6) |
                          (ba[i+3] & 0x3f)
                        );
                i += 3;
            }
        }
        return ss.str();
    }

    ///
    /// \brief Creates RSA VP for verification (aka rsavp1)
    /// \param signature signature representative, an integer between 0 and n - 1
    /// \return message representative, an integer between 0 and n - 1
    /// \see https://tools.ietf.org/html/rfc3447#section-5.2.2
    ///
    BigIntegerT createVerificationPrimitive(const PublicKey* publicKey, const BigIntegerT& signature)
    {
        if (signature < 0 || signature > publicKey->n() - 1) {
            throw std::runtime_error("signature representative out of range");
        }
        return m_helper.powerMod(signature, publicKey->e(), publicKey->n());
    }

    ///
    /// \brief Creates RSA SP for signing (aka rsasp1)
    /// \param signature signature representative, an integer between 0 and n - 1
    /// \return message representative, an integer between 0 and n - 1
    /// \see https://tools.ietf.org/html/rfc3447#section-5.2.2
    ///
    BigIntegerT createSignaturePrimitive(const PrivateKey* privateKey, const BigIntegerT& msg)
    {
        if (msg < 0 || msg > privateKey->n() - 1) {
            throw std::runtime_error("message representative out of range");
        }
        return m_helper.powerMod(msg, privateKey->e(), privateKey->n());
    }

    ///
    /// \see https://tools.ietf.org/html/rfc3447#section-9.1.1
    ///
    template <typename T>
    RawString emsaPssEncode(const T&, std::size_t)
    {
        return RawString();
    }

    ///
    /// \see http://tools.ietf.org/html/rfc3447#section-9.1.2
    ///
    bool emsaPssVerify(const std::string&, const RawString&, std::size_t)
    {

        return true;
    }

    // for tests
    friend class RSATest_Signature_Test;
    friend class RSATest_Decryption_Test;
    friend class RSATest_KeyAndEncryptionDecryption_Test;
    friend class RSATest_PowerMod_Test;
};

} // end namespace mine

#endif // RSA_H
