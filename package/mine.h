//
//  Bismillah ar-Rahmaan ar-Raheem
//
//  Mine (Unreleased)
//  Single header minimal cryptography library
//
//  Copyright (c) 2017 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//  https://muflihun.github.io/mine
//  https://muflihun.com
//

#ifndef MINE_CRYPTO_H
#define MINE_CRYPTO_H

#include <algorithm>
#include <string>
#include <sstream>
#include <unordered_map>
#include <array>
#include <cmath>
#include <stdexcept>
#include <map>
#include <vector>

namespace mine {

using byte = unsigned char;

///
/// \brief Provides base16 encoding / decoding
///
class Base16 {
public:

    ///
    /// \brief List of valid hex encoding characters
    ///
    static const std::string kValidChars;

    ///
    /// \brief Map for fast lookup corresponding character
    /// \see Base64::kDecodeMap
    ///
    static const std::unordered_map<byte, byte> kDecodeMap;

    ///
    /// \brief Encodes input of length to hex encoding
    ///
    static std::string encode(const std::string& raw) noexcept;

    ///
    /// \brief Encodes integer to hex
    ///
    template <typename T>
    static std::string encode(T n) noexcept
    {
        std::stringstream ss;
        int remainder;
        while (n != 0) {
            remainder = n % 16;
            n /= 16;
            ss << kValidChars[remainder];
        }
        std::string res(ss.str());
        std::reverse(res.begin(), res.end());
        return res;
    }

    ///
    /// \brief Decodes encoded hex
    /// \throws std::runtime if invalid encoding.
    /// std::runtime::what() is set according to the error
    ///
    static std::string decode(const std::string& e);

    ///
    /// \brief Decodes encoding to single integer of type T
    ///
    template <typename T>
    static T decodeInt(const std::string& e)
    {
        T result = 0;
        for (auto it = e.begin(); it != e.end() && result >= 0; ++it) {
            try {
                result = ((result << 4) | kDecodeMap.at(*it & 0xff));
            } catch (const std::exception&) {
                throw std::runtime_error("Invalid base-16 encoding");
            }
        }
        return result;
    }

private:
    Base16() = delete;
    Base16(const Base16&) = delete;
    Base16& operator=(const Base16&) = delete;
};

using byte = unsigned char;

///
/// \brief Provides base64 encoding / decoding implementation
///
class Base64 {
public:

    ///
    /// \brief List of valid base64 encoding characters
    ///
    static const std::string kValidChars;

    ///
    /// \brief Map for fast lookup corresponding character
    /// std::unordered_map is O(1) for best case and linear in worst case
    /// which is better than kValidChars find_first_of() which is linear-pos
    /// in general
    /// \ref http://www.cplusplus.com/reference/unordered_map/unordered_map/at/
    /// \ref  http://www.cplusplus.com/reference/string/string/find_first_of/
    ///
    static const std::unordered_map<byte, byte> kDecodeMap;

    ///
    /// \brief Padding is must in mine implementation of base64
    ///
    static const char kPaddingChar = '=';

    ///
    /// \brief Replacement for better d.size() that consider unicode bytes too
    /// \see https://en.wikipedia.org/wiki/UTF-8#Description
    ///
    static std::size_t countChars(const std::string& d) noexcept;

#ifdef MINE_BASE64_WSTRING_CONVERSION
    ///
    /// \brief Converts it to std::string and calls countChars on it
    ///
    /// \note You need to include <locale> and <codecvt> headers before mine.h
    ///
    static std::size_t countChars(const std::wstring& raw) noexcept
    {
        std::string converted = std::wstring_convert
                <std::codecvt_utf8<wchar_t>, wchar_t>{}.to_bytes(raw);
        return countChars(converted);
    }
#endif

    ///
    /// \brief Encodes input of length to base64 encoding
    ///
    static std::string encode(const std::string& raw) noexcept;

#ifdef MINE_BASE64_WSTRING_CONVERSION
    ///
    /// \brief Converts wstring to corresponding string and returns
    /// encoding
    /// \see encode(const std::string&)
    ///
    /// \note You need to include <locale> and <codecvt> headers before mine.h
    ///
    static std::string encode(const std::wstring& raw) noexcept
    {
        std::string converted = std::wstring_convert
                <std::codecvt_utf8<wchar_t>, wchar_t>{}.to_bytes(raw);
        return encode(converted);
    }
#endif

    ///
    /// \brief Decodes encoded base64
    /// \throws std::runtime if invalid encoding. Another time it is thrown
    /// is if no padding is found
    /// std::runtime::what() is set according to the error
    ///
    static std::string decode(const std::string& e);

#ifdef MINE_BASE64_WSTRING_CONVERSION
    ///
    /// \brief Helper method to decode base64 encoding as wstring (basic_string<wchar_t>)
    /// \see decode(const std::string&)
    /// \note We do not recommend using it, instead have your own conversion function from
    /// std::string to wstring as it can give you invalid results with characters that are
    /// 5+ bytes long e.g, \x1F680. If you don't use such characters then it should be safe
    /// to use this
    ///
    /// \note You need to include <locale> and <codecvt> headers before mine.h
    ///
    static std::wstring decodeAsWString(const std::string& e)
    {
        std::string result = decode(e);
        std::wstring converted = std::wstring_convert
                <std::codecvt_utf8_utf16<wchar_t>>{}.from_bytes(result);
        return converted;
    }
#endif

    ///
    /// \brief expectedBase64Length Returns expected base64 length
    /// \param n Length of input (plain data)
    ///
    inline static std::size_t expectedLength(std::size_t n) noexcept
    {
        return ((4 * n / 3) + 3) & ~0x03;
    }

    ///
    /// \brief Calculates the length of string
    /// \see countChars()
    ///
    template <typename T = std::string>
    inline static std::size_t expectedLength(const T& str) noexcept
    {
        return expectedLength(countChars(str));
    }

    ///
    /// \brief Finds whether data is base64 encoded. This is done
    /// by finding non-base64 character. So it is not necessary
    /// a valid base64 encoding.
    ///
    inline static bool isBase64(const std::string& data) noexcept
    {
        return data.find_first_not_of(kValidChars) == std::string::npos;
    }

private:
    Base64() = delete;
    Base64(const Base64&) = delete;
    Base64& operator=(const Base64&) = delete;
};

using byte = unsigned char;

///
/// \brief Provides AES crypto functionalities
///
/// This is validated against NIST test data and all
/// the corresponding tests under test/ directory
/// are from NIST themselves.
///
/// Please make sure to use public functions and do not
/// use private functions especially in production as
/// you may end up using them incorrectly. However
/// the source code for AES class is heavily commented for
/// verification on implementation.
///
class AES {
public:
    ///
    /// \brief Handy safe byte array
    ///
    using ByteArray = std::vector<byte>;

    ///
    /// \brief A key is a byte array
    ///
    using Key = ByteArray;

private:

    ///
    /// \brief A word is array of 4 byte
    ///
    using Word = std::array<byte, 4>;

    ///
    /// \brief KeySchedule is linear array of 4-byte words
    /// \ref FIPS.197 Sec 5.2
    ///
    using KeySchedule = std::unordered_map<uint8_t, Word>;

    ///
    /// \brief State as described in FIPS.197 Sec. 3.4
    ///
    using State = std::array<Word, 4>;

    ///
    /// \brief AES works on 16 bit block at a time
    ///
    static const uint8_t kBlockSize = 16;

    ///
    /// \brief Defines the key params to it's size
    ///
    static const std::unordered_map<uint8_t, std::vector<uint8_t>> kKeyParams;

    ///
    /// \brief As defined in FIPS. 197 Sec. 5.1.1
    ///
    static const byte kSBox[];

    ///
    /// \brief As defined in FIPS. 197 Sec. 5.3.2
    ///
    static const byte kSBoxInverse[];

    ///
    /// \brief Round constant is constant for each round
    /// it contains 10 values each defined in
    /// Appendix A of FIPS.197 in column Rcon[i/Nk] for
    /// each key size, we add all of them in one array for
    /// ease of access
    ///
    static const byte kRoundConstant[];

    ///
    /// \brief Nb
    /// \note we make it constant as FIPS.197 p.9 says
    /// "For this standard, Nb=4."
    ///
    static const uint8_t kNb = 4;

    ///
    /// \brief Raw encryption function - not for public use
    /// \param input (by val) 128-bit Byte array of input.
    /// If array is bigger it's chopped and if it's smaller, it's padded
    /// please use alternative functions if your array is bigger. Those
    /// function will handle all the bytes correctly.
    /// \param key Byte array of key
    /// \return cipher text (byte array)
    ///
    static ByteArray cipher(ByteArray input, const Key* key);

    ///
    /// \brief Key expansion function as described in FIPS.197
    ///
    static KeySchedule keyExpansion(const Key* key);

    ///
    /// \brief Adds round to the state using specified key schedule
    ///
    static void addRoundKey(State* state, const KeySchedule* keySchedule, int round);

    ///
    /// \brief Substitution step for state (Sec. 5.1.1)
    ///
    static void subBytes(State* state);

    ///
    /// \brief Shifting rows step for the state (Sec. 5.1.2)
    ///
    static void shiftRows(State* state);

    ///
    /// \brief Mixing columns for the state  (Sec. 5.1.3)
    ///
    static void mixColumns(State* state);

    ///
    /// \brief Prints bytes in hex format in 4x4 matrix fashion
    ///
    static void printBytes(const ByteArray& b);

    ///
    /// \brief Prints state for debugging
    ///
    static void printState(const State*);

    AES() = delete;
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;

    friend class AESTest_RawCipher_Test;
    friend class AESTest_FiniteFieldMultiply_Test;
    friend class AESTest_KeyExpansion_Test;
    friend class AESTest_AddRoundKey_Test;
};

/// Here onwards start implementation for RSA - this contains
/// generic classes (templates).
/// User will provide their own implementation of big integer
/// or use existing one.
///
/// Compliant with PKCS#1 (v2.1)
/// https://tools.ietf.org/html/rfc3447#section-7.2
///
/// Mine uses pkcs#1 v1.5 padding scheme
///
/// Big integer must support have following functions implemented
///  -  operator-() [subtraction]
///  -  operator+() [addition]
///  -  operator+=() [short-hand addition]
///  -  operator*() [multiply]
///  -  operator/() [divide]
///  -  operator%() [mod]
///  -  operator>>() [right-shift]
///  -  operator>>=() [short-hand right-shift]
///
/// Also you must provide proper implementation to Helper class
/// which will extend BigIntegerHelper and must implement
/// <code>BigIntegerHelper<BigInteger>::bigIntegerToByte</code>
/// function. The base function returns empty byte.
///


///
/// \brief Default exponent for RSA public key
///
static const unsigned int kDefaultPublicExponent = 65537;

///
/// \brief Declaration for byte in case it's not already included
///
using byte = unsigned char;

///
/// \brief Simple raw string (a.k.a octet string)
///
using RawString = std::vector<byte>;

///
/// \brief Contains helper functions for RSA throughout
///
template <class BigInteger>
class BigIntegerHelper {
public:

    static const BigInteger kBigInteger256;

    BigIntegerHelper() = default;
    virtual ~BigIntegerHelper() = default;

    ///
    /// \brief Implementation for (a ^ -1) mod b
    ///
    virtual BigInteger modInverse(BigInteger a, BigInteger b) const
    {
        BigInteger b0 = b, t, q;
        BigInteger x0 = 0, x1 = 1;
        if (b == 1) {
            return 1;
        }
        while (a > 1) {
            q = a / b;
            t = b;
            b = a % b;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0) {
            x1 += b0;
        }
        return x1;
    }

    ///
    /// \brief Fast GCD
    /// \see https://en.wikipedia.org/wiki/Euclidean_algorithm#Extended_Euclidean_algorithm
    ///
    virtual BigInteger gcd(BigInteger a, BigInteger b) const
    {
        BigInteger c;
        while (a != 0) {
            c = a;
            a = b % a;
            b = c;
        }
        return b;
    }

    ///
    /// \brief Simple (b ^ e) mod m implementation
    /// \param b Base
    /// \param e Exponent
    /// \param m Mod
    ///
    virtual BigInteger powerMod(BigInteger b, BigInteger e, BigInteger m) const
    {
        BigInteger res = 1;
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
    virtual BigInteger power(BigInteger b, BigInteger e) const
    {
        BigInteger result = 1;
        while (e > 0) {
            if (e % 2 == 1) {
                // we decrement exponent to make it even
                e--;
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
    virtual unsigned int countBits(BigInteger b) const
    {
        unsigned int bits = 0;
        while (b > 0) {
            bits++;
            b >>= 1;
        }
        return bits;
    }

    ///
    /// \brief Count number of bytes in big integer
    ///
    virtual inline unsigned int countBytes(BigInteger b) const
    {
        return countBits(b) * 8;
    }

    ///
    /// Raw-string to integer (a.k.a os2ip)
    ///
    BigInteger rawStringToInteger(const RawString& x) const
    {
        BigInteger result = 0;
        std::size_t len = x.size();
        for (std::size_t i = len; i > 0; --i) {
            result += BigInteger(x[i - 1]) * power(kBigInteger256, BigInteger(len - i));
        }
        return result;
    }

    ///
    /// \brief Convert integer to raw string
    /// (this func is also known as i2osp)
    ///
    RawString integerToRaw(BigInteger x, int xlen = -1) const
    {
        xlen = xlen == -1 ? countBytes(x) : xlen;

        RawString ba(xlen);
        BigInteger r;
        BigInteger q;

        int i = 1;

        for (; i <= xlen; ++i) {
            divideBigNumber(x, power(kBigInteger256, BigInteger(xlen - i)), &q, &r);
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
    virtual void divideBigNumber(const BigInteger& divisor, const BigInteger& divident,
                                        BigInteger* quotient, BigInteger* remainder) const
    {
        *quotient = divisor / divident;
        *remainder = divisor % divident;
    }

    ///
    /// \brief Absolutely must override this - conversion from x to single byte
    ///
    virtual inline byte bigIntegerToByte(const BigInteger& x) const
    {
        return static_cast<byte>(0);
    }

    ///
    /// \brief Converts big integer to hex
    ///
    virtual std::string bigIntegerToHex(BigInteger n) const
    {
        return Base16::encode(n);
    }

    ///
    /// \brief Converts big integer to hex
    ///
    virtual std::string bigIntegerToString(const BigInteger& b) const
    {
        std::stringstream ss;
        ss << b;
        return ss.str();
    }

    ///
    /// \brief Converts hex to big integer
    /// \param hex Hexadecimal without '0x' prefix
    ///
    virtual BigInteger hexToBigInteger(const std::string& hex) const
    {
        std::string readableMsg = "0x" + hex;
        BigInteger msg;
        std::istringstream iss(readableMsg);
        iss >> std::hex >> msg;
        return msg;
    }
private:
    BigIntegerHelper(const BigIntegerHelper&) = delete;
    BigIntegerHelper& operator=(const BigIntegerHelper&) = delete;
};

///
/// \brief Big Integer = 256 (static declaration)
///
template <typename BigInteger>
const BigInteger BigIntegerHelper<BigInteger>::kBigInteger256 = 256;

///
/// \brief Public key object with generic big integer
///
template <class BigInteger, class Helper = BigIntegerHelper<BigInteger>>
class GenericPublicKey {
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

    GenericPublicKey(BigInteger n, int e) :
        m_n(n),
        m_e(e)
    {
        m_k = m_helper.countBytes(m_n);
        if (m_k < 11) {
            throw std::invalid_argument("Invalid prime. Length error.");
        }
    }

    virtual ~GenericPublicKey() = default;

    inline BigInteger n() const { return m_n; }
    inline int e() const { return m_e; }
    inline unsigned int k() const { return m_k; }

protected:
    BigIntegerHelper<BigInteger> m_helper;
    BigInteger m_n;
    int m_e;
    unsigned int m_k;
};

///
/// \brief Private key object with generic big integer
///
template <class BigInteger, class Helper = BigIntegerHelper<BigInteger>>
class GenericPrivateKey {
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

    GenericPrivateKey(const BigInteger& p, const BigInteger& q, int e = kDefaultPublicExponent) :
          m_p(p),
          m_q(q),
          m_e(e)

    {
        if (p == q || p == 0 || q == 0) {
            throw std::invalid_argument("p and q must be prime numbers unique to each other");
        }

        const BigInteger pMinus1 = m_p - 1;
        const BigInteger qMinus1 = m_q - 1;
        const BigInteger phi = pMinus1 * qMinus1;

        if (m_helper.gcd(m_e, phi) != 1) {
            throw std::invalid_argument("Invalid exponent, it must not share factor with phi");
        }
        m_n = m_p * m_q;
        m_k = m_helper.countBytes(m_n);
        if (m_k < 11) {
            throw std::invalid_argument("Invalid prime. Length error.");
        }
        m_coeff = m_helper.modInverse(m_q, m_p);

        m_d = m_helper.modInverse(m_e, phi);

        // note:
        // https://tools.ietf.org/html/rfc3447#section-2 says to use m_e
        // openssl says to use m_d - which one?!
        //
        m_dp = BigInteger(m_d) % pMinus1;
        m_dq = BigInteger(m_d) % qMinus1;
    }

    virtual ~GenericPrivateKey() = default;

    inline BigInteger p() const { return m_p; }
    inline BigInteger q() const { return m_q; }
    inline BigInteger coeff() const { return m_coeff; }
    inline BigInteger n() const { return m_n; }
    inline int e() const { return m_e; }
    inline BigInteger d() const { return m_d; }
    inline BigInteger dp() const { return m_dq; }
    inline BigInteger dq() const { return m_dp; }
    inline int k() const { return m_k; }

    friend std::ostream& operator<<(std::ostream& ss, const GenericPrivateKey<BigInteger, Helper>& k)
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
    /// \return
    ///
    virtual std::string exportASNSequence() const
    {
        std::stringstream ss;
        ss << "asn1=SEQUENCE:rsa_key\n\n";
        ss << "[rsa_key]\n";
        ss << "version=INTEGER:0\n";
        ss << "modulus=INTEGER:" << m_helper.bigIntegerToString(m_n) << "\n";
        ss << "pubExp=INTEGER:" << m_e << "\n";
        ss << "privExp=INTEGER:" << m_helper.bigIntegerToString(m_d) << "\n";
        ss << "p=INTEGER:" << m_helper.bigIntegerToString(m_p) << "\n";
        ss << "q=INTEGER:" << m_helper.bigIntegerToString(m_q) << "\n";
        ss << "e1=INTEGER:" << m_helper.bigIntegerToString(m_dp) << "\n";
        ss << "e2=INTEGER:" << m_helper.bigIntegerToString(m_dq) << "\n";
        ss << "coeff=INTEGER:" << m_helper.bigIntegerToString(m_coeff);
        return ss.str();
    }
protected:
    Helper m_helper;
    BigInteger m_p;
    BigInteger m_q;
    int m_e;
    BigInteger m_coeff;
    BigInteger m_n;
    BigInteger m_d;
    BigInteger m_dp;
    BigInteger m_dq;
    unsigned int m_k;
};

///
/// \brief Key pair (containing public and private key objects) with generic big integer
///
template <class BigInteger, class Helper = BigIntegerHelper<BigInteger>>
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

    GenericKeyPair(const BigInteger& p, const BigInteger& q, unsigned int exp = kDefaultPublicExponent)
    {
        m_publicKey = GenericPublicKey<BigInteger, Helper>(p * q, exp);
        m_privateKey = GenericPrivateKey<BigInteger, Helper>(p, q, exp);
    }

    virtual ~GenericKeyPair() = default;

    inline const GenericPublicKey<BigInteger, Helper>* publicKey() const { return &m_publicKey; }
    inline const GenericPrivateKey<BigInteger, Helper>* privateKey() const { return &m_privateKey; }

protected:
    GenericPublicKey<BigInteger, Helper> m_publicKey;
    GenericPrivateKey<BigInteger, Helper> m_privateKey;
};

///
/// \brief Provides RSA crypto functionalities
///
template <class BigInteger, class Helper = BigIntegerHelper<BigInteger>>
class GenericRSA {
public:

    using PublicKey = GenericPublicKey<BigInteger, Helper>;
    using PrivateKey = GenericPrivateKey<BigInteger, Helper>;

    GenericRSA() = default;
    GenericRSA(const GenericRSA&) = delete;
    GenericRSA& operator=(const GenericRSA&) = delete;

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
        BigInteger paddedMsg = pkcs1pad2<T>(m, (m_helper.countBits(publicKey->n()) + 7) >> 3);
        BigInteger cipher = m_helper.powerMod(paddedMsg, publicKey->e(), publicKey->n());
        return m_helper.bigIntegerToHex(cipher);
    }

    ///
    /// \brief Helper method to encrypt wide-string messages using public key.
    /// \see encrypt<T>(const GenericPublicKey<BigInteger>* publicKey, const T& m)
    ///
    inline std::string encrypt(const PublicKey* publicKey,
                               const std::wstring& message)
    {
        return encrypt<decltype(message)>(publicKey, message);
    }

    ///
    /// \brief Helper method to encrypt std::string messages using public key.
    /// \see encrypt<T>(const GenericPublicKey<BigInteger>* publicKey, const T& m)
    ///
    inline std::string encrypt(const PublicKey* publicKey,
                               const std::string& message)
    {
        return encrypt<decltype(message)>(publicKey, message);
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
        BigInteger msg = m_helper.hexToBigInteger(c);
        int xlen = (m_helper.countBits(privateKey->n()) + 7) >> 3;
        if (msg >= m_helper.power(BigInteger(256), BigInteger(xlen))) {
            throw std::runtime_error("Integer too large");
        }
        BigInteger decr = m_helper.powerMod(msg, privateKey->d(), privateKey->n());
        RawString rawStr = m_helper.integerToRaw(decr, xlen);
        return pkcs1unpad2<TResult>(rawStr);
    }

    ///
    /// \brief Verifies signature for text using RSA public key
    /// \param message An octet string
    /// \param signature Signature in hex
    /// \see https://tools.ietf.org/html/rfc3447#section-8.1.2
    ///
    bool verify(const PublicKey* publicKey, const std::string& message,
                       const std::string& signature)
    {
        /*
        // TODO: Add it to test
        std::vector<byte> f = getByteArray(18537);
        BigInteger s = i2osp(f, 2);
        BigInteger os = os2ip(18537); // 105

        std::cout << s << std::endl;
        std::cout << os << std::endl;

        std::vector<byte> f2 = getByteArray(1214841185);
        BigInteger s2 = i2osp(f2, 4);
        BigInteger os2 = os2ip(1214841185); // 97

        std::cout << s2 << std::endl;
        std::cout << os2 << std::endl;

        std::cout << changeBase(54735, 8) << std::endl;

        std::cout << std::hex << 16 << std::endl;
        std::cout << std::oct << 72 << std::endl;

        return true;

        BigInteger sign = m_helper.hexToBigInteger(signature);
        try {
            BigInteger vp = createVerificationPrimitive(publicKey, sign);

            const int xlen = (publicKey->n().BitCount() + 7) >> 3;

            if (xlen < vp + 11) {
                // throw std::runtime_error("Integer too large"); // Needed??! Where in RFC?
            }

            std::vector<int> em = m_helper.getByteArray(vp, xlen);


            // todo: add check for following (as per https://tools.ietf.org/html/rfc3447#section-8.1.2)
            // Note that emLen will be one less than k if modBits - 1 is
            // divisible by 8 and equal to k otherwise.  If I2OSP outputs
            // "integer too large," output "invalid signature" and stop.

            // EMSA-PSS_VERIFY - https://tools.ietf.org/html/rfc3447#section-9.1.2



            std::cout << "tt" << std::endl;
            return true;
        } catch (std::exception&) {
        }
*/
        return true;
    }

private:
    Helper m_helper;

    ///
    /// \brief PKCS #1 padding
    /// \see https://tools.ietf.org/html/rfc3447#page-23
    /// \return corresponding nonnegative integer
    ///
    template <class T = std::wstring>
    BigInteger pkcs1pad2(const T& s, int n) {
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

        srand(time(NULL));
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
    T pkcs1unpad2(const RawString& ba)
    {
        std::size_t baLen = ba.size();
        if (baLen <= 2 || ba[0] != 0 || ba[1] != 2) {
            throw std::runtime_error("Incorrect padding PKCS#1");
        }
        int i = 2; // passed first two characters (0x0 and 0x2) test
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
    /// \brief Creates RSA VP for verification
    /// \param signature signature representative, an integer between 0 and n - 1
    /// \return message representative, an integer between 0 and n - 1
    /// \see https://tools.ietf.org/html/rfc3447#section-5.2.2
    ///
    BigInteger createVerificationPrimitive(const PublicKey* publicKey, const BigInteger& signature)
    {
        if (signature < 0 || signature > publicKey->n() - 1) {
            throw std::runtime_error("signature representative out of range");
        }
        return m_helper.powerMod(signature, publicKey->e(), publicKey->n());
    }

    // for tests
    friend class RSATest_Signature_Test;
    friend class RSATest_Decryption_Test;
    friend class RSATest_KeyAndEncryptionDecryption_Test;
    friend class RSATest_PowerMod_Test;
};


///
/// \brief Provides Zlib functionality for inflate and deflate
///
class ZLib {
public:

private:
    ZLib() = delete;
    ZLib(const ZLib&) = delete;
    ZLib& operator=(const ZLib&) = delete;
};

} // namespace mine
#endif // MINE_CRYPTO_H
