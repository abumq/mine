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

#include <cmath>
#include <stdexcept>
#include <map>
#include <string>
#include <sstream>
#include <vector>

namespace mine {

///
/// \brief Provides base16 encoding / decoding
///
class Base16 {
public:

private:
    Base16() = delete;
    Base16(const Base16&) = delete;
    Base16& operator=(const Base16&) = delete;
};

///
/// \brief Provides base64 encoding / decoding
///
class Base64 {
public:

private:
    Base64() = delete;
    Base64(const Base64&) = delete;
    Base64& operator=(const Base64&) = delete;
};

///
/// \brief Provides AES crypto functionalities
///
class AES {
public:

private:
    AES() = delete;
    AES(const AES&) = delete;
    AES& operator=(const AES&) = delete;
};

// Here onwards start implementation for RSA - this contains
// naked classes and need implementation for Big Integer
// once available you can use DECLARE_MINE_RSA(BIG_INTEGER) macro
// to declare

///
/// \brief Default exponent for RSA public key
///
static const unsigned int kDefaultPublicExponent = 65537;

///
/// Declaration for byte in case it's not already included
///
using byte = unsigned char;

///
/// \brief Contains helper functions for RSA throughout
///
template <typename BigInteger>
class VirtualHelper {
public:

    ///
    /// \brief Implementation for (a ^ -1) mod b
    ///
    static BigInteger modInverse(BigInteger a, BigInteger b)
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
    static BigInteger gcd(BigInteger a, BigInteger b)
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
    /// \brief Octet string to integer
    ///
    static inline BigInteger os2ip(const BigInteger& x)
    {
        return os2ip(getByteArray(x));
    }

    ///
    /// Octet-string to integer
    ///
    template <typename Byte = byte>
    static BigInteger os2ip(const std::vector<Byte>& x)
    {
        const BigInteger b256 = 256;

        BigInteger result = 0;
        std::size_t len = x.size();
        for (std::size_t i = len; i > 0; --i) {
            result += BigInteger(x[i - 1]) * power(b256, BigInteger(len - i));
        }
        return result;
    }

    ///
    /// \brief Integer to octet-string
    ///
    static BigInteger i2osp(const BigInteger& x, int xlen)
    {
        return i2osp(getByteArray(x), xlen);
    }

    ///
    /// \brief Integer to octet-string
    ///
    template <typename Byte = byte>
    static BigInteger i2osp(const std::vector<Byte>& x, int xlen)
    {
        const BigInteger b256 = 256;

        BigInteger result = 0;
        std::size_t len = x.size();
        for (std::size_t i = len; i > 0; --i) {
            result += BigInteger(x[i - 1]) * power(b256, BigInteger(len - i));
        }
        // TODO: Fix this!
        return result;
    }

    ///
    /// \brief Specific base to specified base
    /// \param n Number
    /// \param b Target base (default: 16 - Hex)
    ///
    template <typename T = BigInteger>
    static T changeBase(T n, T b = 16)
    {
        T r, i = 1, o = 0;
        while (n != 0) {
            r = n % b;
            n /= b;
            o += r * i;
            i *= 10;
        }
        return o;
    }

    ///
    /// \brief Simple (b ^ e) mod m implementation
    /// \param b Base
    /// \param e Exponent
    /// \param m Mod
    ///
    static BigInteger powerMod(BigInteger b, BigInteger e, BigInteger m)
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
    static BigInteger power(BigInteger b, BigInteger e)
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

    static unsigned int countBits(BigInteger b)
    {
        unsigned int bits = 0;
        while (b > 0) {
            bits++;
            b >>= 1;
        }
        return bits;
    }

    ///
    /// \brief Get byte array from big integer
    ///
    template <typename Byte = byte>
    static std::vector<Byte> getByteArray(BigInteger x, int xlen = -1)
    {
        const BigInteger b256 = 256;
        xlen = xlen == -1 ? countBits(x) * 8 : xlen;

        std::vector<Byte> ba(xlen);
        BigInteger r;
        BigInteger q;

        for (int i = 1; i <= xlen; ++i) {
            BigInteger e = power(b256, BigInteger(xlen - i));
            q = x / e;
            r = x % e;
            ba[i - 1] = static_cast<Byte>(q.ConvertToLong());
            x = r;
        }
        return ba;
    }
};

template <typename BigInteger>
class VirtualPublicKey {
public:
    VirtualPublicKey() = default;

    VirtualPublicKey(BigInteger n, int e) :
        m_n(n),
        m_e(e)
    {
    }

    virtual ~VirtualPublicKey() = default;

    inline BigInteger n() const { return m_n; }
    inline int e() const { return m_e; }

protected:
    BigInteger m_n;
    int m_e;
};

template <typename BigInteger>
class VirtualRawKey {
public:
    using Helper = VirtualHelper<BigInteger>;

    VirtualRawKey(const BigInteger& p, const BigInteger& q, int e = kDefaultPublicExponent) :
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

          if (Helper::gcd(m_e, phi) != 1) {
              throw std::invalid_argument("Invalid exponent, it must not share factor with phi");
          }
          m_n = m_p * m_q;
          m_coeff = Helper::modInverse(m_q, m_p);

          m_d = Helper::modInverse(m_e, phi);

          // note:
          // https://www.ipa.go.jp/security/rfc/RFC3447EN.html#2 says to use m_e
          // openssl says to use m_d
          m_dp = BigInteger(m_d) % pMinus1;
          m_dq = BigInteger(m_d) % qMinus1;
      }

    virtual ~VirtualRawKey() = default;

    inline BigInteger p() const { return m_p; }
    inline BigInteger q() const { return m_q; }
    inline BigInteger coeff() const { return m_coeff; }
    inline BigInteger n() const { return m_n; }
    inline int e() const { return m_e; }
    inline BigInteger d() const { return m_d; }
    inline BigInteger dp() const { return m_dq; }
    inline BigInteger dq() const { return m_dp; }

protected:
    BigInteger m_p;
    BigInteger m_q;
    int m_e;
    BigInteger m_coeff;
    BigInteger m_n;
    BigInteger m_d;
    BigInteger m_dp;
    BigInteger m_dq;
};

template <typename BigInteger>
using VirtualPrivateKey = VirtualRawKey<BigInteger> ;

template <typename BigInteger>
class VirtualKeyPair : public VirtualRawKey<BigInteger> {
public:
    VirtualKeyPair(const BigInteger& p, const BigInteger& q, unsigned int exp = kDefaultPublicExponent) :
        VirtualRawKey<BigInteger>(p, q, exp) {
        m_publicKey = VirtualPublicKey<BigInteger>(p * q, exp);
    }

    inline const VirtualPublicKey<BigInteger>* publicKey() const { return &m_publicKey; }
    inline const VirtualPrivateKey<BigInteger>* privateKey() const { return this; }

protected:
    VirtualPublicKey<BigInteger> m_publicKey;
};

///
/// \brief Provides RSA crypto functionalities
///
template <typename BigInteger>
class VirtualRSA {
public:

    using Helper = VirtualHelper<BigInteger>;

    ///
    /// \brief Generic RSA encryption. T can of std::string or std::wstring
    /// or custom similar type
    ///
    /// \return hex of final octet string
    ///
    template <class T>
    std::string encrypt(const VirtualPublicKey<BigInteger>* publicKey, const T& m)
    {
        BigInteger paddedMsg = pkcs1pad2<T>(m, (Helper::countBits(publicKey->n()) + 7) >> 3);
        std::stringstream ss;
        ss << std::hex << Helper::powerMod(paddedMsg, publicKey->e(), publicKey->n());
        std::string h(ss.str());
        h.erase(h.end() - 1);
        return ((h.size() & 1) == 0) ? h : ("0" + h);
    }

    ///
    /// \brief Encrypts wstring msg using public key.
    ///
    /// \return hex of cipher. Padded using PKCS#1 padding scheme
    ///
    std::string encrypt(const VirtualPublicKey<BigInteger>* publicKey,
                               const std::wstring& message)
    {
        return encrypt<decltype(message)>(publicKey, message);
    }

    ///
    /// \brief Encrypts string msg using public key
    ///
    /// \return hex of cipher. Padded using PKCS#1 padding scheme
    ///
    std::string encrypt(const VirtualPublicKey<BigInteger>* publicKey,
                               const std::string& message)
    {
        return encrypt<decltype(message)>(publicKey, message);
    }

    ///
    /// \brief Decrypts RSA hex message m using private key
    /// \param cipher Cipher in hex format (should not start with 0x)
    /// \return Plain text, return type depends on TResult
    ///
    template <class TResult = std::wstring>
    TResult decrypt(const VirtualPrivateKey<BigInteger>* privateKey, const std::string& cipher)
    {
        // TODO: Add checks https://tools.ietf.org/html/rfc3447#section-7.2.2

        std::string readableMsg = "0x" + cipher;
        //BigInteger msg(readableMsg.c_str());
        BigInteger msg;
        std::istringstream iss(readableMsg);
        iss >> std::hex >> msg;

        // https://tools.ietf.org/html/rfc3447#section-4.1
        int xlen = (Helper::countBits(privateKey->n()) + 7) >> 3;
        if (msg >= Helper::power(BigInteger(256), BigInteger(xlen))) {
            throw std::runtime_error("Integer too large");
        }
        BigInteger decr = Helper::powerMod(msg, privateKey->d(), privateKey->n());
        return pkcs1unpad2<TResult>(decr, xlen);
    }

    ///
    /// \brief Verifies signature for text using RSA public key
    /// \param message An octet string
    /// \param signature Signature in hex
    /// \see https://tools.ietf.org/html/rfc3447#section-8.1.2
    ///
    bool verify(const VirtualPublicKey<BigInteger>* publicKey, const std::string& message,
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

        std::string readableSign = "0x" + signature;
        BigInteger sign(readableSign.c_str());
        try {
            BigInteger vp = createVerificationPrimitive(publicKey, sign);
            // I2OSP

            std::cout << vp << std::endl;

            const int xlen = (publicKey->n().BitCount() + 7) >> 3;

            if (xlen < vp + 11) {
                // throw std::runtime_error("Integer too large"); // Needed??! Where in RFC?
            }

            BigInteger em = i2osp(vp, xlen);

            // manually test
            std::string encr = encrypt(publicKey, message);


            // todo: add check for following (as per https://tools.ietf.org/html/rfc3447#section-8.1.2)
            // Note that emLen will be one less than k if modBits - 1 is
            // divisible by 8 and equal to k otherwise.  If I2OSP outputs
            // "integer too large," output "invalid signature" and stop.

            // EMSA-PSS_VERIFY - https://tools.ietf.org/html/rfc3447#section-9.1.2



            std::cout << em << " " << encr << std::endl;
            return true;
        } catch (std::exception&) {
        }*/

        return true;
    }

    ///
    /// \brief Singleton instance
    ///
    inline static VirtualRSA& instance()
    {
        static VirtualRSA s_instance;
        return s_instance;
    }

private:
    VirtualRSA() = default;
    VirtualRSA(const VirtualRSA&) = default;
    VirtualRSA& operator=(const VirtualRSA&) = delete;

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
        std::vector<int> byteArray(n);
        long long i = s.size() - 1;
        while(i >= 0 && n > 0) {
            int c = static_cast<int>(s.at(i--));
            if (c < 128) {
                // utf
                byteArray[--n] = c;
            } else if ((c > 127) && (c < 2048)) {
                // 16-bit
                byteArray[--n] = (c & 63) | 128;
                byteArray[--n] = (c >> 6) | 192;
            } else {
                // 24-bit
                byteArray[--n] = (c & 63) | 128;
                byteArray[--n] = ((c >> 6) & 63) | 128;
                byteArray[--n] = (c >> 12) | 224;
            }
        }

        // now padding i.e, 0x00 || 0x02 || PS || 0x00
        // see point #2 on https://tools.ietf.org/html/rfc3447#section-7.2.1 => EME-PKCS1-v1_5 encoding

        byteArray[--n] = 0;

        // todo: check if there are any more specs for randoms in standard
        srand(time(NULL));
        int r = rand() % 100 + 1;
        while (n > 2) {
            r = 0;
            while (r == 0) {
                r = rand() % 100 + 1;
            }
            byteArray[--n] = r;
        }
        // first two bytes of padding are 0x2 (second) and 0x0 (first)
        byteArray[--n] = 2;
        byteArray[--n] = 0;
        return Helper::i2osp(byteArray, n);
    }

    ///
    /// \brief PKCS #1 unpadding
    /// \see https://tools.ietf.org/html/rfc3447#section-4.1
    /// \return corresponding octet string of length n
    ///
    template <class T = std::wstring>
    T pkcs1unpad2(const BigInteger& m, unsigned long n)
    {
        std::vector<byte> ba = Helper::getByteArray(m, n);
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

        std::basic_stringstream<typename T::value_type> ss;
        for (; i < baLen; ++i) {
            // reference: http://en.cppreference.com/w/cpp/language/types -> range of values
            int c = ba[i] & 0xFF;
            if (c < 128) {
                // utf-8
                ss << static_cast<char>(c);
            } else if ((c > 191) && (c < 224)) { // 16-bit char
                ss << static_cast<wchar_t>(((c & 31) << 6) | (ba[i+1] & 63));
                ++i;
            } else { // 24-bit char
                ss << static_cast<wchar_t>(((c & 15) << 12) | ((ba[i+1] & 63) << 6) | (ba[i+2] & 63));
                i += 2;
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
    BigInteger createVerificationPrimitive(const VirtualPublicKey<BigInteger>* publicKey, const BigInteger& signature)
    {
        if (signature < 0 || signature > publicKey->n() - 1) {
            throw std::runtime_error("signature representative out of range");
        }
        return powerMod(signature, publicKey->e(), publicKey->n());
    }

    // for tests
    friend class RSATest_Signature_Test;
    friend class RSATest_Decryption_Test;
    friend class RSATest_KeyAndEncryptionDecryption_Test;
    friend class RSATest_PowerMod_Test;
};

///
/// A macro that you can use to use specific version of big integer
/// implementation.
///
/// Big integer that is used here must have following public functions
///  -  operator-() [subtraction]
///  -  operator+() [addition]
///  -  operator+=() [short-hand addition]
///  -  operator*() [multiply]
///  -  operator/() [divide]
///  -  operator%() [mod]
///  -  operator>>() [right-shift]
///  -  operator>>=() [short-hand right-shift]
///  -  long ConvertToLong()
///  -  support for std::hex
///
#define DECLARE_MINE_RSA(BIG_INTEGER_IMPLEMENTATION)                      \
using BigInteger = BIG_INTEGER_IMPLEMENTATION;             \
class Helper : public VirtualHelper<BigInteger>{};         \
class RSA : public VirtualRSA<BigInteger>{};               \
class KeyPair : public VirtualKeyPair<BigInteger>{         \
public:                                                    \
    KeyPair(const BigInteger& p, const BigInteger& q,      \
            unsigned int exp = kDefaultPublicExponent) :   \
        VirtualKeyPair<BigInteger>(p, q, exp) {}           \
};                                                         \
class RawKey : public VirtualRawKey<BigInteger>{};         \
class PublicKey : public VirtualPublicKey<BigInteger>{};   \
class PrivateKey : public VirtualPrivateKey<BigInteger>{}; \


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
