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


using namespace mine;





RawKey::RawKey(const BigInteger &p, const BigInteger &q, int e) :
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

    if (RSA::instance().gcd(m_e, phi) != 1) {
        throw std::invalid_argument("Invalid exponent, it must not share factor with phi");
    }
    m_n = m_p * m_q;
    m_coeff = RSA::instance().modInverse(m_q, m_p);

    m_d = RSA::instance().modInverse(m_e, phi);

    // note:
    // https://www.ipa.go.jp/security/rfc/RFC3447EN.html#2 says to use m_e
    // openssl says to use m_d
    m_dp = BigInteger(m_d) % pMinus1;
    m_dq = BigInteger(m_d) % qMinus1;
}

KeyPair::KeyPair(const BigInteger &p, const BigInteger &q, unsigned int exp) :
    RawKey(p, q, exp) {
    m_publicKey = PublicKey(n(), e());
}

BigInteger RSA::createVerificationPrimitive(const PublicKey *publicKey, const BigInteger &signature)
{
    if (signature < 0 || signature > publicKey->n() - 1) {
        throw std::runtime_error("signature representative out of range");
    }
    return powerMod(signature, publicKey->e(), publicKey->n());
}

BigInteger RSA::gcd(BigInteger a, BigInteger b)
{
    BigInteger c;
    while (a != 0) {
        c = a;
        a = b % a;
        b = c;
    }
    return b;
}

BigInteger RSA::powerMod(BigInteger b, BigInteger e, BigInteger m)
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

BigInteger RSA::power(BigInteger b, BigInteger e)
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


BigInteger RSA::modInverse(BigInteger a, BigInteger b)
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

bool RSA::isPrime(BigInteger n)
{
    if (n <= 1) {
        return false;
    }
    if (n <= 3) {
        return true;
    }
    if (n % 2 == 0 || n % 3 == 0) {
        return false;
    }
    for (BigInteger i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
    }
    return true;
}

std::string RSA::bigIntegerToString(const BigInteger &b)
{
    std::stringstream ss;
    ss << b;
    std::string sss(ss.str());
    sss.erase(sss.end() - 1);
    return sss;
}

unsigned int RSA::countBits(BigInteger b)
{
    unsigned int bits = 0;
    while (b > 0) {
        bits++;
        b >>= 1;
    }
    return bits;
}

