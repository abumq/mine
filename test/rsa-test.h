#ifndef RSA_TEST_H
#define RSA_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "package/mine.h"
#else
#   include "src/rsa.h"
#endif

#include <type_traits>
#include <cryptopp/integer.h>
#include <cryptopp/pem-com.h> // for readPem func
//#include <openssl/ossl_typ.h>

namespace mine {

using BigInteger = CryptoPP::Integer;

class Helper : public MathHelper<BigInteger>
{
public:
    virtual byte bigIntegerToByte(const BigInteger& b) const override
    {
        return static_cast<byte>(b.ConvertToLong());
    }

    virtual void divideBigNumber(const BigInteger& divisor, const BigInteger& divident,
                                        BigInteger* quotient, BigInteger* remainder) const override
    {
        BigInteger::Divide(*remainder, *quotient, divisor, divident);
    }

    virtual std::string bigIntegerToHex(BigInteger b) const override
    {
        std::stringstream ss;
        ss << std::hex << b;
        std::string h(ss.str());
        h.erase(h.end() - 1);
        return h;
    }

    virtual std::string bigIntegerToString(const BigInteger& b) const override
    {
        std::stringstream ss;
        ss << b;
        std::string h(ss.str());
        h.erase(h.end() - 1);
        return h;
    }
};

class RSA : public GenericRSA<BigInteger, Helper> {};
class PublicKey : public GenericPublicKey<BigInteger, Helper> {}; // you can choose to not add this line
class PrivateKey : public GenericPrivateKey<BigInteger, Helper> {}; // you can choose to not add this line
class KeyPair : public GenericKeyPair<BigInteger, Helper> {
    using GenericKeyPair::GenericKeyPair;
public:

    void loadFromPem(const std::string& contents, const std::string& secret)
    {
        CryptoPP::RSA::PrivateKey keyOut;
        {
            using namespace CryptoPP;
            StringSource source(contents, true);
            if (secret.empty()) {
                PEM_Load(source, keyOut);
            } else {
                PEM_Load(source, keyOut, secret.data(), secret.size());
            }
        }
        init(keyOut.GetPrime1(), keyOut.GetPrime2(), static_cast<int>(keyOut.GetPublicExponent().ConvertToLong()));
    }
};

static RSA rsaManager;
static Helper rsaHelper;

//--------------------------------------------------------------------------//

// a, b, expected
static TestData<int, int, int> GCDData = {
    TestCase(270, 192, 6),
};

TEST(RSATest, FindGCD)
{
    for (const auto& item : GCDData) {
        LOG(INFO) << "Finding GCD for " << PARAM(0) << " and " << PARAM(1);
        ASSERT_EQ(rsaHelper.gcd(PARAM(0), PARAM(1)), PARAM(2));
    }
}

//--------------------------------------------------------------------------//

// b, e, m, exp
static TestData<BigInteger, BigInteger, BigInteger, BigInteger> PowerModData = {
    TestCase(5, 3, 1, 0),
    TestCase(5, 3, 19, 11),
    TestCase(3, 11, 4, 3),
    TestCase(5, 117, 19, 1),
    TestCase(5, 64, 19, 5),
    TestCase(5, 2, 19, 6),
    TestCase(5, 4, 19, 17),
    TestCase(5, 8, 19, 4),
    TestCase(7, 256, 13, 9),
};

TEST(RSATest, PowerMod)
{
    for (const auto& item : PowerModData) {
        ASSERT_EQ(rsaHelper.powerMod(PARAM(0), PARAM(1), PARAM(2)), PARAM(3));
    }
}

//--------------------------------------------------------------------------//

// a, b, expected mod, expected mod_inv
static TestData<int, int, int> InvModuloData = {
    TestCase(3, 11, 4),
    TestCase(1, 2, 1),
    TestCase(199, 2443, 1510),
    TestCase(2443, 199, 76),
    TestCase(17, 3120, 2753),
};

TEST(RSATest, InvModulo)
{
    for (const auto& item : InvModuloData) {
        ASSERT_EQ(rsaHelper.modInverse(PARAM(0), PARAM(1)), PARAM(2));
    }
}

// msg
static TestData<std::string> RSAEncryptionStringData = {
    TestCase("1"),
    TestCase("Slightly longer text"),
};

//--------------------------------------------------------------------------//

// p, q, d, e
static TestData<BigInteger, BigInteger, BigInteger, unsigned int> RawKeyData = {
    TestCase(173, 149, 16971, 3),
    TestCase(7, 11, 53, kDefaultPublicExponent),
    TestCase(53, 59, 2011, 3),
    TestCase(3, 11, 13, kDefaultPublicExponent),
    TestCase(11, 3, 13, kDefaultPublicExponent),
    TestCase(11, 17, 107, 3),
    TestCase(60779, 53003, 1986380529, 65537),
    TestCase(BigInteger("108215449534587396558557488943879350166773359647071667116025080873441234413887"), BigInteger("91243493758612676931094271904842149664289633274572930135618242638207523081573"), BigInteger("6582637129463060155009365989980507690389844347218288265898882119918384609608605061080359962338234258873604135082233881579524605068749537845926158658339195"), 3), // << - this is what we tested based upon
    TestCase(BigInteger("108806323825932706977307191097259117033353572146991115579334232319532442798209"), BigInteger("75778358732466892022501809496541864532894038434008219546470758430052996329071"), BigInteger("5496776426161658798940200169671739270887755348701962910881820208997794909110934102331035956003239535747096593580882262107967594097892650413676521849537707"), 3),
    TestCase(BigInteger("176360517760307645469197766454483974235511085138581196179561347493397045582678676376582697316359235034160209749898412011153924577295946180206410049279151818330310786286636241193330444606031071350600285897477381895748147316188740513022461102919987041280831098968434434553879045380055670995086500659087065302403"), BigInteger("169163723758010117173450277772073715921803592964927638245731997826080549397171438893995388301374973303599758650257957793677462633788535432641753359275162340138639711102283198388259082836510170614304484108899685152902783320622394241970680405511348370667697428176827008839392860840538166537806520720483413747299"), BigInteger("19889201272149546443463155392252159315174210881947747082976069645146016944350039871470895772510979533532867685298201602992918775321216324576337623180033432704404378220468328792827286239010112541240591233928213472506415790478729110344923198900414497739281740852945910987895868475178794593401701658716065890906852003893420692929407600046549070094684609746581564079903528672418432707811264082243503362255422665241970781850081871999244191153644696361248245946591425338244340405196223004592171521190997670962141503496215757774355742872186005655701283224796723544068646999720522489543729822936326934344869201943856253606531"), 3),
    TestCase(BigInteger("10923469363857806825021760247956265275428795620548365979989112951205898332841066142803135517770434197629570824181214965091978202988425777455632583620648573"), BigInteger("10616722866603125331840450803703198445712906691762933784938310338533958220543323895829410115777559171564354942092760457591438766850006207107583419792614799"), BigInteger("100135682768296545534437842644054326140008581269369655680309979439491675932266939714929393946536056632420527170839805699312975642015803721952542018739599899051226696289188235642510788531344671276783173570477762249241138411740921476903102308841464986571851644112056574180282941203845382289637668214850639602017"), 65537),
};

// msg
static TestData<std::wstring> RSAEncryptionData = {
    TestCase(L"Hi"),
    TestCase(L"G'day"),
    TestCase(L"Hello竜"), // contains 4 byte char [\u7ADC]
    TestCase(L"大家好"), // total 10 bytes
    TestCase(L"Postal mark face 〠"), // contains 4 byte char [\u3020] total 21
    TestCase(L"کیا میں آپکی مدد کر سکتاہوں"), // total 50 bytes
    TestCase(L"Rocket 🚀 is flying"), // contains 5 byte char [\u1F680]
    TestCase(L"Another rocket \x1F680 \x003D h"), // contains 5 byte char [\u1F680] and = sign
};

TEST(RSATest, KeyAndEncryptionDecryption)
{
    for (const auto& item : RawKeyData) {
        int bits = rsaHelper.countBits(PARAM(0)) + rsaHelper.countBits(PARAM(1));
        LOG(INFO) << "Generating key " << bits << "-bit...";

        KeyPair k(PARAM(0), PARAM(1), PARAM(3));
        ASSERT_EQ(k.privateKey()->p(), PARAM(0));
        ASSERT_EQ(k.privateKey()->q(), PARAM(1));
        ASSERT_EQ(k.privateKey()->d(), PARAM(2));
        ASSERT_EQ(k.privateKey()->e(), PARAM(3));
        ASSERT_EQ(k.publicKey()->n(), k.privateKey()->n());
        ASSERT_EQ(k.publicKey()->e(), k.privateKey()->e());

        for (const auto& item2 : RSAEncryptionData) {
            std::wstring msg = std::get<0>(item2);
            if (bits <= 32) {
                EXPECT_THROW(rsaManager.encrypt(k.publicKey(), msg), std::runtime_error);
            } else {
                LOG(INFO) << "Plain: " << msg;
                std::string encr = rsaManager.encrypt(k.publicKey(), msg);
                LOG(INFO) << "Encr: " << encr;
                std::wstring decr = rsaManager.decrypt(k.privateKey(), encr);
                LOG(INFO) << "Decr: " << decr;
                ASSERT_STREQ(decr.c_str(), msg.c_str());
            }
        }

        for (const auto& item2 : RSAEncryptionStringData) {
            std::string msg = std::get<0>(item2);
            if (bits <= 32) {
                EXPECT_THROW(rsaManager.encrypt(k.publicKey(), msg), std::runtime_error);
            } else {
                LOG(INFO) << "Plain: " << msg;
                std::string encr = rsaManager.encrypt(k.publicKey(), msg);
                LOG(INFO) << "Encr: " << encr;
                std::string decr = rsaManager.decrypt<std::string>(k.privateKey(), encr);
                LOG(INFO) << "Decr: " << decr;
                ASSERT_STREQ(decr.c_str(), msg.c_str());
            }
        }
    }
}

//--------------------------------------------------------------------------//

// p, q, e, cipher, msg
static TestData<BigInteger, BigInteger, unsigned int, std::string, std::wstring> RSADecryptionData = {
    TestCase(BigInteger("108215449534587396558557488943879350166773359647071667116025080873441234413887"), BigInteger("91243493758612676931094271904842149664289633274572930135618242638207523081573"), 3, "55a5f32084cdbbd3edcba573317f99678a1b85b6c455fa86476d697900ce5fd95ec599a16690d5e7c2196608477ac1006e86c74cbd25b7e4681e026774381e63", L"Apple"),
};

TEST(RSATest, Decryption)
{
    for (const auto& item : RSADecryptionData) {
        int bits = rsaHelper.countBits(PARAM(0)) + rsaHelper.countBits(PARAM(1));
        LOG(INFO) << "Generating key " << bits << "-bit...";

        KeyPair k(PARAM(0), PARAM(1), PARAM(2));

        std::string cipher = PARAM(3);
        std::wstring expected = PARAM(4);
        LOG(INFO) << "Testing: " << cipher;
        if (bits <= 32) {
            EXPECT_THROW(rsaManager.decrypt(k.privateKey(), cipher), std::runtime_error);
        } else {
            std::wstring decr = rsaManager.decrypt(k.privateKey(), cipher);
            ASSERT_STREQ(decr.c_str(), expected.c_str());
        }
    }
}

//--------------------------------------------------------------------------//

TEST(RSATest, ManualTest)
{
    // These keys were generated using
    //      ripe -g --rsa --length 128 --out-public public.pem --out-private private.pem
    // and can only encrypt 5 bytes
    //
    //
    // imported from test/private.pem  test/public.pem
    // using: cat private.pem | openssl rsa -text -noout
    //
    KeyPair k(BigInteger("13866701041466745229"), BigInteger("18381132054282063251"), 17);
    std::cout << "Key ASN Seq:" << std::endl << k.privateKey()->exportASNSequence() << std::endl << "---------------" << std::endl;
    std::cout << rsaManager.encrypt(k.publicKey(), std::string("Test")) << std::endl;

    // You can manually run the output of above and confirm the result with ripe and openssl
    //      ripe:      echo [encrypted_hex] | ripe -d --rsa --in-key private.pem --hex
    //      openssl:   echo [encrypted_hex] | ripe -d --hex | openssl rsautl -decrypt -inkey private.pem
    //

    // this was created using ripe
    //      echo Test | ripe -e --rsa --in-key public.pem | ripe -d --base64 | ripe -e --hex
    std::string sripe = rsaManager.decrypt<std::string>(k.privateKey(), std::string("4A1E74DC3CC2FC57305287F3396449E4"));
    ASSERT_STREQ(sripe.c_str(), "Test");

    // this was created using openssl-cli
    //      echo 'Test' | openssl rsautl -encrypt -pubin -inkey public.pem | ripe -e --hex
    std::string sopenssl = rsaManager.decrypt<std::string>(k.privateKey(), std::string("57E56205E3D0135E7A2E7C5062D5453E"));
    ASSERT_STREQ(sopenssl.c_str(), "Test\n");
}

//--------------------------------------------------------------------------//

TEST(RSATest, KeyRead)
{
    // 2048-bit long encrypted key
    // encryption secret asdf
    std::string pem("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpQcm9jLVR5cGU6IDQsRU5DUllQVEVECkRFSy1JbmZvOiBBRVMtMjU2LUNCQywyQjRDNDFBMDQwQjI1MDA"
                    "5MUE1MTU4RjNCRTE2MkM0MgoKTU5uMW9QdUZHWi9yK2U3cHVqTDRiREgrSmN6a3BBdUNBMit5THIyL1BOSmcwUUltK25SWEptd0dBZDh4dVYvNgpvZ3h4RWVhQ1"
                    "NJQlVJbW82Um1xWWtiSmVNN05FMHB2OW1EZlBHQWZKTVNjOXh0azFIVldCZFV0UkhkSHpLTXkyCnprSjg5dURJWlhBMEtQblNsa3JqSGluUjQvUEpKSXNha2VsO"
                    "WxWUGFBNTZ5SDdwVWxPVzBOWW5BY0NNYlh1MDcKTy9WYWdMUU1FUE0yaWhTOFFWSlFabVhJMTI5dDYzYk85RWpTeGJ6aWsvc1NGaVlPdDNMK0tqZHJvbjNMVjFa"
                    "NwpUZ29UZXZVZjJidERMMkh4U3BJWFNxNDhEeTJtQytyWUc2eDZ5aTBYMU5kWUFqamw1VGJtSUJreWJSTG5mK3FMCmtzRUt3L0RkTXI3N1hPamtCOTg3dTU2N0x"
                    "jelpCY0k0ZUFvNDdTRHpqWHQ3eE81VCtUV21UOVZmRHlGa3MwdDcKbi9iQ1RVbUw5UE5JL2ZSZzFubnkrRVFodm1tZ1BvL2RMMWt6aVhGMHMzdTNYQ00ycnhiWi"
                    "9EUVM1bTJlRjJuVQp4ajZDZUg5bzhtUU5vdDc0blpobkxxQ1Y0WTFhYnd1S3paUUJzSU0vVVBkMGV4ekZLK3k3T0l5aGxxNGVmeVMzCkltRWpvbG53RHFNbjdoc"
                    "FYxZUljTDA5aHMzUDhvcUtDTzE5bGFVc2NxMWpKdGVOMXNPQVFkSVo3b282ZTZTUm4KOUY5ZnFFZDZzM0piN28rMU5IdFZadlVVRjg2a2NWb0QwaHRmYTc4bmZm"
                    "VFpIejNITlZZRHVYREdldS9pQmRiYQphNjJNMUpIZHR0cVk3cVdFcVBxM2hVaVpnSndNVm1Od3hWQXplM2tvcTFpa0Q0eGJubEFUYnl1ZTIrME44S01ZCjZUaUZ"
                    "IdVY2RGUvUENYOGxibklaOTYyY3R0ZkpFZG9jWWdjdUZ1TDBNTjU2aU9EUzBmanlqRjdkSklJV21POVkKbW56NTFKaC85OFEwZ2R2V09SQ0FBOHY2OWRIL1RabUY"
                    "3eWNIZkd4YUhRbThKRXNFVEdBU3RJaTF6QzVIMW5TaQppT1RDdjduMmJKeTB2eVp2Umo3NXlib09iNmRzQTlYQnkyaEtqa1BDd2lrd05UWEdHS2NGQjJJVXJlL1R"
                    "tYzdvCi9UQWxvN09CVkQ0U3p3WCtNL1dWVlF2ZzdZS3A0cUIvcmR5ZlBZcTJFclQ1WkdnbzJoUjdkRWR0VGZPNzZQU2YKQkhJdXVnOGpYZzlrZnkySWpJU0p1Znl"
                    "MYm9vWmE2YVFnUmMwN2FlRzlKcmhwajB4V2g5YWR5cXVkUFo0WjJiRwpxbnhETFNvc2xpSEY0TEFuK2dIaDR0dFptbFlpRGhJTUdTYnpRcGwrcG91UEJFQWplNTV"
                    "4WVhNbUVRRmNLRjdECkJMeDF1ZzYvVVdJbWdObHdBbERnR1NmZlBKMGkyQkM5SmRUaThoY284QnlRWHN2ZURIemJUOGFMTlE0RzhKTzYKQUlvUCtvNERLRHBHZSs"
                    "yMGFGR1d3L0hEK1pnSUtLaEQvSlBtZUNlek50bUZXazNQdDBJN0NnM0EzU3Q1M1NZQQplelEwV28wRmFIS2hPbWJPcmZ5OTkzVTZQN3dCOXpmR2hkRzZyTWRocXo"
                    "xYVhibyt3ZERJZituNkxRdDBCQUVEClVqbUdsVVFPYnZjbDlkWlVjclV6cjJCRWZ3MkRTbWg0NUozSEsxOFc2RkZ6d0lTbDBSR1JZVWZQNmg2Tyt0bmoKbEs1SXU"
                    "xcUE5eG5FS2lmN3E4K2k1cGo2MlBROUhKNTk0MytyWXFGWSt3TUdyaEl3TGxrNENnMjhhZGFsRDEvSQpIU3g2SDNMRitwSUpiQzc4ZDNDTTBDcTNzQTZkdFBqczV"
                    "YWHcxTUpycFR4RElIWjV0eHVJdUlnZDdSN0tsenB2CnNFWDc0QUYyTjFlNVZsNkV3WHRqcHFoeGlRVnVEWmVqQzcvMEU5dGR5YjRWdk9wOVNoRm85cXNHekxKb1J"
                    "IQVgKZmlsWmxZcGdtbXlpNlNnY1ExSERuRWZYZkpMbWROY0tUVEVqNWo3MkhXN0RpQ1Eza3BpN1lhZzRsQlE1MGZ4QwotLS0tLUVORCBSU0EgUFJJVkFURSBLRVk"
                    "tLS0tLQo=");
    KeyPair k;
    k.loadFromPem(Base64::decode(pem), "asdf");

    std::cout << "Run: echo " << rsaManager.encrypt(k.publicKey(), std::string("Testing this long secret"))
              << " | ripe -d --rsa --in-key private2.pem --secret asdf --hex" << std::endl;
}

//--------------------------------------------------------------------------//

// p, q, e, signature, text, result
static TestData<BigInteger, BigInteger, unsigned int, std::string, std::string, bool> RSASignatureVerificationData = {
    TestCase(BigInteger("108215449534587396558557488943879350166773359647071667116025080873441234413887"),
             BigInteger("91243493758612676931094271904842149664289633274572930135618242638207523081573"),
             3,
             "01400ccd971dad2744c37baf7f5cf13a5590a675c90354f2002d4c6a6a7ef3d1377986e1d8f0b69676e243fae8cf6c6bbdc7f18deb0e0418fe6452c4afb1e4b5",
             "test", true),
    TestCase(BigInteger("108215449534587396558557488943879350166773359647071667116025080873441234413887"),
             BigInteger("91243493758612676931094271904842149664289633274572930135618242638207523081573"),
             3,
             "01400ccd971dad2744c37baf7f5cf13a5590a675c90354f2002d4c6a6a7ef3d1377986e1d8f0b69676e243fae8cf6c6bbdc7f18deb0e0418fe6452c4afb1e4b5",
             "test2", false),
};

// key above is:
/*

-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBALyG49x4LERu51a4dKzs8qEV5hMCHq8e1e8pW+wr7YmdJv4uyJa/
nehP44GvZ6e3y7SNhSNecqtZWr+P6EDV+NsCAQMCQH2vQpL6yC2fROR6+HNIocC5
RAysFHS/OUobkp1ynlu89ALympMA4RtHjAkffl2s0/jtri7/4xZNfg7q2ofugXsC
IQDvP8YeIYZ6kA4B7ksbpp9UAydO0nZW2gPtiNeQLM5pPwIhAMm5/MKYt9GvVo+F
tQ50lTm8AbEKaEcv4TAgWBBIIc1lAiEAn3/ZaWuu/GAJVp7cvRm/jVdvieGkOeat
SQXlCsiJm38CIQCGe/3XEHqLyjm1A84Jow4mfVZ2BvAvdUDKwDq1hWveQwIgQS1r
VR2T7hvX3Mr8Y9em0DH8ZgNezGMN33X5SaN4zZ0=
-----END RSA PRIVATE KEY-----


-----BEGIN PUBLIC KEY-----
MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBALyG49x4LERu51a4dKzs8qEV5hMCHq8e
1e8pW+wr7YmdJv4uyJa/nehP44GvZ6e3y7SNhSNecqtZWr+P6EDV+NsCAQM=
-----END PUBLIC KEY-----

*/

TEST(RSATest, Verification)
{
    for (const auto& item : RSASignatureVerificationData) {
        int bits = rsaHelper.countBits(PARAM(0)) + rsaHelper.countBits(PARAM(1));
        LOG(INFO) << "Generating key " << bits << "-bit...";

        KeyPair k(PARAM(0), PARAM(1), PARAM(2));

        std::string sign = PARAM(3);
        std::string text = PARAM(4);
        LOG(INFO) << "Testing: " << text;
        if (bits <= 32) {
            EXPECT_THROW(rsaManager.verify(k.publicKey(), text, sign), std::runtime_error);
        } else {
            ASSERT_EQ(rsaManager.verify(k.publicKey(), text, sign), PARAM(5));
        }
    }
}

}

#endif // RSA_TEST_H
