#ifndef AES_TEST_H
#define AES_TEST_H

#include "test.h"

#ifdef MINE_SINGLE_HEADER_TEST
#   include "package/mine.h"
#else
#   include "src/aes.h"
#   include "src/base16.h"
#endif

namespace mine {


// many test data is from NIST special publication
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

static AES aes;

TEST(AESTest, KeyExpansion)
{
    // This key expansion is original key from FIPS.197 example
    static TestData<std::string, AES::Key, AES::KeySchedule> KeyExpansionTestData = {
        TestCase("128-bit key expansion", AES::Key{{
                                                       0x2b, 0x7e, 0x15, 0x16,
                                                       0x28, 0xae, 0xd2, 0xa6,
                                                       0xab, 0xf7, 0x15, 0x88,
                                                       0x09, 0xcf, 0x4f, 0x3c
                                                   }}, AES::KeySchedule{{
                                                                            {0, {{ 0x2B, 0x7E, 0x15, 0x16 }}},
                                                                            {1, {{ 0x28, 0xAE, 0xD2, 0xA6 }}},
                                                                            {2, {{ 0xAB, 0xF7, 0x15, 0x88 }}},
                                                                            {3, {{ 0x9, 0xCF, 0x4F, 0x3C }}},
                                                                            {4, {{ 0xA0, 0xFA, 0xFE, 0x17 }}},
                                                                            {5, {{ 0x88, 0x54, 0x2C, 0xB1 }}},
                                                                            {6, {{ 0x23, 0xA3, 0x39, 0x39 }}},
                                                                            {7, {{ 0x2A, 0x6C, 0x76, 0x5 }}},
                                                                            {8, {{ 0xF2, 0xC2, 0x95, 0xF2 }}},
                                                                            {9, {{ 0x7A, 0x96, 0xB9, 0x43 }}},
                                                                            {10, {{ 0x59, 0x35, 0x80, 0x7A }}},
                                                                            {11, {{ 0x73, 0x59, 0xF6, 0x7F }}},
                                                                            {12, {{ 0x3D, 0x80, 0x47, 0x7D }}},
                                                                            {13, {{ 0x47, 0x16, 0xFE, 0x3E }}},
                                                                            {14, {{ 0x1E, 0x23, 0x7E, 0x44 }}},
                                                                            {15, {{ 0x6D, 0x7A, 0x88, 0x3B }}},
                                                                            {16, {{ 0xEF, 0x44, 0xA5, 0x41 }}},
                                                                            {17, {{ 0xA8, 0x52, 0x5B, 0x7F }}},
                                                                            {18, {{ 0xB6, 0x71, 0x25, 0x3B }}},
                                                                            {19, {{ 0xDB, 0xB, 0xAD, 0x00 }}},
                                                                            {20, {{ 0xD4, 0xD1, 0xC6, 0xF8 }}},
                                                                            {21, {{ 0x7C, 0x83, 0x9D, 0x87 }}},
                                                                            {22, {{ 0xCA, 0xF2, 0xB8, 0xBC }}},
                                                                            {23, {{ 0x11, 0xF9, 0x15, 0xBC }}},
                                                                            {24, {{ 0x6D, 0x88, 0xA3, 0x7A }}},
                                                                            {25, {{ 0x11, 0xB, 0x3E, 0xFD }}},
                                                                            {26, {{ 0xDB, 0xF9, 0x86, 0x41 }}},
                                                                            {27, {{ 0xCA, 0x00, 0x93, 0xFD }}},
                                                                            {28, {{ 0x4E, 0x54, 0xF7, 0xE }}},
                                                                            {29, {{ 0x5F, 0x5F, 0xC9, 0xF3 }}},
                                                                            {30, {{ 0x84, 0xA6, 0x4F, 0xB2 }}},
                                                                            {31, {{ 0x4E, 0xA6, 0xDC, 0x4F }}},
                                                                            {32, {{ 0xEA, 0xD2, 0x73, 0x21 }}},
                                                                            {33, {{ 0xB5, 0x8D, 0xBA, 0xD2 }}},
                                                                            {34, {{ 0x31, 0x2B, 0xF5, 0x60 }}},
                                                                            {35, {{ 0x7F, 0x8D, 0x29, 0x2F }}},
                                                                            {36, {{ 0xAC, 0x77, 0x66, 0xF3 }}},
                                                                            {37, {{ 0x19, 0xFA, 0xDC, 0x21 }}},
                                                                            {38, {{ 0x28, 0xD1, 0x29, 0x41 }}},
                                                                            {39, {{ 0x57, 0x5C, 0x00, 0x6E }}},
                                                                            {40, {{ 0xD0, 0x14, 0xF9, 0xA8 }}},
                                                                            {41, {{ 0xC9, 0xEE, 0x25, 0x89 }}},
                                                                            {42, {{ 0xE1, 0x3F, 0xC, 0xC8 }}},
                                                                            {43, {{ 0xB6, 0x63, 0xC, 0xA6 }}}
                                                                        }}),
        TestCase("192-bit key expansion", AES::Key{{
                                                       0x8e, 0x73, 0xb0, 0xf7,
                                                       0xda, 0x0e, 0x64, 0x52,
                                                       0xc8, 0x10, 0xf3, 0x2b,
                                                       0x80, 0x90, 0x79, 0xe5,
                                                       0x62, 0xf8, 0xea, 0xd2,
                                                       0x52, 0x2c, 0x6b, 0x7b
                                                   }}, AES::KeySchedule{{
                                                                            {0, {{ 0x8E, 0x73, 0xB0, 0xF7 }}},
                                                                            {1, {{ 0xDA, 0xE, 0x64, 0x52 }}},
                                                                            {2, {{ 0xC8, 0x10, 0xF3, 0x2B }}},
                                                                            {3, {{ 0x80, 0x90, 0x79, 0xE5 }}},
                                                                            {4, {{ 0x62, 0xF8, 0xEA, 0xD2 }}},
                                                                            {5, {{ 0x52, 0x2C, 0x6B, 0x7B }}},
                                                                            {6, {{ 0xFE, 0xC, 0x91, 0xF7 }}},
                                                                            {7, {{ 0x24, 0x2, 0xF5, 0xA5 }}},
                                                                            {8, {{ 0xEC, 0x12, 0x6, 0x8E }}},
                                                                            {9, {{ 0x6C, 0x82, 0x7F, 0x6B }}},
                                                                            {10, {{ 0xE, 0x7A, 0x95, 0xB9 }}},
                                                                            {11, {{ 0x5C, 0x56, 0xFE, 0xC2 }}},
                                                                            {12, {{ 0x4D, 0xB7, 0xB4, 0xBD }}},
                                                                            {13, {{ 0x69, 0xB5, 0x41, 0x18 }}},
                                                                            {14, {{ 0x85, 0xA7, 0x47, 0x96 }}},
                                                                            {15, {{ 0xE9, 0x25, 0x38, 0xFD }}},
                                                                            {16, {{ 0xE7, 0x5F, 0xAD, 0x44 }}},
                                                                            {17, {{ 0xBB, 0x9, 0x53, 0x86 }}},
                                                                            {18, {{ 0x48, 0x5A, 0xF0, 0x57 }}},
                                                                            {19, {{ 0x21, 0xEF, 0xB1, 0x4F }}},
                                                                            {20, {{ 0xA4, 0x48, 0xF6, 0xD9 }}},
                                                                            {21, {{ 0x4D, 0x6D, 0xCE, 0x24 }}},
                                                                            {22, {{ 0xAA, 0x32, 0x63, 0x60 }}},
                                                                            {23, {{ 0x11, 0x3B, 0x30, 0xE6 }}},
                                                                            {24, {{ 0xA2, 0x5E, 0x7E, 0xD5 }}},
                                                                            {25, {{ 0x83, 0xB1, 0xCF, 0x9A }}},
                                                                            {26, {{ 0x27, 0xF9, 0x39, 0x43 }}},
                                                                            {27, {{ 0x6A, 0x94, 0xF7, 0x67 }}},
                                                                            {28, {{ 0xC0, 0xA6, 0x94, 0x7 }}},
                                                                            {29, {{ 0xD1, 0x9D, 0xA4, 0xE1 }}},
                                                                            {30, {{ 0xEC, 0x17, 0x86, 0xEB }}},
                                                                            {31, {{ 0x6F, 0xA6, 0x49, 0x71 }}},
                                                                            {32, {{ 0x48, 0x5F, 0x70, 0x32 }}},
                                                                            {33, {{ 0x22, 0xCB, 0x87, 0x55 }}},
                                                                            {34, {{ 0xE2, 0x6D, 0x13, 0x52 }}},
                                                                            {35, {{ 0x33, 0xF0, 0xB7, 0xB3 }}},
                                                                            {36, {{ 0x40, 0xBE, 0xEB, 0x28 }}},
                                                                            {37, {{ 0x2F, 0x18, 0xA2, 0x59 }}},
                                                                            {38, {{ 0x67, 0x47, 0xD2, 0x6B }}},
                                                                            {39, {{ 0x45, 0x8C, 0x55, 0x3E }}},
                                                                            {40, {{ 0xA7, 0xE1, 0x46, 0x6C }}},
                                                                            {41, {{ 0x94, 0x11, 0xF1, 0xDF }}},
                                                                            {42, {{ 0x82, 0x1F, 0x75, 0xA }}},
                                                                            {43, {{ 0xAD, 0x7, 0xD7, 0x53 }}},
                                                                            {44, {{ 0xCA, 0x40, 0x5, 0x38 }}},
                                                                            {45, {{ 0x8F, 0xCC, 0x50, 0x6 }}},
                                                                            {46, {{ 0x28, 0x2D, 0x16, 0x6A }}},
                                                                            {47, {{ 0xBC, 0x3C, 0xE7, 0xB5 }}},
                                                                            {48, {{ 0xE9, 0x8B, 0xA0, 0x6F }}},
                                                                            {49, {{ 0x44, 0x8C, 0x77, 0x3C }}},
                                                                            {50, {{ 0x8E, 0xCC, 0x72, 0x4 }}},
                                                                            {51, {{ 0x1, 0x0, 0x22, 0x2 }}},

                                                                        }}),

        TestCase("256-bit key expansion", AES::Key{{
                                                       0x60, 0x3d, 0xeb, 0x10,
                                                       0x15, 0xca, 0x71, 0xbe,
                                                       0x2b, 0x73, 0xae, 0xf0,
                                                       0x85, 0x7d, 0x77, 0x81,
                                                       0x1f, 0x35, 0x2c, 0x07,
                                                       0x3b, 0x61, 0x08, 0xd7,
                                                       0x2d, 0x98, 0x10, 0xa3,
                                                       0x09, 0x14, 0xdf, 0xf4
                                                   }}, AES::KeySchedule{{
                                                                            {0, {{ 0x60, 0x3D, 0xEB, 0x10 }}},
                                                                            {1, {{ 0x15, 0xCA, 0x71, 0xBE }}},
                                                                            {2, {{ 0x2B, 0x73, 0xAE, 0xF0 }}},
                                                                            {3, {{ 0x85, 0x7D, 0x77, 0x81 }}},
                                                                            {4, {{ 0x1F, 0x35, 0x2C, 0x7 }}},
                                                                            {5, {{ 0x3B, 0x61, 0x8, 0xD7 }}},
                                                                            {6, {{ 0x2D, 0x98, 0x10, 0xA3 }}},
                                                                            {7, {{ 0x9, 0x14, 0xDF, 0xF4 }}},
                                                                            {8, {{ 0x9B, 0xA3, 0x54, 0x11 }}},
                                                                            {9, {{ 0x8E, 0x69, 0x25, 0xAF }}},
                                                                            {10, {{ 0xA5, 0x1A, 0x8B, 0x5F }}},
                                                                            {11, {{ 0x20, 0x67, 0xFC, 0xDE }}},
                                                                            {12, {{ 0xA8, 0xB0, 0x9C, 0x1A }}},
                                                                            {13, {{ 0x93, 0xD1, 0x94, 0xCD }}},
                                                                            {14, {{ 0xBE, 0x49, 0x84, 0x6E }}},
                                                                            {15, {{ 0xB7, 0x5D, 0x5B, 0x9A }}},
                                                                            {16, {{ 0xD5, 0x9A, 0xEC, 0xB8 }}},
                                                                            {17, {{ 0x5B, 0xF3, 0xC9, 0x17 }}},
                                                                            {18, {{ 0xFE, 0xE9, 0x42, 0x48 }}},
                                                                            {19, {{ 0xDE, 0x8E, 0xBE, 0x96 }}},
                                                                            {20, {{ 0xB5, 0xA9, 0x32, 0x8A }}},
                                                                            {21, {{ 0x26, 0x78, 0xA6, 0x47 }}},
                                                                            {22, {{ 0x98, 0x31, 0x22, 0x29 }}},
                                                                            {23, {{ 0x2F, 0x6C, 0x79, 0xB3 }}},
                                                                            {24, {{ 0x81, 0x2C, 0x81, 0xAD }}},
                                                                            {25, {{ 0xDA, 0xDF, 0x48, 0xBA }}},
                                                                            {26, {{ 0x24, 0x36, 0xA, 0xF2 }}},
                                                                            {27, {{ 0xFA, 0xB8, 0xB4, 0x64 }}},
                                                                            {28, {{ 0x98, 0xC5, 0xBF, 0xC9 }}},
                                                                            {29, {{ 0xBE, 0xBD, 0x19, 0x8E }}},
                                                                            {30, {{ 0x26, 0x8C, 0x3B, 0xA7 }}},
                                                                            {31, {{ 0x9, 0xE0, 0x42, 0x14 }}},
                                                                            {32, {{ 0x68, 0x0, 0x7B, 0xAC }}},
                                                                            {33, {{ 0xB2, 0xDF, 0x33, 0x16 }}},
                                                                            {34, {{ 0x96, 0xE9, 0x39, 0xE4 }}},
                                                                            {35, {{ 0x6C, 0x51, 0x8D, 0x80 }}},
                                                                            {36, {{ 0xC8, 0x14, 0xE2, 0x4 }}},
                                                                            {37, {{ 0x76, 0xA9, 0xFB, 0x8A }}},
                                                                            {38, {{ 0x50, 0x25, 0xC0, 0x2D }}},
                                                                            {39, {{ 0x59, 0xC5, 0x82, 0x39 }}},
                                                                            {40, {{ 0xDE, 0x13, 0x69, 0x67 }}},
                                                                            {41, {{ 0x6C, 0xCC, 0x5A, 0x71 }}},
                                                                            {42, {{ 0xFA, 0x25, 0x63, 0x95 }}},
                                                                            {43, {{ 0x96, 0x74, 0xEE, 0x15 }}},
                                                                            {44, {{ 0x58, 0x86, 0xCA, 0x5D }}},
                                                                            {45, {{ 0x2E, 0x2F, 0x31, 0xD7 }}},
                                                                            {46, {{ 0x7E, 0xA, 0xF1, 0xFA }}},
                                                                            {47, {{ 0x27, 0xCF, 0x73, 0xC3 }}},
                                                                            {48, {{ 0x74, 0x9C, 0x47, 0xAB }}},
                                                                            {49, {{ 0x18, 0x50, 0x1D, 0xDA }}},
                                                                            {50, {{ 0xE2, 0x75, 0x7E, 0x4F }}},
                                                                            {51, {{ 0x74, 0x1, 0x90, 0x5A }}},
                                                                            {52, {{ 0xCA, 0xFA, 0xAA, 0xE3 }}},
                                                                            {53, {{ 0xE4, 0xD5, 0x9B, 0x34 }}},
                                                                            {54, {{ 0x9A, 0xDF, 0x6A, 0xCE }}},
                                                                            {55, {{ 0xBD, 0x10, 0x19, 0xD }}},
                                                                            {56, {{ 0xFE, 0x48, 0x90, 0xD1 }}},
                                                                            {57, {{ 0xE6, 0x18, 0x8D, 0xB }}},
                                                                            {58, {{ 0x4, 0x6D, 0xF3, 0x44 }}},
                                                                            {59, {{ 0x70, 0x6C, 0x63, 0x1E }}},
                                                                        }}),
    };

    for (auto& item : KeyExpansionTestData) {
        LOG(INFO) << "Test: " << PARAM(0);
        AES::KeySchedule keys = aes.keyExpansion(&PARAM(1));
        AES::KeySchedule expected = PARAM(2);
        ASSERT_EQ(expected, keys);
    }
}

TEST(AESTest, SubByte)
{
    //             <input state> <expected state>
    static TestData<AES::State, AES::State> SubByteTestData = {
        TestCase(AES::State {{
                                 {{ 0x04, 0x66, 0x81, 0xe5 }}, // c0
                                 {{ 0xe0, 0xcb, 0x19, 0x9a }}, // c1
                                 {{ 0x48, 0xf8, 0xd3, 0x7a }}, // c2
                                 {{ 0x28, 0x06, 0x26, 0x4c }}, // c3
                             }}, AES::State {{
                                                 {{ 0xf2, 0x33, 0x0c, 0xd9 }}, // c0
                                                 {{ 0xe1, 0x1f, 0xd4, 0xb8 }}, // c1
                                                 {{ 0x52, 0x41, 0x66, 0xda }}, // c2
                                                 {{ 0x34, 0x6f, 0xf7, 0x29 }}, // c3
                                             }}
        ),
    };

    for (auto& item : SubByteTestData) {
        AES::State state = PARAM(0);
        AES::State expected = PARAM(1);
        aes.subBytes(&state);
        ASSERT_EQ(expected, state);
    }
}

TEST(AESTest, InvSubByte)
{
    //             <input state> <expected state>
    static TestData<AES::State, AES::State> InvSubByteTestData = {
        TestCase(AES::State {{
                                 {{ 0xf2, 0x33, 0x0c, 0xd9 }}, // c0
                                 {{ 0xe1, 0x1f, 0xd4, 0xb8 }}, // c1
                                 {{ 0x52, 0x41, 0x66, 0xda }}, // c2
                                 {{ 0x34, 0x6f, 0xf7, 0x29 }}, // c3
                             }}, AES::State {{
                                                 {{ 0x04, 0x66, 0x81, 0xe5 }}, // c0
                                                 {{ 0xe0, 0xcb, 0x19, 0x9a }}, // c1
                                                 {{ 0x48, 0xf8, 0xd3, 0x7a }}, // c2
                                                 {{ 0x28, 0x06, 0x26, 0x4c }}, // c3
                                             }}
        ),
    };

    for (auto& item : InvSubByteTestData) {
        AES::State state = PARAM(0);
        AES::State expected = PARAM(1);
        aes.invSubBytes(&state);
        ASSERT_EQ(expected, state);
    }
}

TEST(AESTest, ShiftRows)
{
    //             <input state> <expected state>
    static TestData<AES::State, AES::State> ShiftRowsTestData = {
        TestCase(AES::State {{
                                 {{ 0x04, 0x66, 0x81, 0xe5 }}, // c0
                                 {{ 0xe0, 0xcb, 0x19, 0x9a }}, // c1
                                 {{ 0x48, 0xf8, 0xd3, 0x7a }}, // c2
                                 {{ 0x28, 0x06, 0x26, 0x4c }}, // c3
                             }}, AES::State {{
                                                 {{ 0x04, 0xcb, 0xd3, 0x4c }}, // c0
                                                 {{ 0xe0, 0xf8, 0x26, 0xe5 }}, // c1
                                                 {{ 0x48, 0x06, 0x81, 0x9a }}, // c2
                                                 {{ 0x28, 0x66, 0x19, 0x7a }}, // c3
                                             }}
        ),
    };

    for (auto& item : ShiftRowsTestData) {
        AES::State state = PARAM(0);
        AES::State expected = PARAM(1);
        aes.shiftRows(&state);
        ASSERT_EQ(expected, state);
    }
}

TEST(AESTest, InvShiftRows)
{
    //             <input state> <expected state>
    static TestData<AES::State, AES::State> InvShiftRowsTestData = {
        TestCase(AES::State {{
                                 {{ 0x04, 0xcb, 0xd3, 0x4c }}, // c0
                                 {{ 0xe0, 0xf8, 0x26, 0xe5 }}, // c1
                                 {{ 0x48, 0x06, 0x81, 0x9a }}, // c2
                                 {{ 0x28, 0x66, 0x19, 0x7a }}, // c3
                             }}, AES::State {{
                                                 {{ 0x04, 0x66, 0x81, 0xe5 }}, // c0
                                                 {{ 0xe0, 0xcb, 0x19, 0x9a }}, // c1
                                                 {{ 0x48, 0xf8, 0xd3, 0x7a }}, // c2
                                                 {{ 0x28, 0x06, 0x26, 0x4c }}, // c3
                                             }}
        ),
    };

    for (auto& item : InvShiftRowsTestData) {
        AES::State state = PARAM(0);
        AES::State expected = PARAM(1);
        aes.invShiftRows(&state);
        ASSERT_EQ(expected, state);
    }
}

TEST(AESTest, MixColumns)
{
    //             <input state> <expected state>
    static TestData<AES::State, AES::State> MixColumnsTestData = {
        TestCase(AES::State {{
                                 {{ 0x04, 0x66, 0x81, 0xe5 }}, // c0
                                 {{ 0xe0, 0xcb, 0x19, 0x9a }}, // c1
                                 {{ 0x48, 0xf8, 0xd3, 0x7a }}, // c2
                                 {{ 0x28, 0x06, 0x26, 0x4c }}, // c3
                             }}, AES::State {{
                                                 {{ 0xc6, 0xb5, 0x4f, 0x3a }}, // c0
                                                 {{ 0x1e, 0xdc, 0xac, 0xc6 }}, // c1
                                                 {{ 0x2a, 0xb7, 0x83, 0x07 }}, // c2
                                                 {{ 0x30, 0x02, 0xb6, 0xc0 }}, // c3
                                             }}
        ),
    };

    for (auto& item : MixColumnsTestData) {
        AES::State state = PARAM(0);
        AES::State expected = PARAM(1);
        aes.mixColumns(&state);
        ASSERT_EQ(expected, state);
    }
}

TEST(AESTest, InvMixColumns)
{
    //             <input state> <expected state>
    static TestData<AES::State, AES::State> InvMixColumnsTestData = {
        TestCase(AES::State {{
                                 {{ 0xc6, 0xb5, 0x4f, 0x3a }}, // c0
                                 {{ 0x1e, 0xdc, 0xac, 0xc6 }}, // c1
                                 {{ 0x2a, 0xb7, 0x83, 0x07 }}, // c2
                                 {{ 0x30, 0x02, 0xb6, 0xc0 }}, // c3
                             }}, AES::State {{
                                                 {{ 0x04, 0x66, 0x81, 0xe5 }}, // c0
                                                 {{ 0xe0, 0xcb, 0x19, 0x9a }}, // c1
                                                 {{ 0x48, 0xf8, 0xd3, 0x7a }}, // c2
                                                 {{ 0x28, 0x06, 0x26, 0x4c }}, // c3
                                             }}
        ),
    };

    for (auto& item : InvMixColumnsTestData) {
        AES::State state = PARAM(0);
        AES::State expected = PARAM(1);
        aes.invMixColumns(&state);
        ASSERT_EQ(expected, state);
    }
}

TEST(AESTest, AddRoundKey)
{
    // Simple test with test data from FIPS.197 p.33 and 34
    // round 1 and round 6 are tested
    AES::Key key = {{
                        0x2b, 0x7e, 0x15, 0x16,
                        0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88,
                        0x09, 0xcf, 0x4f, 0x3c
                    }};
    AES::KeySchedule schedule = aes.keyExpansion(&key);
    AES::State state = {{
                            {{ 0x04, 0x66, 0x81, 0xe5 }}, // c0
                            {{ 0xe0, 0xcb, 0x19, 0x9a }}, // c1
                            {{ 0x48, 0xf8, 0xd3, 0x7a }}, // c2
                            {{ 0x28, 0x06, 0x26, 0x4c }}, // c3
                        }};
    AES::State expected2 = {{
                                {{ 0xa4, 0x9c, 0x7f, 0xf2 }}, // c0
                                {{ 0x68, 0x9f, 0x35, 0x2b }}, // c1
                                {{ 0x6b, 0x5b, 0xea, 0x43 }}, // c2
                                {{ 0x02, 0x6a, 0x50, 0x49 }}, // c3
                            }};
    AES::State expected7 = {{
                                {{ 0x26, 0x0e, 0x2e, 0x17 }}, // c0
                                {{ 0x3d, 0x41, 0xb7, 0x7d }}, // c1
                                {{ 0xe8, 0x64, 0x72, 0xa9 }}, // c2
                                {{ 0xfd, 0xd2, 0x8b, 0x25 }}, // c3
                            }};
    aes.addRoundKey(&state, &schedule, 1);
    ASSERT_EQ(expected2, state);

    state = {{
                 {{ 0x4b, 0x86, 0x8d, 0x6d }}, // c0
                 {{ 0x2c, 0x4a, 0x89, 0x80 }}, // c1
                 {{ 0x33, 0x9d, 0xf4, 0xe8 }}, // c2
                 {{ 0x37, 0xd2, 0x18, 0xd8 }}, // c3
             }};
    aes.addRoundKey(&state, &schedule, 6);
    ASSERT_EQ(expected7, state);
}

TEST(AESTest, RawSimpleCipher)
{

    // FIPS. 197 p. 33
    ByteArray input = {{
                           0x32, 0x43, 0xf6, 0xa8,
                           0x88, 0x5a, 0x30, 0x8d,
                           0x31, 0x31, 0x98, 0xa2,
                           0xe0, 0x37, 0x07, 0x34
                       }};

    AES::Key key = {{
                        0x2b, 0x7e, 0x15, 0x16,
                        0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88,
                        0x09, 0xcf, 0x4f, 0x3c
                    }};

    ByteArray expected = {{
                              0x39, 0x25, 0x84, 0x1d,
                              0x02, 0xdc, 0x09, 0xfb,
                              0xdc, 0x11, 0x85, 0x97,
                              0x19, 0x6a, 0x0b, 0x32
                          }};

    AES::KeySchedule keySchedule = aes.keyExpansion(&key);
    ByteArray output = aes.encryptSingleBlock(input.begin(), &key, &keySchedule);
    ASSERT_EQ(expected, output);
}

TEST(AESTest, RawSimpleDecipher)
{

    // FIPS. 197 p. 33
    ByteArray input = {{
                           0x39, 0x25, 0x84, 0x1d,
                           0x02, 0xdc, 0x09, 0xfb,
                           0xdc, 0x11, 0x85, 0x97,
                           0x19, 0x6a, 0x0b, 0x32
                       }};

    AES::Key key = {{
                        0x2b, 0x7e, 0x15, 0x16,
                        0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88,
                        0x09, 0xcf, 0x4f, 0x3c
                    }};

    ByteArray expected = {{

                              0x32, 0x43, 0xf6, 0xa8,
                              0x88, 0x5a, 0x30, 0x8d,
                              0x31, 0x31, 0x98, 0xa2,
                              0xe0, 0x37, 0x07, 0x34
                          }};

    AES::KeySchedule keySchedule = aes.keyExpansion(&key);
    ByteArray output = aes.decryptSingleBlock(input.begin(), &key, &keySchedule);
    ASSERT_EQ(expected, output);
}

// from FIPS.197 p.35 onwards
//              input           key         expected
static TestData<std::string, std::string, std::string> RawCipherData = {
    // 128-bit key
    TestCase("00112233445566778899aabbccddeeff",
    "000102030405060708090a0b0c0d0e0f",
    "69c4e0d86a7b0430d8cdb78070b4c55a"),

    // 192-bit key
    TestCase("00112233445566778899aabbccddeeff",
    "000102030405060708090a0b0c0d0e0f1011121314151617",
    "dda97ca4864cdfe06eaf70a0ec0d7191"),

    // 256-bit key
    TestCase("00112233445566778899aabbccddeeff",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "8ea2b7ca516745bfeafc49904b496089"),
};

TEST(AESTest, RawCipher)
{
    for (auto& item : RawCipherData) {
        //ByteArray b = item<0>;

        ByteArray input = Base16::fromString(PARAM(0));
        AES::Key key = static_cast<AES::Key>(Base16::fromString(PARAM(1)));
        ByteArray expected = Base16::fromString(PARAM(2));

        AES::KeySchedule keySchedule = aes.keyExpansion(&key);

        ByteArray output = aes.encryptSingleBlock(input.begin(), &key, &keySchedule);
        ASSERT_EQ(expected, output);
    }
}

TEST(AESTest, RawCipherDirect)
{

    for (auto& item : RawCipherData) {
        std::string expected = PARAM(2);
        std::string output = aes.encrypt(PARAM(0), PARAM(1), MineCommon::Encoding::Base16);
        // case insensitive comparison because hex can be upper or lower case
        ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
    }
}

//              input           key         expected
static TestData<std::string, std::string, std::string> RawCipherPlainInputData = {
    TestCase("this is test...", "000102030405060708090a0b0c0d0e0f", "da14fb09b2378948c5b4966414a6779f"),
};

TEST(AESTest, RawCipherPlain)
{
    for (auto& item : RawCipherPlainInputData) {
        std::string expected = PARAM(2);
        std::string output = aes.encrypt(PARAM(0), PARAM(1), MineCommon::Encoding::Raw, MineCommon::Encoding::Base16, false);
        ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
    }
}

//              input           key         expected
static TestData<std::string, std::string, std::string> RawCipherBase64InputData = {
    TestCase("dGhpcyBpcyB0ZXN0Li4u", "000102030405060708090a0b0c0d0e0f", "da14fb09b2378948c5b4966414a6779f"),
};

TEST(AESTest, RawCipherBase64)
{
    for (auto& item : RawCipherBase64InputData) {
        std::string expected = PARAM(2);
        std::string output = aes.encrypt(PARAM(0), PARAM(1), MineCommon::Encoding::Base64, MineCommon::Encoding::Base16, false);
        ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
    }
}

TEST(AESTest, CbcCipher)
{
    //                 input      expected
    static TestData<std::string, ByteArray> CbcCipherTestData = {
        TestCase("this is test....", ByteArray {{
                                                    0xa3, 0xd9, 0x36, 0xf1,
                                                    0xfe, 0xd3, 0xb8, 0xd3,
                                                    0xe7, 0x4e, 0x09, 0x4e,
                                                    0x2c, 0x0f, 0x1b, 0xd9
                                                }}),
        TestCase("this is test.", ByteArray {{
                                                    0x86, 0xae, 0xc0, 0x99,
                                                    0xfc, 0x4e, 0xba, 0x5f,
                                                    0xcd, 0xaa, 0xd2, 0x94,
                                                    0x96, 0x48, 0x01, 0x65
                                                }}),
        TestCase("this is test longer", ByteArray {{
                                                                    0x2c, 0x32, 0x8a, 0xa3,
                                                                    0x6c, 0xff, 0xdd, 0xe8,
                                                                    0xc1, 0x41, 0x2e, 0x12,
                                                                    0x10, 0x2f, 0x22, 0x05,
                                                                    0xe7, 0x4e, 0x98, 0x8c,
                                                                    0x9a, 0x15, 0x42, 0xe9,
                                                                    0x72, 0x84, 0xc5, 0x19,
                                                                    0x76, 0xc2, 0x6a, 0x44
                                                                }}),
        TestCase("this is test longer than 128-bit", ByteArray {{
                                                                    0x2c, 0x32, 0x8a, 0xa3,
                                                                    0x6c, 0xff, 0xdd, 0xe8,
                                                                    0xc1, 0x41, 0x2e, 0x12,
                                                                    0x10, 0x2f, 0x22, 0x05,
                                                                    0x49, 0x32, 0x6a, 0x1c,
                                                                    0x3c, 0x51, 0xc3, 0x64,
                                                                    0x33, 0x47, 0xdf, 0x21,
                                                                    0xe4, 0x26, 0xe8, 0x45
                                                                }}),
        TestCase("this is test longer than 128-bit this is test "
        "longer than 128-bit this is test longer than 128-bit", ByteArray {{
                                                                               0x2c, 0x32, 0x8a, 0xa3, 0x6c, 0xff, 0xdd, 0xe8,
                                                                               0xc1, 0x41, 0x2e, 0x12, 0x10, 0x2f, 0x22, 0x05,
                                                                               0x49, 0x32, 0x6a, 0x1c, 0x3c, 0x51, 0xc3, 0x64,
                                                                               0x33, 0x47, 0xdf, 0x21, 0xe4, 0x26, 0xe8, 0x45,
                                                                               0xf0, 0x82, 0xb4, 0x6e, 0xa2, 0xda, 0xcb, 0x82,
                                                                               0xa3, 0x78, 0x90, 0x47, 0xf3, 0x9a, 0x33, 0x44,
                                                                               0x56, 0x8d, 0xa6, 0x1c, 0x66, 0x53, 0x47, 0x96,
                                                                               0x56, 0x05, 0xb9, 0xa9, 0x78, 0xc8, 0x1e, 0xc6,
                                                                               0xa0, 0x46, 0x22, 0x38, 0x62, 0xdb, 0xbe, 0xf9,
                                                                               0x78, 0xda, 0xdf, 0xc1, 0xe0, 0x57, 0x51, 0x23,
                                                                               0x35, 0x67, 0xab, 0xa3, 0x6e, 0x95, 0x02, 0xdd,
                                                                               0x66, 0x9f, 0x53, 0x00, 0x82, 0x79, 0x4f, 0x5d,
                                                                               0xad, 0xe2, 0x58, 0x93, 0xef, 0xe3, 0x2f, 0x52,
                                                                               0x58, 0x48, 0xd1, 0xef, 0x65, 0x87, 0xc8, 0xc7
                                                                           }}),
    };

    AES::Key key = {{
                        0x2b, 0x7e, 0x15, 0x16,
                        0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88,
                        0x09, 0xcf, 0x4f, 0x3c
                    }};
    ByteArray iv = {{
                        0x20, 0xc7, 0x04, 0x40,
                        0xac, 0x40, 0x0d, 0xba,
                        0x84, 0x06, 0x57, 0x00,
                        0x74, 0xf2, 0xe2, 0x2a
                    }};

    for (auto& item : CbcCipherTestData) {
        ByteArray expected = PARAM(1);
        ByteArray input = Base16::fromString(Base16::encode(PARAM(0)));
        ByteArray output = aes.encrypt(input, &key, iv, false);
        ASSERT_EQ(expected, output);

        ByteArray dec = aes.decrypt(output, &key, iv);
        int f = 0;
        for (auto i = input.begin(); i < input.end(); ++i, ++f) {
            ASSERT_EQ(*i, dec[f]);
        }
    }

    // specifies modes of input and output
    for (auto& item : CbcCipherTestData) {
        std::string expected = Base16::encode(Base16::toRawString(PARAM(1)));
        std::string input = PARAM(0);
        std::string k = Base16::encode(Base16::toRawString(key));
        std::string initVec = Base16::encode(Base16::toRawString(iv));
        std::string output = aes.encrypt(input, k, initVec,
                                         MineCommon::Encoding::Raw,
                                         MineCommon::Encoding::Base16, false);
        ASSERT_STREQ(expected.c_str(), output.c_str());

    }
}

// from FIPS.197 p.35 onwards
//              input           key         expected
static TestData<std::string, std::string, std::string> RawDecipherData = {
    // 128-bit key
    TestCase("00112233445566778899aabbccddeeff",
    "000102030405060708090a0b0c0d0e0f",
    "69c4e0d86a7b0430d8cdb78070b4c55a"),

    // 192-bit key
    TestCase("00112233445566778899aabbccddeeff",
    "000102030405060708090a0b0c0d0e0f1011121314151617",
    "dda97ca4864cdfe06eaf70a0ec0d7191"),

    // 256-bit key
    TestCase("00112233445566778899aabbccddeeff",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "8ea2b7ca516745bfeafc49904b496089"),
};

TEST(AESTest, HexStringDecipher)
{
    for (auto& item : RawDecipherData) {
        std::string expected = PARAM(0);
        std::string output = aes.decrypt(PARAM(2), PARAM(1), MineCommon::Encoding::Base16, MineCommon::Encoding::Base16);
        ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
    }
}

TEST(AESTest, Base64StringDecipher)
{
    // input mode = base16,
    // output mode = base64
    std::string expected = "dGhpcyBpcyB0ZXN0Li4uLg=="; // base64("this is test....")
    std::string output = aes.decrypt("b92daaae6e57773b10653703af12716f",
                                       "000102030405060708090a0b0c0d0e0f",
                                       MineCommon::Encoding::Base16,
                                       MineCommon::Encoding::Base64);
    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
}

TEST(AESTest, Base64StringInputDecipher)
{
    std::string expected = "this is test..";
    std::string output = aes.decrypt("Z0BiQ8NcwknqzbGrWBjXqw==",
                                       "000102030405060708090a0b0c0d0e0f",
                                       MineCommon::Encoding::Base64,
                                       MineCommon::Encoding::Raw);
    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
}

TEST(AESTest, CbcCipherPadding)
{
    const std::string key = "F1EF6477CC39E65DE106C33BB0EC651386CD0932A9DE491CF960BC3EB79EBE78";
    const std::string iv = "000102030405060708090a0b0c0d0e0f";

    std::string cipherB64 = "OcTPoBeDqlA/igjnNcl5yw==";
    std::string expected = "o1223456789012";
    std::string output = aes.decrypt(cipherB64, key, iv, MineCommon::Encoding::Base64);
    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());

    cipherB64 = "NNH44Ybac3AhcP4+sTq8j4miT04jHtoaj7a/Wv0/TQ8=";
    expected = "sho4123456789014";
    output = aes.decrypt(cipherB64, key, iv, MineCommon::Encoding::Base64);
    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
}

TEST(AESTest, EcbDecipher)
{
    const std::string key = "F1EF6477CC39E65DE106C33BB0EC651386CD0932A9DE491CF960BC3EB79EBE78";
    const std::string cipherHex = "b939427f4231593f5cbf73449439a847726b1898b03db028a6f0824108678f78";
    const std::string expected = "this is slightly longer";
    std::string output = aes.decrypt(cipherHex, key);
    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
}

TEST(AESTest, CbcDecipher)
{

    AES::Key key = {{
                        0x2b, 0x7e, 0x15, 0x16,
                        0x28, 0xae, 0xd2, 0xa6,
                        0xab, 0xf7, 0x15, 0x88,
                        0x09, 0xcf, 0x4f, 0x3c
                    }};
    ByteArray iv = {{
                        0x20, 0xc7, 0x04, 0x40,
                        0xac, 0x40, 0x0d, 0xba,
                        0x84, 0x06, 0x57, 0x00,
                        0x74, 0xf2, 0xe2, 0x2a
                    }};

    //                 input      expected
    static TestData<std::string, ByteArray> CbcDecipherTestData = {
        TestCase("this is test....", ByteArray {{
                                                    0xa3, 0xd9, 0x36, 0xf1,
                                                    0xfe, 0xd3, 0xb8, 0xd3,
                                                    0xe7, 0x4e, 0x09, 0x4e,
                                                    0x2c, 0x0f, 0x1b, 0xd9
                                                }}),
        TestCase("this is test.", ByteArray {{
                                                    0x86, 0xae, 0xc0, 0x99,
                                                    0xfc, 0x4e, 0xba, 0x5f,
                                                    0xcd, 0xaa, 0xd2, 0x94,
                                                    0x96, 0x48, 0x01, 0x65
                                                }}),
        TestCase("this is test longer", ByteArray {{
                                                                    0x2c, 0x32, 0x8a, 0xa3,
                                                                    0x6c, 0xff, 0xdd, 0xe8,
                                                                    0xc1, 0x41, 0x2e, 0x12,
                                                                    0x10, 0x2f, 0x22, 0x05,
                                                                    0xe7, 0x4e, 0x98, 0x8c,
                                                                    0x9a, 0x15, 0x42, 0xe9,
                                                                    0x72, 0x84, 0xc5, 0x19,
                                                                    0x76, 0xc2, 0x6a, 0x44
                                                                }}),
        TestCase("this is test longer than 128-bit", ByteArray {{
                                                                    0x2c, 0x32, 0x8a, 0xa3,
                                                                    0x6c, 0xff, 0xdd, 0xe8,
                                                                    0xc1, 0x41, 0x2e, 0x12,
                                                                    0x10, 0x2f, 0x22, 0x05,
                                                                    0x49, 0x32, 0x6a, 0x1c,
                                                                    0x3c, 0x51, 0xc3, 0x64,
                                                                    0x33, 0x47, 0xdf, 0x21,
                                                                    0xe4, 0x26, 0xe8, 0x45
                                                                }}),
        TestCase("this is test longer than 128-bit this is test "
        "longer than 128-bit this is test longer than 128-bit", ByteArray {{
                                                                               0x2c, 0x32, 0x8a, 0xa3, 0x6c, 0xff, 0xdd, 0xe8,
                                                                               0xc1, 0x41, 0x2e, 0x12, 0x10, 0x2f, 0x22, 0x05,
                                                                               0x49, 0x32, 0x6a, 0x1c, 0x3c, 0x51, 0xc3, 0x64,
                                                                               0x33, 0x47, 0xdf, 0x21, 0xe4, 0x26, 0xe8, 0x45,
                                                                               0xf0, 0x82, 0xb4, 0x6e, 0xa2, 0xda, 0xcb, 0x82,
                                                                               0xa3, 0x78, 0x90, 0x47, 0xf3, 0x9a, 0x33, 0x44,
                                                                               0x56, 0x8d, 0xa6, 0x1c, 0x66, 0x53, 0x47, 0x96,
                                                                               0x56, 0x05, 0xb9, 0xa9, 0x78, 0xc8, 0x1e, 0xc6,
                                                                               0xa0, 0x46, 0x22, 0x38, 0x62, 0xdb, 0xbe, 0xf9,
                                                                               0x78, 0xda, 0xdf, 0xc1, 0xe0, 0x57, 0x51, 0x23,
                                                                               0x35, 0x67, 0xab, 0xa3, 0x6e, 0x95, 0x02, 0xdd,
                                                                               0x66, 0x9f, 0x53, 0x00, 0x82, 0x79, 0x4f, 0x5d,
                                                                               0xad, 0xe2, 0x58, 0x93, 0xef, 0xe3, 0x2f, 0x52,
                                                                               0x58, 0x48, 0xd1, 0xef, 0x65, 0x87, 0xc8, 0xc7
                                                                           }}),
    };

    for (auto& item : CbcDecipherTestData) {
        std::string expected = PARAM(0);
        std::string input = Base16::toRawString(PARAM(1));
        std::string k = Base16::encode(Base16::toRawString(key));
        std::string initVec = Base16::encode(Base16::toRawString(iv));
        std::string output = aes.decrypt(input, k, initVec,
                                         MineCommon::Encoding::Raw,
                                         MineCommon::Encoding::Raw);
        ASSERT_STREQ(expected.c_str(), output.c_str());

    }
}

TEST(AESTest, CrossAppsDataTest)
{
    std::string iv = "a14c54563269e9e368f56b325f04ff00";
    const std::string key = "CBD437FA37772C66051A47D72367B38E";
    const std::string keyBig = "163E6AC9A9EB43253AC237D849BDD22C4798393D38FBE322F7E593E318F1AEAF";

    // genearted using online tool
    std::string expected = "WQ73OMIum+OHKGHnAhQKJX1tByfBq4BhSpw2X+SgtjY=";
    std::string output = aes.encrypt("test this test this",
                          "CBD437FA37772C66051A47D72367B38E",
                          iv,
                          MineCommon::Encoding::Raw,
                          MineCommon::Encoding::Base64);

    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());

    std::string nextexp = "test this test this";
    output = aes.decrypt("WQ73OMIum+OHKGHnAhQKJX1tByfBq4BhSpw2X+SgtjY=",
                          key,
                          iv,
                          MineCommon::Encoding::Base64,
                          MineCommon::Encoding::Raw);

    ASSERT_STRCASEEQ(nextexp.c_str(), output.c_str());

    expected = "EtYr5JFo/7kqYWxooMvU2DJ+upNhUMDii9X6IEHYxvUNXSVGk34IakT5H7GbyzL5/JIMMAQCLnUU824RI3ymgQ==";

    output = aes.encrypt(R"({"_t":1503928197,"logger_id":"default","access_code":"default"})",
                          key,
                          iv,
                          MineCommon::Encoding::Raw,
                          MineCommon::Encoding::Base64);

    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());


    // this is real data from residue logging server (development)
    //
    expected = R"({"_t":1503928197,"logger_id":"default","access_code":"default"})";
    output = aes.decrypt("EtYr5JFo/7kqYWxooMvU2DJ+upNhUMDii9X6IEHYxvUNXSVGk34IakT5H7GbyzL5/JIMMAQCLnUU824RI3ymgQ==",
                                       key,
                                       iv,
                                       MineCommon::Encoding::Base64,
                                       MineCommon::Encoding::Raw);

    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());

    // generated with ripe
    // echo test this test this | ripe -e --aes --key CBD437FA37772C66051A47D72367B38E --iv a14c54563269e9e368f56b325f04ff00
    expected = "test this test this";
    output = aes.decrypt("WQ73OMIum+OHKGHnAhQKJX1tByfBq4BhSpw2X+SgtjY=",
                                       key,
                                       iv,
                                       MineCommon::Encoding::Base64,
                                       MineCommon::Encoding::Raw);


    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());

     // generated with openssl
    // echo test this test this | openssl enc -aes-128-cbc -K CBD437FA37772C66051A47D72367B38E -iv a14c54563269e9e368f56b325f04ff00 -base64
    expected = "test this test this\n"; // openssl adds newline char
    output = aes.decrypt("WQ73OMIum+OHKGHnAhQKJdSsXR5NwysOnq+cuf5C6cs=",
                                       key,
                                       iv,
                                       MineCommon::Encoding::Base64,
                                       MineCommon::Encoding::Raw);


    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());

    // generated with openssl
    // echo test this test this | openssl enc -aes-256-cbc -K 163E6AC9A9EB43253AC237D849BDD22C4798393D38FBE322F7E593E318F1AEAF -iv a14c54563269e9e368f56b325f04ff00 -base64
    expected = "test this test this\n"; // openssl adds newline char
    output = aes.decrypt("vVMWB9aLpcfRgfai7OnCCLI5aAK+kK3Yem/E03uEM+w=",
                                       keyBig,
                                       iv,
                                       MineCommon::Encoding::Base64,
                                       MineCommon::Encoding::Raw);


    ASSERT_STRCASEEQ(expected.c_str(), output.c_str());
}

TEST(AESTest, Copy)
{
    AES::Key key = {{
            0x60, 0x3d, 0xeb, 0x10,
            0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0,
            0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07,
            0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4
        }};
    AES::KeySchedule expectedKeySchedule = {{
                                                {0, {{ 0x60, 0x3D, 0xEB, 0x10 }}},
                                                {1, {{ 0x15, 0xCA, 0x71, 0xBE }}},
                                                {2, {{ 0x2B, 0x73, 0xAE, 0xF0 }}},
                                                {3, {{ 0x85, 0x7D, 0x77, 0x81 }}},
                                                {4, {{ 0x1F, 0x35, 0x2C, 0x7 }}},
                                                {5, {{ 0x3B, 0x61, 0x8, 0xD7 }}},
                                                {6, {{ 0x2D, 0x98, 0x10, 0xA3 }}},
                                                {7, {{ 0x9, 0x14, 0xDF, 0xF4 }}},
                                                {8, {{ 0x9B, 0xA3, 0x54, 0x11 }}},
                                                {9, {{ 0x8E, 0x69, 0x25, 0xAF }}},
                                                {10, {{ 0xA5, 0x1A, 0x8B, 0x5F }}},
                                                {11, {{ 0x20, 0x67, 0xFC, 0xDE }}},
                                                {12, {{ 0xA8, 0xB0, 0x9C, 0x1A }}},
                                                {13, {{ 0x93, 0xD1, 0x94, 0xCD }}},
                                                {14, {{ 0xBE, 0x49, 0x84, 0x6E }}},
                                                {15, {{ 0xB7, 0x5D, 0x5B, 0x9A }}},
                                                {16, {{ 0xD5, 0x9A, 0xEC, 0xB8 }}},
                                                {17, {{ 0x5B, 0xF3, 0xC9, 0x17 }}},
                                                {18, {{ 0xFE, 0xE9, 0x42, 0x48 }}},
                                                {19, {{ 0xDE, 0x8E, 0xBE, 0x96 }}},
                                                {20, {{ 0xB5, 0xA9, 0x32, 0x8A }}},
                                                {21, {{ 0x26, 0x78, 0xA6, 0x47 }}},
                                                {22, {{ 0x98, 0x31, 0x22, 0x29 }}},
                                                {23, {{ 0x2F, 0x6C, 0x79, 0xB3 }}},
                                                {24, {{ 0x81, 0x2C, 0x81, 0xAD }}},
                                                {25, {{ 0xDA, 0xDF, 0x48, 0xBA }}},
                                                {26, {{ 0x24, 0x36, 0xA, 0xF2 }}},
                                                {27, {{ 0xFA, 0xB8, 0xB4, 0x64 }}},
                                                {28, {{ 0x98, 0xC5, 0xBF, 0xC9 }}},
                                                {29, {{ 0xBE, 0xBD, 0x19, 0x8E }}},
                                                {30, {{ 0x26, 0x8C, 0x3B, 0xA7 }}},
                                                {31, {{ 0x9, 0xE0, 0x42, 0x14 }}},
                                                {32, {{ 0x68, 0x0, 0x7B, 0xAC }}},
                                                {33, {{ 0xB2, 0xDF, 0x33, 0x16 }}},
                                                {34, {{ 0x96, 0xE9, 0x39, 0xE4 }}},
                                                {35, {{ 0x6C, 0x51, 0x8D, 0x80 }}},
                                                {36, {{ 0xC8, 0x14, 0xE2, 0x4 }}},
                                                {37, {{ 0x76, 0xA9, 0xFB, 0x8A }}},
                                                {38, {{ 0x50, 0x25, 0xC0, 0x2D }}},
                                                {39, {{ 0x59, 0xC5, 0x82, 0x39 }}},
                                                {40, {{ 0xDE, 0x13, 0x69, 0x67 }}},
                                                {41, {{ 0x6C, 0xCC, 0x5A, 0x71 }}},
                                                {42, {{ 0xFA, 0x25, 0x63, 0x95 }}},
                                                {43, {{ 0x96, 0x74, 0xEE, 0x15 }}},
                                                {44, {{ 0x58, 0x86, 0xCA, 0x5D }}},
                                                {45, {{ 0x2E, 0x2F, 0x31, 0xD7 }}},
                                                {46, {{ 0x7E, 0xA, 0xF1, 0xFA }}},
                                                {47, {{ 0x27, 0xCF, 0x73, 0xC3 }}},
                                                {48, {{ 0x74, 0x9C, 0x47, 0xAB }}},
                                                {49, {{ 0x18, 0x50, 0x1D, 0xDA }}},
                                                {50, {{ 0xE2, 0x75, 0x7E, 0x4F }}},
                                                {51, {{ 0x74, 0x1, 0x90, 0x5A }}},
                                                {52, {{ 0xCA, 0xFA, 0xAA, 0xE3 }}},
                                                {53, {{ 0xE4, 0xD5, 0x9B, 0x34 }}},
                                                {54, {{ 0x9A, 0xDF, 0x6A, 0xCE }}},
                                                {55, {{ 0xBD, 0x10, 0x19, 0xD }}},
                                                {56, {{ 0xFE, 0x48, 0x90, 0xD1 }}},
                                                {57, {{ 0xE6, 0x18, 0x8D, 0xB }}},
                                                {58, {{ 0x4, 0x6D, 0xF3, 0x44 }}},
                                                {59, {{ 0x70, 0x6C, 0x63, 0x1E }}},
                                            }};
    AES aesSimple(key);
    ASSERT_EQ(aesSimple.m_key, key);
    ASSERT_EQ(aesSimple.m_keySchedule, expectedKeySchedule);

    AES aesSimple2 = aesSimple; // eq operator
    ASSERT_EQ(aesSimple2.m_key, key);
    ASSERT_EQ(aesSimple2.m_keySchedule, expectedKeySchedule);
    // make sure original values didn't change
    ASSERT_EQ(aesSimple.m_key, key);
    ASSERT_EQ(aesSimple.m_keySchedule, expectedKeySchedule);


    AES aesSimple3(aesSimple); // copy constructor
    ASSERT_EQ(aesSimple3.m_key, key);
    ASSERT_EQ(aesSimple3.m_keySchedule, expectedKeySchedule);
    // make sure original values didn't change
    ASSERT_EQ(aesSimple.m_key, key);
    ASSERT_EQ(aesSimple.m_keySchedule, expectedKeySchedule);

    AES::Key key2 = AES::Key {{
            0x8e, 0x73, 0xb0, 0xf7,
            0xda, 0x0e, 0x64, 0x52,
            0xc8, 0x10, 0xf3, 0x2b,
            0x80, 0x90, 0x79, 0xe5,
            0x62, 0xf8, 0xea, 0xd2,
            0x52, 0x2c, 0x6b, 0x7b
        }};

    AES::KeySchedule expectedKeySchedule2 =
            AES::KeySchedule{{
                {0, {{ 0x8E, 0x73, 0xB0, 0xF7 }}},
                {1, {{ 0xDA, 0xE, 0x64, 0x52 }}},
                {2, {{ 0xC8, 0x10, 0xF3, 0x2B }}},
                {3, {{ 0x80, 0x90, 0x79, 0xE5 }}},
                {4, {{ 0x62, 0xF8, 0xEA, 0xD2 }}},
                {5, {{ 0x52, 0x2C, 0x6B, 0x7B }}},
                {6, {{ 0xFE, 0xC, 0x91, 0xF7 }}},
                {7, {{ 0x24, 0x2, 0xF5, 0xA5 }}},
                {8, {{ 0xEC, 0x12, 0x6, 0x8E }}},
                {9, {{ 0x6C, 0x82, 0x7F, 0x6B }}},
                {10, {{ 0xE, 0x7A, 0x95, 0xB9 }}},
                {11, {{ 0x5C, 0x56, 0xFE, 0xC2 }}},
                {12, {{ 0x4D, 0xB7, 0xB4, 0xBD }}},
                {13, {{ 0x69, 0xB5, 0x41, 0x18 }}},
                {14, {{ 0x85, 0xA7, 0x47, 0x96 }}},
                {15, {{ 0xE9, 0x25, 0x38, 0xFD }}},
                {16, {{ 0xE7, 0x5F, 0xAD, 0x44 }}},
                {17, {{ 0xBB, 0x9, 0x53, 0x86 }}},
                {18, {{ 0x48, 0x5A, 0xF0, 0x57 }}},
                {19, {{ 0x21, 0xEF, 0xB1, 0x4F }}},
                {20, {{ 0xA4, 0x48, 0xF6, 0xD9 }}},
                {21, {{ 0x4D, 0x6D, 0xCE, 0x24 }}},
                {22, {{ 0xAA, 0x32, 0x63, 0x60 }}},
                {23, {{ 0x11, 0x3B, 0x30, 0xE6 }}},
                {24, {{ 0xA2, 0x5E, 0x7E, 0xD5 }}},
                {25, {{ 0x83, 0xB1, 0xCF, 0x9A }}},
                {26, {{ 0x27, 0xF9, 0x39, 0x43 }}},
                {27, {{ 0x6A, 0x94, 0xF7, 0x67 }}},
                {28, {{ 0xC0, 0xA6, 0x94, 0x7 }}},
                {29, {{ 0xD1, 0x9D, 0xA4, 0xE1 }}},
                {30, {{ 0xEC, 0x17, 0x86, 0xEB }}},
                {31, {{ 0x6F, 0xA6, 0x49, 0x71 }}},
                {32, {{ 0x48, 0x5F, 0x70, 0x32 }}},
                {33, {{ 0x22, 0xCB, 0x87, 0x55 }}},
                {34, {{ 0xE2, 0x6D, 0x13, 0x52 }}},
                {35, {{ 0x33, 0xF0, 0xB7, 0xB3 }}},
                {36, {{ 0x40, 0xBE, 0xEB, 0x28 }}},
                {37, {{ 0x2F, 0x18, 0xA2, 0x59 }}},
                {38, {{ 0x67, 0x47, 0xD2, 0x6B }}},
                {39, {{ 0x45, 0x8C, 0x55, 0x3E }}},
                {40, {{ 0xA7, 0xE1, 0x46, 0x6C }}},
                {41, {{ 0x94, 0x11, 0xF1, 0xDF }}},
                {42, {{ 0x82, 0x1F, 0x75, 0xA }}},
                {43, {{ 0xAD, 0x7, 0xD7, 0x53 }}},
                {44, {{ 0xCA, 0x40, 0x5, 0x38 }}},
                {45, {{ 0x8F, 0xCC, 0x50, 0x6 }}},
                {46, {{ 0x28, 0x2D, 0x16, 0x6A }}},
                {47, {{ 0xBC, 0x3C, 0xE7, 0xB5 }}},
                {48, {{ 0xE9, 0x8B, 0xA0, 0x6F }}},
                {49, {{ 0x44, 0x8C, 0x77, 0x3C }}},
                {50, {{ 0x8E, 0xCC, 0x72, 0x4 }}},
                {51, {{ 0x1, 0x0, 0x22, 0x2 }}},

            }};

    aesSimple.setKey(key2);
    ASSERT_NE(aesSimple.m_keySchedule, expectedKeySchedule);
    ASSERT_EQ(aesSimple.m_keySchedule, expectedKeySchedule2);
    ASSERT_EQ(aesSimple.m_key, key2);
    ASSERT_EQ(aesSimple3.m_key, key);

    std::string output = aesSimple.encr("Test");
    ASSERT_STRCASEEQ("Test", aesSimple.decr(output).c_str());

    std::string iv = "a14c54563269e9e368f56b325f04ff00";
    output = aesSimple.encr("Test", iv);
    ASSERT_STRCASEEQ("Test", aesSimple.decr(output, iv).c_str());

    ByteArray ivBA = Base16::fromString(iv);

    ByteArray input = {{
                           0x39, 0x25, 0x84, 0x1d,
                           0x02, 0xdc, 0x09, 0xfb,
                           0xdc, 0x11, 0x85, 0x97,
                       }};

    ByteArray outBA = aesSimple.encr(input, ivBA);
    ByteArray result = aesSimple.decr(outBA, ivBA);
    ASSERT_EQ(input, result);

    outBA = aesSimple.encr(input);
    result = aesSimple.decr(outBA);
    ASSERT_EQ(input, result);
}

}

#endif // AES_TEST_H
