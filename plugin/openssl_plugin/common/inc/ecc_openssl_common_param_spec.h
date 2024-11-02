/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCF_ECC_OPENSSL_COMMON_PARAM_SPEC_H
#define HCF_ECC_OPENSSL_COMMON_PARAM_SPEC_H

#include "utils.h"

static const int32_t NID_secp224r1_len = 28;
static const int32_t NID_X9_62_prime256v1_len = 32;
static const int32_t NID_secp384r1_len = 48;
static const int32_t NID_secp521r1_len = 66;
static const int32_t NID_brainpoolP160r1_len = 20;
static const int32_t NID_brainpoolP160t1_len = 20;
static const int32_t NID_brainpoolP192r1_len = 24;
static const int32_t NID_brainpoolP192t1_len = 24;
static const int32_t NID_brainpoolP224r1_len = 28;
static const int32_t NID_brainpoolP224t1_len = 28;
static const int32_t NID_brainpoolP256r1_len = 32;
static const int32_t NID_brainpoolP256t1_len = 32;
static const int32_t NID_brainpoolP320r1_len = 40;
static const int32_t NID_brainpoolP320t1_len = 40;
static const int32_t NID_brainpoolP384r1_len = 48;
static const int32_t NID_brainpoolP384t1_len = 48;
static const int32_t NID_brainpoolP512r1_len = 64;
static const int32_t NID_brainpoolP512t1_len = 64;
static const int32_t NID_secp256k1_len = 32;

static unsigned char g_ecc224CorrectBigP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

static unsigned char g_ecc224CorrectBigB[] = {
    0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41, 0x32, 0x56,
    0x50, 0x44, 0xB0, 0xB7, 0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43,
    0x23, 0x55, 0xFF, 0xB4
};

static unsigned char g_ecc224CorrectBigGX[] = {
    0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F, 0x32, 0x13, 0x90, 0xB9,
    0x4A, 0x03, 0xC1, 0xD3, 0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6,
    0x11, 0x5C, 0x1D, 0x21
};

static unsigned char g_ecc224CorrectBigGY[] = {
    0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6,
    0xcd, 0x43, 0x75, 0xa0, 0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99,
    0x85, 0x00, 0x7e, 0x34
};

// ECC256
static unsigned char g_ecc256CorrectBigP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc256CorrectBigB[] = {
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55,
    0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

static unsigned char g_ecc256CorrectBigGX[] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5,
    0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};

static unsigned char g_ecc256CorrectBigGY[] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A,
    0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

// ECC384
static unsigned char g_ecc384CorrectBigP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc384CorrectBigB[] = {
    0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B,
    0xE3, 0xF8, 0x2D, 0x19, 0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
    0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A, 0xC6, 0x56, 0x39, 0x8D,
    0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF
};

static unsigned char g_ecc384CorrectBigGX[] = {
    0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E,
    0xF3, 0x20, 0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
    0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D,
    0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7
};

static unsigned char g_ecc384CorrectBigGY[] = {
    0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF,
    0x92, 0x92, 0xDC, 0x29, 0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C,
    0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0, 0x0A, 0x60, 0xB1, 0xCE,
    0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F,
};

// ECC521
static unsigned char g_ecc521CorrectBigP[] = {
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc521CorrectBigB[] = {
    0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A,
    0x21, 0xA0, 0xB6, 0x85, 0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
    0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19,
    0x39, 0x51, 0xEC, 0x7E, 0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
    0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45,
    0x1F, 0xD4, 0x6B, 0x50, 0x3F, 0x00
};

static unsigned char g_ecc521CorrectBigGX[] = {
    0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E,
    0xCB, 0x66, 0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F,
    0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B,
    0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
    0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E,
    0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66
};

static unsigned char g_ecc521CorrectBigGY[] = {
    0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B, 0xC0, 0x04, 0x5C, 0x8A,
    0x5F, 0xB4, 0x2C, 0x7D, 0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B,
    0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E, 0x66, 0x2C, 0x97, 0xEE,
    0x72, 0x99, 0x5E, 0xF4, 0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD,
    0x07, 0x61, 0x35, 0x3C, 0x70, 0x86, 0xA2, 0x72, 0xC2, 0x40, 0x88, 0xBE,
    0x94, 0x76, 0x9F, 0xD1, 0x66, 0x50
};

// SM2_256
static unsigned char g_sm256CorrectBigP[] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static unsigned char g_sm256CorrectBigB[] = {
    0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b,
    0xcf, 0x65, 0x09, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
    0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
};

static unsigned char g_sm256CorrectBigGX[] = {
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46,
    0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
    0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7
};

static unsigned char g_sm256CorrectBigGY[] = {
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3,
    0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
    0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0
};

// BrainPool160r1
static unsigned char g_bp160r1CorrectBigP[] = {
    0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0xC7, 0xAD,
    0x95, 0xB3, 0xD8, 0x13, 0x95, 0x15, 0x62, 0x0F
};

static unsigned char g_bp160r1CorrectBigB[] = {
    0x1E, 0x58, 0x9A, 0x85, 0x95, 0x42, 0x34, 0x12, 0x13, 0x4F, 0xAA, 0x2D,
    0xBD, 0xEC, 0x95, 0xC8, 0xD8, 0x67, 0x5E, 0x58
};

static unsigned char g_bp160r1CorrectBigGX[] = {
    0xBE, 0xD5, 0xAF, 0x16, 0xEA, 0x3F, 0x6A, 0x4F, 0x62, 0x93, 0x8C, 0x46,
    0x31, 0xEB, 0x5A, 0xF7, 0xBD, 0xBC, 0xDB, 0xC3
};

static unsigned char g_bp160r1CorrectBigGY[] = {
    0x16, 0x67, 0xCB, 0x47, 0x7A, 0x1A, 0x8E, 0xC3, 0x38, 0xF9, 0x47, 0x41,
    0x66, 0x9C, 0x97, 0x63, 0x16, 0xDA, 0x63, 0x21
};

// BrainPool160t1
static unsigned char g_bp160t1CorrectBigP[] = {
    0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC, 0x60, 0xDF, 0xC7, 0xAD,
    0x95, 0xB3, 0xD8, 0x13, 0x95, 0x15, 0x62, 0x0F
};

static unsigned char g_bp160t1CorrectBigB[] = {
    0x7A, 0x55, 0x6B, 0x6D, 0xAE, 0x53, 0x5B, 0x7B, 0x51, 0xED, 0x2C, 0x4D,
    0x7D, 0xAA, 0x7A, 0x0B, 0x5C, 0x55, 0xF3, 0x80
};

static unsigned char g_bp160t1CorrectBigGX[] = {
    0xB1, 0x99, 0xB1, 0x3B, 0x9B, 0x34, 0xEF, 0xC1, 0x39, 0x7E, 0x64, 0xBA,
    0xEB, 0x05, 0xAC, 0xC2, 0x65, 0xFF, 0x23, 0x78
};

static unsigned char g_bp160t1CorrectBigGY[] = {
    0xAD, 0xD6, 0x71, 0x8B, 0x7C, 0x7C, 0x19, 0x61, 0xF0, 0x99, 0x1B, 0x84,
    0x24, 0x43, 0x77, 0x21, 0x52, 0xC9, 0xE0, 0xAD
};

// BrainPool192r1
static unsigned char g_bp192r1CorrectBigP[] = {
    0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30,
    0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97
};

static unsigned char g_bp192r1CorrectBigB[] = {
    0x46, 0x9A, 0x28, 0xEF, 0x7C, 0x28, 0xCC, 0xA3, 0xDC, 0x72, 0x1D, 0x04,
    0x4F, 0x44, 0x96, 0xBC, 0xCA, 0x7E, 0xF4, 0x14, 0x6F, 0xBF, 0x25, 0xC9
};

static unsigned char g_bp192r1CorrectBigGX[] = {
    0xC0, 0xA0, 0x64, 0x7E, 0xAA, 0xB6, 0xA4, 0x87, 0x53, 0xB0, 0x33, 0xC5,
    0x6C, 0xB0, 0xF0, 0x90, 0x0A, 0x2F, 0x5C, 0x48, 0x53, 0x37, 0x5F, 0xD6
};

static unsigned char g_bp192r1CorrectBigGY[] = {
    0x14, 0xB6, 0x90, 0x86, 0x6A, 0xBD, 0x5B, 0xB8, 0x8B, 0x5F, 0x48, 0x28,
    0xC1, 0x49, 0x00, 0x02, 0xE6, 0x77, 0x3F, 0xA2, 0xFA, 0x29, 0x9B, 0x8F
};

// BrainPool192t1
static unsigned char g_bp192t1CorrectBigP[] = {
    0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD, 0xA7, 0xA3, 0x46, 0x30,
    0x93, 0xD1, 0x8D, 0xB7, 0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97
};

static unsigned char g_bp192t1CorrectBigB[] = {
    0x13, 0xD5, 0x6F, 0xFA, 0xEC, 0x78, 0x68, 0x1E, 0x68, 0xF9, 0xDE, 0xB4,
    0x3B, 0x35, 0xBE, 0xC2, 0xFB, 0x68, 0x54, 0x2E, 0x27, 0x89, 0x7B, 0x79
};

static unsigned char g_bp192t1CorrectBigGX[] = {
    0x3A, 0xE9, 0xE5, 0x8C, 0x82, 0xF6, 0x3C, 0x30, 0x28, 0x2E, 0x1F, 0xE7,
    0xBB, 0xF4, 0x3F, 0xA7, 0x2C, 0x44, 0x6A, 0xF6, 0xF4, 0x61, 0x81, 0x29
};

static unsigned char g_bp192t1CorrectBigGY[] = {
    0x09, 0x7E, 0x2C, 0x56, 0x67, 0xC2, 0x22, 0x3A, 0x90, 0x2A, 0xB5, 0xCA,
    0x44, 0x9D, 0x00, 0x84, 0xB7, 0xE5, 0xB3, 0xDE, 0x7C, 0xCC, 0x01, 0xC9
};

// BrainPool224r1
static unsigned char g_bp224r1CorrectBigP[] = {
    0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25,
    0x75, 0xD1, 0xD7, 0x87, 0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5,
    0x7E, 0xC8, 0xC0, 0xFF
};

static unsigned char g_bp224r1CorrectBigB[] = {
    0x25, 0x80, 0xF6, 0x3C, 0xCF, 0xE4, 0x41, 0x38, 0x87, 0x07, 0x13, 0xB1,
    0xA9, 0x23, 0x69, 0xE3, 0x3E, 0x21, 0x35, 0xD2, 0x66, 0xDB, 0xB3, 0x72,
    0x38, 0x6C, 0x40, 0x0B
};

static unsigned char g_bp224r1CorrectBigGX[] = {
    0x0D, 0x90, 0x29, 0xAD, 0x2C, 0x7E, 0x5C, 0xF4, 0x34, 0x08, 0x23, 0xB2,
    0xA8, 0x7D, 0xC6, 0x8C, 0x9E, 0x4C, 0xE3, 0x17, 0x4C, 0x1E, 0x6E, 0xFD,
    0xEE, 0x12, 0xC0, 0x7D
};

static unsigned char g_bp224r1CorrectBigGY[] = {
    0x58, 0xAA, 0x56, 0xF7, 0x72, 0xC0, 0x72, 0x6F, 0x24, 0xC6, 0xB8, 0x9E,
    0x4E, 0xCD, 0xAC, 0x24, 0x35, 0x4B, 0x9E, 0x99, 0xCA, 0xA3, 0xF6, 0xD3,
    0x76, 0x14, 0x02, 0xCD
};

// BrainPool224t1
static unsigned char g_bp224t1CorrectBigP[] = {
    0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86, 0x2A, 0x18, 0x30, 0x25,
    0x75, 0xD1, 0xD7, 0x87, 0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5,
    0x7E, 0xC8, 0xC0, 0xFF
};

static unsigned char g_bp224t1CorrectBigB[] = {
    0x4B, 0x33, 0x7D, 0x93, 0x41, 0x04, 0xCD, 0x7B, 0xEF, 0x27, 0x1B, 0xF6,
    0x0C, 0xED, 0x1E, 0xD2, 0x0D, 0xA1, 0x4C, 0x08, 0xB3, 0xBB, 0x64, 0xF1,
    0x8A, 0x60, 0x88, 0x8D
};

static unsigned char g_bp224t1CorrectBigGX[] = {
    0x6A, 0xB1, 0xE3, 0x44, 0xCE, 0x25, 0xFF, 0x38, 0x96, 0x42, 0x4E, 0x7F,
    0xFE, 0x14, 0x76, 0x2E, 0xCB, 0x49, 0xF8, 0x92, 0x8A, 0xC0, 0xC7, 0x60,
    0x29, 0xB4, 0xD5, 0x80
};

static unsigned char g_bp224t1CorrectBigGY[] = {
    0x03, 0x74, 0xE9, 0xF5, 0x14, 0x3E, 0x56, 0x8C, 0xD2, 0x3F, 0x3F, 0x4D,
    0x7C, 0x0D, 0x4B, 0x1E, 0x41, 0xC8, 0xCC, 0x0D, 0x1C, 0x6A, 0xBD, 0x5F,
    0x1A, 0x46, 0xDB, 0x4C
};

// BrainPool256r1
static unsigned char g_bp256r1CorrectBigP[] = {
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90,
    0x9D, 0x83, 0x8D, 0x72, 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
    0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77
};

static unsigned char g_bp256r1CorrectBigB[] = {
    0x26, 0xDC, 0x5C, 0x6C, 0xE9, 0x4A, 0x4B, 0x44, 0xF3, 0x30, 0xB5, 0xD9,
    0xBB, 0xD7, 0x7C, 0xBF, 0x95, 0x84, 0x16, 0x29, 0x5C, 0xF7, 0xE1, 0xCE,
    0x6B, 0xCC, 0xDC, 0x18, 0xFF, 0x8C, 0x07, 0xB6
};

static unsigned char g_bp256r1CorrectBigGX[] = {
    0x8B, 0xD2, 0xAE, 0xB9, 0xCB, 0x7E, 0x57, 0xCB, 0x2C, 0x4B, 0x48, 0x2F,
    0xFC, 0x81, 0xB7, 0xAF, 0xB9, 0xDE, 0x27, 0xE1, 0xE3, 0xBD, 0x23, 0xC2,
    0x3A, 0x44, 0x53, 0xBD, 0x9A, 0xCE, 0x32, 0x62
};

static unsigned char g_bp256r1CorrectBigGY[] = {
    0x54, 0x7E, 0xF8, 0x35, 0xC3, 0xDA, 0xC4, 0xFD, 0x97, 0xF8, 0x46, 0x1A,
    0x14, 0x61, 0x1D, 0xC9, 0xC2, 0x77, 0x45, 0x13, 0x2D, 0xED, 0x8E, 0x54,
    0x5C, 0x1D, 0x54, 0xC7, 0x2F, 0x04, 0x69, 0x97
};

// BrainPool256t1
static unsigned char g_bp256t1CorrectBigP[] = {
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC, 0x3E, 0x66, 0x0A, 0x90,
    0x9D, 0x83, 0x8D, 0x72, 0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
    0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77
};

static unsigned char g_bp256t1CorrectBigB[] = {
    0x66, 0x2C, 0x61, 0xC4, 0x30, 0xD8, 0x4E, 0xA4, 0xFE, 0x66, 0xA7, 0x73,
    0x3D, 0x0B, 0x76, 0xB7, 0xBF, 0x93, 0xEB, 0xC4, 0xAF, 0x2F, 0x49, 0x25,
    0x6A, 0xE5, 0x81, 0x01, 0xFE, 0xE9, 0x2B, 0x04
};

static unsigned char g_bp256t1CorrectBigGX[] = {
    0xA3, 0xE8, 0xEB, 0x3C, 0xC1, 0xCF, 0xE7, 0xB7, 0x73, 0x22, 0x13, 0xB2,
    0x3A, 0x65, 0x61, 0x49, 0xAF, 0xA1, 0x42, 0xC4, 0x7A, 0xAF, 0xBC, 0x2B,
    0x79, 0xA1, 0x91, 0x56, 0x2E, 0x13, 0x05, 0xF4
};

static unsigned char g_bp256t1CorrectBigGY[] = {
    0x2D, 0x99, 0x6C, 0x82, 0x34, 0x39, 0xC5, 0x6D, 0x7F, 0x7B, 0x22, 0xE1,
    0x46, 0x44, 0x41, 0x7E, 0x69, 0xBC, 0xB6, 0xDE, 0x39, 0xD0, 0x27, 0x00,
    0x1D, 0xAB, 0xE8, 0xF3, 0x5B, 0x25, 0xC9, 0xBE
};

//secp256k1
static unsigned char g_secp256k1CorrectBigP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
};

static unsigned char g_secp256k1CorrectBigB[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07
};

static unsigned char g_secp256k1CorrectBigGX[] = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95,
    0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};

static unsigned char g_secp256k1CorrectBigGY[] = {
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc,
    0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
};

// BrainPool320r1
static unsigned char g_bp320r1CorrectBigP[] = {
    0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E,
    0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF,
    0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28, 0xFC, 0xD4, 0x12, 0xB1,
    0xF1, 0xB3, 0x2E, 0x27
};

static unsigned char g_bp320r1CorrectBigB[] = {
    0x52, 0x08, 0x83, 0x94, 0x9D, 0xFD, 0xBC, 0x42, 0xD3, 0xAD, 0x19, 0x86,
    0x40, 0x68, 0x8A, 0x6F, 0xE1, 0x3F, 0x41, 0x34, 0x95, 0x54, 0xB4, 0x9A,
    0xCC, 0x31, 0xDC, 0xCD, 0x88, 0x45, 0x39, 0x81, 0x6F, 0x5E, 0xB4, 0xAC,
    0x8F, 0xB1, 0xF1, 0xA6
};

static unsigned char g_bp320r1CorrectBigGX[] = {
    0x43, 0xBD, 0x7E, 0x9A, 0xFB, 0x53, 0xD8, 0xB8, 0x52, 0x89, 0xBC, 0xC4,
    0x8E, 0xE5, 0xBF, 0xE6, 0xF2, 0x01, 0x37, 0xD1, 0x0A, 0x08, 0x7E, 0xB6,
    0xE7, 0x87, 0x1E, 0x2A, 0x10, 0xA5, 0x99, 0xC7, 0x10, 0xAF, 0x8D, 0x0D,
    0x39, 0xE2, 0x06, 0x11
};

static unsigned char g_bp320r1CorrectBigGY[] = {
    0x14, 0xFD, 0xD0, 0x55, 0x45, 0xEC, 0x1C, 0xC8, 0xAB, 0x40, 0x93, 0x24,
    0x7F, 0x77, 0x27, 0x5E, 0x07, 0x43, 0xFF, 0xED, 0x11, 0x71, 0x82, 0xEA,
    0xA9, 0xC7, 0x78, 0x77, 0xAA, 0xAC, 0x6A, 0xC7, 0xD3, 0x52, 0x45, 0xD1,
    0x69, 0x2E, 0x8E, 0xE1
};

// BrainPool320t1
static unsigned char g_bp320t1CorrectBigP[] = {
    0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7, 0xE1, 0x3C, 0x78, 0x5E,
    0xD2, 0x01, 0xE0, 0x65, 0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF,
    0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28, 0xFC, 0xD4, 0x12, 0xB1,
    0xF1, 0xB3, 0x2E, 0x27
};

static unsigned char g_bp320t1CorrectBigB[] = {
    0xA7, 0xF5, 0x61, 0xE0, 0x38, 0xEB, 0x1E, 0xD5, 0x60, 0xB3, 0xD1, 0x47,
    0xDB, 0x78, 0x20, 0x13, 0x06, 0x4C, 0x19, 0xF2, 0x7E, 0xD2, 0x7C, 0x67,
    0x80, 0xAA, 0xF7, 0x7F, 0xB8, 0xA5, 0x47, 0xCE, 0xB5, 0xB4, 0xFE, 0xF4,
    0x22, 0x34, 0x03, 0x53
};

static unsigned char g_bp320t1CorrectBigGX[] = {
    0x92, 0x5B, 0xE9, 0xFB, 0x01, 0xAF, 0xC6, 0xFB, 0x4D, 0x3E, 0x7D, 0x49,
    0x90, 0x01, 0x0F, 0x81, 0x34, 0x08, 0xAB, 0x10, 0x6C, 0x4F, 0x09, 0xCB,
    0x7E, 0xE0, 0x78, 0x68, 0xCC, 0x13, 0x6F, 0xFF, 0x33, 0x57, 0xF6, 0x24,
    0xA2, 0x1B, 0xED, 0x52
};

static unsigned char g_bp320t1CorrectBigGY[] = {
    0x63, 0xBA, 0x3A, 0x7A, 0x27, 0x48, 0x3E, 0xBF, 0x66, 0x71, 0xDB, 0xEF,
    0x7A, 0xBB, 0x30, 0xEB, 0xEE, 0x08, 0x4E, 0x58, 0xA0, 0xB0, 0x77, 0xAD,
    0x42, 0xA5, 0xA0, 0x98, 0x9D, 0x1E, 0xE7, 0x1B, 0x1B, 0x9B, 0xC0, 0x45,
    0x5F, 0xB0, 0xD2, 0xC3
};

// BrainPool384r1
static unsigned char g_bp384r1CorrectBigP[] = {
    0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E,
    0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
    0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 0xAC, 0xD3, 0xA7, 0x29,
    0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53
};

static unsigned char g_bp384r1CorrectBigB[] = {
    0x04, 0xA8, 0xC7, 0xDD, 0x22, 0xCE, 0x28, 0x26, 0x8B, 0x39, 0xB5, 0x54,
    0x16, 0xF0, 0x44, 0x7C, 0x2F, 0xB7, 0x7D, 0xE1, 0x07, 0xDC, 0xD2, 0xA6,
    0x2E, 0x88, 0x0E, 0xA5, 0x3E, 0xEB, 0x62, 0xD5, 0x7C, 0xB4, 0x39, 0x02,
    0x95, 0xDB, 0xC9, 0x94, 0x3A, 0xB7, 0x86, 0x96, 0xFA, 0x50, 0x4C, 0x11
};

static unsigned char g_bp384r1CorrectBigGX[] = {
    0x1D, 0x1C, 0x64, 0xF0, 0x68, 0xCF, 0x45, 0xFF, 0xA2, 0xA6, 0x3A, 0x81,
    0xB7, 0xC1, 0x3F, 0x6B, 0x88, 0x47, 0xA3, 0xE7, 0x7E, 0xF1, 0x4F, 0xE3,
    0xDB, 0x7F, 0xCA, 0xFE, 0x0C, 0xBD, 0x10, 0xE8, 0xE8, 0x26, 0xE0, 0x34,
    0x36, 0xD6, 0x46, 0xAA, 0xEF, 0x87, 0xB2, 0xE2, 0x47, 0xD4, 0xAF, 0x1E
};

static unsigned char g_bp384r1CorrectBigGY[] = {
    0x8A, 0xBE, 0x1D, 0x75, 0x20, 0xF9, 0xC2, 0xA4, 0x5C, 0xB1, 0xEB, 0x8E,
    0x95, 0xCF, 0xD5, 0x52, 0x62, 0xB7, 0x0B, 0x29, 0xFE, 0xEC, 0x58, 0x64,
    0xE1, 0x9C, 0x05, 0x4F, 0xF9, 0x91, 0x29, 0x28, 0x0E, 0x46, 0x46, 0x21,
    0x77, 0x91, 0x81, 0x11, 0x42, 0x82, 0x03, 0x41, 0x26, 0x3C, 0x53, 0x15
};

// BrainPool384t1
static unsigned char g_bp384t1CorrectBigP[] = {
    0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28, 0x0F, 0x5D, 0x6F, 0x7E,
    0x50, 0xE6, 0x41, 0xDF, 0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
    0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23, 0xAC, 0xD3, 0xA7, 0x29,
    0x90, 0x1D, 0x1A, 0x71, 0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53
};

static unsigned char g_bp384t1CorrectBigB[] = {
    0x7F, 0x51, 0x9E, 0xAD, 0xA7, 0xBD, 0xA8, 0x1B, 0xD8, 0x26, 0xDB, 0xA6,
    0x47, 0x91, 0x0F, 0x8C, 0x4B, 0x93, 0x46, 0xED, 0x8C, 0xCD, 0xC6, 0x4E,
    0x4B, 0x1A, 0xBD, 0x11, 0x75, 0x6D, 0xCE, 0x1D, 0x20, 0x74, 0xAA, 0x26,
    0x3B, 0x88, 0x80, 0x5C, 0xED, 0x70, 0x35, 0x5A, 0x33, 0xB4, 0x71, 0xEE
};

static unsigned char g_bp384t1CorrectBigGX[] = {
    0x18, 0xDE, 0x98, 0xB0, 0x2D, 0xB9, 0xA3, 0x06, 0xF2, 0xAF, 0xCD, 0x72,
    0x35, 0xF7, 0x2A, 0x81, 0x9B, 0x80, 0xAB, 0x12, 0xEB, 0xD6, 0x53, 0x17,
    0x24, 0x76, 0xFE, 0xCD, 0x46, 0x2A, 0xAB, 0xFF, 0xC4, 0xFF, 0x19, 0x1B,
    0x94, 0x6A, 0x5F, 0x54, 0xD8, 0xD0, 0xAA, 0x2F, 0x41, 0x88, 0x08, 0xCC
};

static unsigned char g_bp384t1CorrectBigGY[] = {
    0x25, 0xAB, 0x05, 0x69, 0x62, 0xD3, 0x06, 0x51, 0xA1, 0x14, 0xAF, 0xD2,
    0x75, 0x5A, 0xD3, 0x36, 0x74, 0x7F, 0x93, 0x47, 0x5B, 0x7A, 0x1F, 0xCA,
    0x3B, 0x88, 0xF2, 0xB6, 0xA2, 0x08, 0xCC, 0xFE, 0x46, 0x94, 0x08, 0x58,
    0x4D, 0xC2, 0xB2, 0x91, 0x26, 0x75, 0xBF, 0x5B, 0x9E, 0x58, 0x29, 0x28
};

// BrainPool512r1
static unsigned char g_bp512r1CorrectBigP[] = {
    0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE,
    0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
    0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 0x7D, 0x4D, 0x9B, 0x00,
    0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
    0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56,
    0x58, 0x3A, 0x48, 0xF3
};

static unsigned char g_bp512r1CorrectBigB[] = {
    0x3D, 0xF9, 0x16, 0x10, 0xA8, 0x34, 0x41, 0xCA, 0xEA, 0x98, 0x63, 0xBC,
    0x2D, 0xED, 0x5D, 0x5A, 0xA8, 0x25, 0x3A, 0xA1, 0x0A, 0x2E, 0xF1, 0xC9,
    0x8B, 0x9A, 0xC8, 0xB5, 0x7F, 0x11, 0x17, 0xA7, 0x2B, 0xF2, 0xC7, 0xB9,
    0xE7, 0xC1, 0xAC, 0x4D, 0x77, 0xFC, 0x94, 0xCA, 0xDC, 0x08, 0x3E, 0x67,
    0x98, 0x40, 0x50, 0xB7, 0x5E, 0xBA, 0xE5, 0xDD, 0x28, 0x09, 0xBD, 0x63,
    0x80, 0x16, 0xF7, 0x23
};

static unsigned char g_bp512r1CorrectBigGX[] = {
    0x81, 0xAE, 0xE4, 0xBD, 0xD8, 0x2E, 0xD9, 0x64, 0x5A, 0x21, 0x32, 0x2E,
    0x9C, 0x4C, 0x6A, 0x93, 0x85, 0xED, 0x9F, 0x70, 0xB5, 0xD9, 0x16, 0xC1,
    0xB4, 0x3B, 0x62, 0xEE, 0xF4, 0xD0, 0x09, 0x8E, 0xFF, 0x3B, 0x1F, 0x78,
    0xE2, 0xD0, 0xD4, 0x8D, 0x50, 0xD1, 0x68, 0x7B, 0x93, 0xB9, 0x7D, 0x5F,
    0x7C, 0x6D, 0x50, 0x47, 0x40, 0x6A, 0x5E, 0x68, 0x8B, 0x35, 0x22, 0x09,
    0xBC, 0xB9, 0xF8, 0x22
};

static unsigned char g_bp512r1CorrectBigGY[] = {
    0x7D, 0xDE, 0x38, 0x5D, 0x56, 0x63, 0x32, 0xEC, 0xC0, 0xEA, 0xBF, 0xA9,
    0xCF, 0x78, 0x22, 0xFD, 0xF2, 0x09, 0xF7, 0x00, 0x24, 0xA5, 0x7B, 0x1A,
    0xA0, 0x00, 0xC5, 0x5B, 0x88, 0x1F, 0x81, 0x11, 0xB2, 0xDC, 0xDE, 0x49,
    0x4A, 0x5F, 0x48, 0x5E, 0x5B, 0xCA, 0x4B, 0xD8, 0x8A, 0x27, 0x63, 0xAE,
    0xD1, 0xCA, 0x2B, 0x2F, 0xA8, 0xF0, 0x54, 0x06, 0x78, 0xCD, 0x1E, 0x0F,
    0x3A, 0xD8, 0x08, 0x92
};

// BrainPool512t1
static unsigned char g_bp512t1CorrectBigP[] = {
    0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B, 0x3F, 0xD4, 0xE6, 0xAE,
    0x33, 0xC9, 0xFC, 0x07, 0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
    0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71, 0x7D, 0x4D, 0x9B, 0x00,
    0x9B, 0xC6, 0x68, 0x42, 0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
    0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85, 0x28, 0xAA, 0x60, 0x56,
    0x58, 0x3A, 0x48, 0xF3
};

static unsigned char g_bp512t1CorrectBigB[] = {
    0x7C, 0xBB, 0xBC, 0xF9, 0x44, 0x1C, 0xFA, 0xB7, 0x6E, 0x18, 0x90, 0xE4,
    0x68, 0x84, 0xEA, 0xE3, 0x21, 0xF7, 0x0C, 0x0B, 0xCB, 0x49, 0x81, 0x52,
    0x78, 0x97, 0x50, 0x4B, 0xEC, 0x3E, 0x36, 0xA6, 0x2B, 0xCD, 0xFA, 0x23,
    0x04, 0x97, 0x65, 0x40, 0xF6, 0x45, 0x00, 0x85, 0xF2, 0xDA, 0xE1, 0x45,
    0xC2, 0x25, 0x53, 0xB4, 0x65, 0x76, 0x36, 0x89, 0x18, 0x0E, 0xA2, 0x57,
    0x18, 0x67, 0x42, 0x3E
};

static unsigned char g_bp512t1CorrectBigGX[] = {
    0x64, 0x0E, 0xCE, 0x5C, 0x12, 0x78, 0x87, 0x17, 0xB9, 0xC1, 0xBA, 0x06,
    0xCB, 0xC2, 0xA6, 0xFE, 0xBA, 0x85, 0x84, 0x24, 0x58, 0xC5, 0x6D, 0xDE,
    0x9D, 0xB1, 0x75, 0x8D, 0x39, 0xC0, 0x31, 0x3D, 0x82, 0xBA, 0x51, 0x73,
    0x5C, 0xDB, 0x3E, 0xA4, 0x99, 0xAA, 0x77, 0xA7, 0xD6, 0x94, 0x3A, 0x64,
    0xF7, 0xA3, 0xF2, 0x5F, 0xE2, 0x6F, 0x06, 0xB5, 0x1B, 0xAA, 0x26, 0x96,
    0xFA, 0x90, 0x35, 0xDA
};

static unsigned char g_bp512t1CorrectBigGY[] = {
    0x5B, 0x53, 0x4B, 0xD5, 0x95, 0xF5, 0xAF, 0x0F, 0xA2, 0xC8, 0x92, 0x37,
    0x6C, 0x84, 0xAC, 0xE1, 0xBB, 0x4E, 0x30, 0x19, 0xB7, 0x16, 0x34, 0xC0,
    0x11, 0x31, 0x15, 0x9C, 0xAE, 0x03, 0xCE, 0xE9, 0xD9, 0x93, 0x21, 0x84,
    0xBE, 0xEF, 0x21, 0x6B, 0xD7, 0x1D, 0xF2, 0xDA, 0xDF, 0x86, 0xA6, 0x27,
    0x30, 0x6E, 0xCF, 0xF9, 0x6D, 0xBB, 0x8B, 0xAC, 0xE1, 0x98, 0xB6, 0x1E,
    0x00, 0xF8, 0xB3, 0x32
};
#endif
