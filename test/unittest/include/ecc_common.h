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

#ifndef ECC_COMMON_H
#define ECC_COMMON_H

#include <string>

#ifdef __cplusplus
extern "C" {
#endif

static unsigned char g_ecc224CorrectBigA[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE
};

static unsigned char g_ecc224CorrectBigN[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45,
    0x5C, 0x5C, 0x2A, 0x3D
};

static unsigned char g_ecc224CorrectBigSk[] = {
    0x3F, 0x0C, 0x48, 0x8E, 0x98, 0x7C, 0x80, 0xBE, 0x0F, 0xEE, 0x52, 0x1F,
    0x8D, 0x90, 0xBE, 0x60, 0x34, 0xEC, 0x69, 0xAE, 0x11, 0xCA, 0x72, 0xAA,
    0x77, 0x74, 0x81, 0xE8
};

static unsigned char g_ecc224CorrectBigPkX[] = {
    0xE8, 0x4F, 0xB0, 0xB8, 0xE7, 0x00, 0x0C, 0xB6, 0x57, 0xD7, 0x97, 0x3C,
    0xF6, 0xB4, 0x2E, 0xD7, 0x8B, 0x30, 0x16, 0x74, 0x27, 0x6D, 0xF7, 0x44,
    0xAF, 0x13, 0x0B, 0x3E
};

static unsigned char g_ecc224CorrectBigPkY[] = {
    0x43, 0x76, 0x67, 0x5C, 0x6F, 0xC5, 0x61, 0x2C, 0x21, 0xA0, 0xFF, 0x2D,
    0x2A, 0x89, 0xD2, 0x98, 0x7D, 0xF7, 0xA2, 0xBC, 0x52, 0x18, 0x3B, 0x59,
    0x82, 0x29, 0x85, 0x55
};

static unsigned char g_ecc224CorrectLittleP[] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff
};

static unsigned char g_ecc224CorrectLittleA[] = {
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff
};

static unsigned char g_ecc224CorrectLittleB[] = {
    0xb4, 0xff, 0x55, 0x23, 0x43, 0x39, 0x0b, 0x27, 0xba, 0xd8, 0xbf, 0xd7,
    0xb7, 0xb0, 0x44, 0x50, 0x56, 0x32, 0x41, 0xf5, 0xab, 0xb3, 0x04, 0x0c,
    0x85, 0x0a, 0x05, 0xb4
};

static unsigned char g_ecc224CorrectLittleGX[] = {
    0x21, 0x1d, 0x5c, 0x11, 0xd6, 0x80, 0x32, 0x34, 0x22, 0x11, 0xc2, 0x56,
    0xd3, 0xc1, 0x03, 0x4a, 0xb9, 0x90, 0x13, 0x32, 0x7f, 0xbf, 0xb4, 0x6b,
    0xbd, 0x0c, 0x0e, 0xb7
};

static unsigned char g_ecc224CorrectLittleGY[] = {
    0x34, 0x7e, 0x00, 0x85, 0x99, 0x81, 0xd5, 0x44, 0x64, 0x47, 0x07, 0x5a,
    0xa0, 0x75, 0x43, 0xcd, 0xe6, 0xdf, 0x22, 0x4c, 0xfb, 0x23, 0xf7, 0xb5,
    0x88, 0x63, 0x37, 0xbd
};

static unsigned char g_ecc224CorrectLittleN[] = {
    0x3d, 0x2a, 0x5c, 0x5c, 0x45, 0x29, 0xdd, 0x13, 0x3e, 0xf0, 0xb8, 0xe0,
    0xa2, 0x16, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff
};

static unsigned char g_ecc224CorrectLittleSk[] = {
    0xe8, 0x81, 0x74, 0x77, 0xaa, 0x72, 0xca, 0x11, 0xae, 0x69, 0xec, 0x34,
    0x60, 0xbe, 0x90, 0x8d, 0x1f, 0x52, 0xee, 0x0f, 0xbe, 0x80, 0x7c, 0x98,
    0x8e, 0x48, 0x0c, 0x3f
};

static unsigned char g_ecc224CorrectLittlePkX[] = {
    0x3e, 0x0b, 0x13, 0xaf, 0x44, 0xf7, 0x6d, 0x27, 0x74, 0x16, 0x30, 0x8b,
    0xd7, 0x2e, 0xb4, 0xf6, 0x3c, 0x97, 0xd7, 0x57, 0xb6, 0x0c, 0x00, 0xe7,
    0xb8, 0xb0, 0x4f, 0xe8
};

static unsigned char g_ecc224CorrectLittlePkY[] = {
    0x55, 0x85, 0x29, 0x82, 0x59, 0x3b, 0x18, 0x52, 0xbc, 0xa2, 0xf7, 0x7d,
    0x98, 0xd2, 0x89, 0x2a, 0x2d, 0xff, 0xa0, 0x21, 0x2c, 0x61, 0xc5, 0x6f,
    0x5c, 0x67, 0x76, 0x43
};

static unsigned char g_ecc256CorrectBigA[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

static unsigned char g_ecc256CorrectBigSk[] = {
    0xB2, 0x81, 0x28, 0x15, 0x22, 0x43, 0x2D, 0xAB, 0x54, 0x67, 0xC3, 0x0D,
    0x1F, 0x2C, 0x5F, 0xA4, 0x5D, 0x2C, 0xC8, 0x9F, 0x30, 0x47, 0xDC, 0x6E,
    0x8C, 0xEC, 0xBA, 0x1E, 0xBE, 0xC2, 0x05, 0x67
};

static unsigned char g_ecc256CorrectBigPkX[] = {
    0x9C, 0x7A, 0xB7, 0x70, 0xD0, 0x15, 0x29, 0x18, 0xB7, 0xCA, 0x13, 0x76,
    0x66, 0xC6, 0xAA, 0xB7, 0x68, 0x19, 0x4F, 0x0C, 0x15, 0xC5, 0xF2, 0x38,
    0xC5, 0xA7, 0xF1, 0xC6, 0x0E, 0x0B, 0x39, 0x23
};

static unsigned char g_ecc256CorrectBigPkY[] = {
    0xA6, 0x31, 0xB0, 0x15, 0x06, 0x44, 0x82, 0x40, 0xD5, 0x10, 0xA9, 0xF7,
    0xDF, 0x79, 0xC1, 0xDE, 0xBD, 0xE4, 0x7E, 0xC2, 0x4F, 0x7D, 0xAC, 0xFF,
    0xF7, 0x47, 0x4E, 0x1C, 0x9F, 0xBA, 0x48, 0xAA
};

static unsigned char g_ecc256CorrectLittleP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc256CorrectLittleA[] = {
    0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc256CorrectLittleB[] = {
    0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B, 0xF6, 0xB0, 0x53, 0xCC,
    0xB0, 0x06, 0x1D, 0x65, 0xBC, 0x86, 0x98, 0x76, 0x55, 0xBD, 0xEB, 0xB3,
    0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A
};

static unsigned char g_ecc256CorrectLittleGX[] = {
    0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4, 0xA0, 0x33, 0xEB, 0x2D,
    0x81, 0x7D, 0x03, 0x77, 0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC, 0xF8,
    0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B
};

static unsigned char g_ecc256CorrectLittleGY[] = {
    0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB, 0xCE, 0x5E, 0x31, 0x6B,
    0x57, 0x33, 0xCE, 0x2B, 0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7, 0x8E,
    0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F
};

static unsigned char g_ecc256CorrectLittleN[] = {
    0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3, 0x84, 0x9E, 0x17, 0xA7,
    0xAD, 0xFA, 0xE6, 0xBC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc256CorrectBigN[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

static unsigned char g_ecc256CorrectLittleSk[] = {
    0x67, 0x05, 0xC2, 0xBE, 0x1E, 0xBA, 0xEC, 0x8C, 0x6E, 0xDC, 0x47, 0x30,
    0x9F, 0xC8, 0x2C, 0x5D, 0xA4, 0x5F, 0x2C, 0x1F, 0x0D, 0xC3, 0x67, 0x54,
    0xAB, 0x2D, 0x43, 0x22, 0x15, 0x28, 0x81, 0xB2
};

static unsigned char g_ecc256CorrectLittlePkX[] = {
    0x23, 0x39, 0x0B, 0x0E, 0xC6, 0xF1, 0xA7, 0xC5, 0x38, 0xF2, 0xC5, 0x15,
    0x0C, 0x4F, 0x19, 0x68, 0xB7, 0xAA, 0xC6, 0x66, 0x76, 0x13, 0xCA, 0xB7,
    0x18, 0x29, 0x15, 0xD0, 0x70, 0xB7, 0x7A, 0x9C
};

static unsigned char g_ecc256CorrectLittlePkY[] = {
    0xAA, 0x48, 0xBA, 0x9F, 0x1C, 0x4E, 0x47, 0xF7, 0xFF, 0xAC, 0x7D, 0x4F,
    0xC2, 0x7E, 0xE4, 0xBD, 0xDE, 0xC1, 0x79, 0xDF, 0xF7, 0xA9, 0x10, 0xD5,
    0x40, 0x82, 0x44, 0x06, 0x15, 0xB0, 0x31, 0xA6,
};

static unsigned char g_ecc384CorrectBigA[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC
};

static unsigned char g_ecc384CorrectBigN[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2,
    0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
};

static unsigned char g_ecc384CorrectBigSk[] = {
    0x93, 0xFA, 0x94, 0x79, 0x43, 0xB2, 0xA4, 0x0B, 0x60, 0xB8, 0x88, 0x51,
    0x45, 0xE5, 0xD7, 0x74, 0x9A, 0x16, 0x10, 0x61, 0x6B, 0xE8, 0xD7, 0x69,
    0xE5, 0x01, 0xF0, 0x8F, 0xED, 0xE3, 0x5B, 0xF2, 0x0E, 0x0A, 0xCC, 0x70,
    0xF6, 0xD7, 0xDF, 0x9A, 0x89, 0x45, 0xB5, 0xCA, 0x34, 0xB2, 0xAA, 0xD8
};

static unsigned char g_ecc384CorrectBigPkX[] = {
    0x66, 0x44, 0xA4, 0x54, 0xF9, 0xC2, 0x3F, 0x47, 0x03, 0xF1, 0xD8, 0x7A,
    0xE4, 0xE9, 0xC5, 0x94, 0xEB, 0x19, 0x99, 0x76, 0x9E, 0x34, 0xD6, 0x3A,
    0x57, 0x89, 0x3F, 0xF2, 0x6B, 0x6F, 0xE7, 0x6E, 0x22, 0x9E, 0x3A, 0x28,
    0x2D, 0xBE, 0x8B, 0x52, 0xFA, 0xDC, 0xE2, 0xB0, 0x5F, 0x5F, 0x82, 0x1A
};

static unsigned char g_ecc384CorrectBigPkY[] = {
    0x78, 0x19, 0x7B, 0x9C, 0xD4, 0x13, 0x7B, 0xFB, 0xD5, 0x5B, 0x95, 0x80,
    0xBB, 0xEE, 0x7E, 0x4F, 0x30, 0x7D, 0xA4, 0x66, 0xD5, 0xB9, 0xC3, 0x95,
    0xB5, 0x62, 0x18, 0x9E, 0x48, 0xCB, 0x1B, 0xC9, 0xE6, 0x2B, 0xB5, 0xA0,
    0xF1, 0xCB, 0x2D, 0xFD, 0x13, 0x15, 0x82, 0x7D, 0xF7, 0x3F, 0x69, 0x1A
};

static unsigned char g_ecc384CorrectLittleP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc384CorrectLittleA[] = {
    0xFC, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc384CorrectLittleB[] = {
    0xEF, 0x2A, 0xEC, 0xD3, 0xED, 0xC8, 0x85, 0x2A, 0x9D, 0xD1, 0x2E, 0x8A,
    0x8D, 0x39, 0x56, 0xC6, 0x5A, 0x87, 0x13, 0x50, 0x8F, 0x08, 0x14, 0x03,
    0x12, 0x41, 0x81, 0xFE, 0x6E, 0x9C, 0x1D, 0x18, 0x19, 0x2D, 0xF8, 0xE3,
    0x6B, 0x05, 0x8E, 0x98, 0xE4, 0xE7, 0x3E, 0xE2, 0xA7, 0x2F, 0x31, 0xB3
};

static unsigned char g_ecc384CorrectLittleGX[] = {
    0xB7, 0x0A, 0x76, 0x72, 0x38, 0x5E, 0x54, 0x3A, 0x6C, 0x29, 0x55, 0xBF,
    0x5D, 0xF2, 0x02, 0x55, 0x38, 0x2A, 0x54, 0x82, 0xE0, 0x41, 0xF7, 0x59,
    0x98, 0x9B, 0xA7, 0x8B, 0x62, 0x3B, 0x1D, 0x6E, 0x74, 0xAD, 0x20, 0xF3,
    0x1E, 0xC7, 0xB1, 0x8E, 0x37, 0x05, 0x8B, 0xBE, 0x22, 0xCA, 0x87, 0xAA
};

static unsigned char g_ecc384CorrectLittleGY[] = {
    0x5F, 0x0E, 0xEA, 0x90, 0x7C, 0x1D, 0x43, 0x7A, 0x9D, 0x81, 0x7E, 0x1D,
    0xCE, 0xB1, 0x60, 0x0A, 0xC0, 0xB8, 0xF0, 0xB5, 0x13, 0x31, 0xDA, 0xE9,
    0x7C, 0x14, 0x9A, 0x28, 0xBD, 0x1D, 0xF4, 0xF8, 0x29, 0xDC, 0x92, 0x92,
    0xBF, 0x98, 0x9E, 0x5D, 0x6F, 0x2C, 0x26, 0x96, 0x4A, 0xDE, 0x17, 0x36
};

static unsigned char g_ecc384CorrectLittleN[] = {
    0x73, 0x29, 0xC5, 0xCC, 0x6A, 0x19, 0xEC, 0xEC, 0x7A, 0xA7, 0xB0, 0x48,
    0xB2, 0x0D, 0x1A, 0x58, 0xDF, 0x2D, 0x37, 0xF4, 0x81, 0x4D, 0x63, 0xC7,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc384CorrectLittleSk[] = {
    0xD8, 0xAA, 0xB2, 0x34, 0xCA, 0xB5, 0x45, 0x89, 0x9A, 0xDF, 0xD7, 0xF6,
    0x70, 0xCC, 0x0A, 0x0E, 0xF2, 0x5B, 0xE3, 0xED, 0x8F, 0xF0, 0x01, 0xE5,
    0x69, 0xD7, 0xE8, 0x6B, 0x61, 0x10, 0x16, 0x9A, 0x74, 0xD7, 0xE5, 0x45,
    0x51, 0x88, 0xB8, 0x60, 0x0B, 0xA4, 0xB2, 0x43, 0x79, 0x94, 0xFA, 0x93
};

static unsigned char g_ecc384CorrectLittlePkX[] = {
    0x1A, 0x82, 0x5F, 0x5F, 0xB0, 0xE2, 0xDC, 0xFA, 0x52, 0x8B, 0xBE, 0x2D,
    0x28, 0x3A, 0x9E, 0x22, 0x6E, 0xE7, 0x6F, 0x6B, 0xF2, 0x3F, 0x89, 0x57,
    0x3A, 0xD6, 0x34, 0x9E, 0x76, 0x99, 0x19, 0xEB, 0x94, 0xC5, 0xE9, 0xE4,
    0x7A, 0xD8, 0xF1, 0x03, 0x47, 0x3F, 0xC2, 0xF9, 0x54, 0xA4, 0x44, 0x66
};

static unsigned char g_ecc384CorrectLittlePkY[] = {
    0x1A, 0x69, 0x3F, 0xF7, 0x7D, 0x82, 0x15, 0x13, 0xFD, 0x2D, 0xCB, 0xF1,
    0xA0, 0xB5, 0x2B, 0xE6, 0xC9, 0x1B, 0xCB, 0x48, 0x9E, 0x18, 0x62, 0xB5,
    0x95, 0xC3, 0xB9, 0xD5, 0x66, 0xA4, 0x7D, 0x30, 0x4F, 0x7E, 0xEE, 0xBB,
    0x80, 0x95, 0x5B, 0xD5, 0xFB, 0x7B, 0x13, 0xD4, 0x9C, 0x7B, 0x19, 0x78
};

static unsigned char g_ecc521CorrectBigA[] = {
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

static unsigned char g_ecc521CorrectBigN[] = {
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86,
    0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
    0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F,
    0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09
};

static unsigned char g_ecc521CorrectBigSk[] = {
    0x00, 0x89, 0xCE, 0xDE, 0x8D, 0xB8, 0x59, 0x2C, 0x29, 0xD2, 0x0F, 0x8A,
    0x2F, 0x4C, 0xF6, 0x1D, 0x84, 0xC9, 0x46, 0x3B, 0x13, 0xF1, 0x75, 0x41,
    0x83, 0x39, 0x16, 0x5D, 0xA4, 0xD1, 0x66, 0x70, 0xCA, 0x78, 0x18, 0x9D,
    0x52, 0xF5, 0x11, 0x60, 0x12, 0xB1, 0xE1, 0x9E, 0x77, 0x5B, 0xD2, 0x45,
    0x19, 0x53, 0x75, 0x31, 0x40, 0x82, 0x90, 0x8C, 0x71, 0x60, 0xBC, 0x92,
    0x68, 0x98, 0xBD, 0x70, 0xC2, 0x5B
};

static unsigned char g_ecc521CorrectBigPkX[] = {
    0x00, 0x8A, 0x43, 0xDD, 0x43, 0x18, 0xE0, 0x03, 0x86, 0x2C, 0xF8, 0x9E,
    0x88, 0xB0, 0x46, 0x44, 0x9E, 0x89, 0x10, 0x61, 0x1F, 0xE8, 0x3C, 0x0A,
    0xBF, 0xB2, 0x80, 0xB5, 0x3F, 0xDC, 0xD1, 0x1A, 0x12, 0xB2, 0x31, 0x2A,
    0xB0, 0x4B, 0xF1, 0x60, 0x98, 0x94, 0x2E, 0xB0, 0xF3, 0x46, 0x5E, 0xB3,
    0x55, 0x10, 0xC4, 0xEC, 0x74, 0x8A, 0xC3, 0xF0, 0x53, 0x25, 0x37, 0x8C,
    0xB2, 0x11, 0x08, 0x66, 0xE3, 0x14
};

static unsigned char g_ecc521CorrectBigPkY[] = {
    0x00, 0x64, 0x25, 0xD3, 0x03, 0x97, 0xF5, 0xC1, 0x59, 0xFE, 0xEC, 0xDF,
    0x24, 0x92, 0x68, 0x2A, 0xBA, 0xE8, 0x8B, 0x8F, 0xD6, 0x28, 0xA8, 0x93,
    0x22, 0x5C, 0x46, 0xF4, 0xE4, 0xA0, 0x48, 0xBD, 0x0D, 0x3F, 0xB2, 0xEA,
    0xAD, 0xB1, 0xD7, 0x08, 0xC7, 0xE2, 0xF3, 0x78, 0x96, 0x33, 0x1D, 0x9F,
    0x84, 0xC8, 0xCE, 0xFB, 0x67, 0xF0, 0x58, 0x2A, 0x1F, 0x7F, 0xBD, 0x82,
    0xA2, 0x59, 0x8F, 0xDC, 0x3E, 0xD5
};

static unsigned char g_ecc521CorrectLittleP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01
};

static unsigned char g_ecc521CorrectLittleA[] = {
    0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01
};

static unsigned char g_ecc521CorrectLittleB[] = {
    0x00, 0x3F, 0x50, 0x6B, 0xD4, 0x1F, 0x45, 0xEF, 0xF1, 0x34, 0x2C, 0x3D,
    0x88, 0xDF, 0x73, 0x35, 0x07, 0xBF, 0xB1, 0x3B, 0xBD, 0xC0, 0x52, 0x16,
    0x7B, 0x93, 0x7E, 0xEC, 0x51, 0x39, 0x19, 0x56, 0xE1, 0x09, 0xF1, 0x8E,
    0x91, 0x89, 0xB4, 0xB8, 0xF3, 0x15, 0xB3, 0x99, 0x5B, 0x72, 0xDA, 0xA2,
    0xEE, 0x40, 0x85, 0xB6, 0xA0, 0x21, 0x9A, 0x92, 0x1F, 0x9A, 0x1C, 0x8E,
    0x61, 0xB9, 0x3E, 0x95, 0x51, 0x00
};

static unsigned char g_ecc521CorrectLittleGX[] = {
    0x66, 0xBD, 0xE5, 0xC2, 0x31, 0x7E, 0x7E, 0xF9, 0x9B, 0x42, 0x6A, 0x85,
    0xC1, 0xB3, 0x48, 0x33, 0xDE, 0xA8, 0xFF, 0xA2, 0x27, 0xC1, 0x1D, 0xFE,
    0x28, 0x59, 0xE7, 0xEF, 0x77, 0x5E, 0x4B, 0xA1, 0xBA, 0x3D, 0x4D, 0x6B,
    0x60, 0xAF, 0x28, 0xF8, 0x21, 0xB5, 0x3F, 0x05, 0x39, 0x81, 0x64, 0x9C,
    0x42, 0xB4, 0x95, 0x23, 0x66, 0xCB, 0x3E, 0x9E, 0xCD, 0xE9, 0x04, 0x04,
    0xB7, 0x06, 0x8E, 0x85, 0xC6, 0x00
};

static unsigned char g_ecc521CorrectLittleGY[] = {
    0x50, 0x66, 0xD1, 0x9F, 0x76, 0x94, 0xBE, 0x88, 0x40, 0xC2, 0x72, 0xA2,
    0x86, 0x70, 0x3C, 0x35, 0x61, 0x07, 0xAD, 0x3F, 0x01, 0xB9, 0x50, 0xC5,
    0x40, 0x26, 0xF4, 0x5E, 0x99, 0x72, 0xEE, 0x97, 0x2C, 0x66, 0x3E, 0x27,
    0x17, 0xBD, 0xAF, 0x17, 0x68, 0x44, 0x9B, 0x57, 0x49, 0x44, 0xF5, 0x98,
    0xD9, 0x1B, 0x7D, 0x2C, 0xB4, 0x5F, 0x8A, 0x5C, 0x04, 0xC0, 0x3B, 0x9A,
    0x78, 0x6A, 0x29, 0x39, 0x18, 0x01
};

static unsigned char g_ecc521CorrectLittleN[] = {
    0x09, 0x64, 0x38, 0x91, 0x1E, 0xB7, 0x6F, 0xBB, 0xAE, 0x47, 0x9C, 0x89,
    0xB8, 0xC9, 0xB5, 0x3B, 0xD0, 0xA5, 0x09, 0xF7, 0x48, 0x01, 0xCC, 0x7F,
    0x6B, 0x96, 0x2F, 0xBF, 0x83, 0x87, 0x86, 0x51, 0xFA, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01
};

static unsigned char g_ecc521CorrectLittleSk[] = {
    0x5B, 0xC2, 0x70, 0xBD, 0x98, 0x68, 0x92, 0xBC, 0x60, 0x71, 0x8C, 0x90,
    0x82, 0x40, 0x31, 0x75, 0x53, 0x19, 0x45, 0xD2, 0x5B, 0x77, 0x9E, 0xE1,
    0xB1, 0x12, 0x60, 0x11, 0xF5, 0x52, 0x9D, 0x18, 0x78, 0xCA, 0x70, 0x66,
    0xD1, 0xA4, 0x5D, 0x16, 0x39, 0x83, 0x41, 0x75, 0xF1, 0x13, 0x3B, 0x46,
    0xC9, 0x84, 0x1D, 0xF6, 0x4C, 0x2F, 0x8A, 0x0F, 0xD2, 0x29, 0x2C, 0x59,
    0xB8, 0x8D, 0xDE, 0xCE, 0x89, 0x00
};

static unsigned char g_ecc521CorrectLittlePkX[] = {
    0x14, 0xE3, 0x66, 0x08, 0x11, 0xB2, 0x8C, 0x37, 0x25, 0x53, 0xF0, 0xC3,
    0x8A, 0x74, 0xEC, 0xC4, 0x10, 0x55, 0xB3, 0x5E, 0x46, 0xF3, 0xB0, 0x2E,
    0x94, 0x98, 0x60, 0xF1, 0x4B, 0xB0, 0x2A, 0x31, 0xB2, 0x12, 0x1A, 0xD1,
    0xDC, 0x3F, 0xB5, 0x80, 0xB2, 0xBF, 0x0A, 0x3C, 0xE8, 0x1F, 0x61, 0x10,
    0x89, 0x9E, 0x44, 0x46, 0xB0, 0x88, 0x9E, 0xF8, 0x2C, 0x86, 0x03, 0xE0,
    0x18, 0x43, 0xDD, 0x43, 0x8A, 0x00
};

static unsigned char g_ecc521CorrectLittlePkY[] = {
    0xD5, 0x3E, 0xDC, 0x8F, 0x59, 0xA2, 0x82, 0xBD, 0x7F, 0x1F, 0x2A, 0x58,
    0xF0, 0x67, 0xFB, 0xCE, 0xC8, 0x84, 0x9F, 0x1D, 0x33, 0x96, 0x78, 0xF3,
    0xE2, 0xC7, 0x08, 0xD7, 0xB1, 0xAD, 0xEA, 0xB2, 0x3F, 0x0D, 0xBD, 0x48,
    0xA0, 0xE4, 0xF4, 0x46, 0x5C, 0x22, 0x93, 0xA8, 0x28, 0xD6, 0x8F, 0x8B,
    0xE8, 0xBA, 0x2A, 0x68, 0x92, 0x24, 0xDF, 0xEC, 0xFE, 0x59, 0xC1, 0xF5,
    0x97, 0x03, 0xD3, 0x25, 0x64, 0x00
};

static unsigned char g_ecc192CorrectBigP[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static unsigned char g_ecc192CorrectBigA[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

static unsigned char g_ecc192CorrectBigB[] = {
    0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7, 0x0F, 0xA7, 0xE9, 0xAB,
    0x72, 0x24, 0x30, 0x49, 0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1
};

static unsigned char g_ecc192CorrectBigGX[] = {
    0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6, 0x7C, 0xBF, 0x20, 0xEB,
    0x43, 0xA1, 0x88, 0x00, 0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12
};

static unsigned char g_ecc192CorrectBigGY[] = {
    0x07, 0x19, 0x2b, 0x95, 0xff, 0xc8, 0xda, 0x78, 0x63, 0x10, 0x11, 0xed,
    0x6b, 0x24, 0xcd, 0xd5, 0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11
};

static unsigned char g_ecc192CorrectBigN[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
};

static unsigned char g_ecc192CorrectLittleP[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static unsigned char g_ecc192CorrectLittleA[] = {
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static unsigned char g_ecc192CorrectLittleB[] = {
    0xb1, 0xb9, 0x46, 0xc1, 0xec, 0xde, 0xb8, 0xfe, 0x49, 0x30, 0x24, 0x72,
    0xab, 0xe9, 0xa7, 0x0f, 0xe7, 0x80, 0x9c, 0xe5, 0x19, 0x05, 0x21, 0x64
};

static unsigned char g_ecc192CorrectLittleGX[] = {
    0x12, 0x10, 0xff, 0x82, 0xfd, 0x0a, 0xff, 0xf4, 0x00, 0x88, 0xa1, 0x43,
    0xeb, 0x20, 0xbf, 0x7c, 0xf6, 0x90, 0x30, 0xb0, 0x0e, 0xa8, 0x8d, 0x18
};

static unsigned char g_ecc192CorrectLittleGY[] = {
    0x11, 0x48, 0x79, 0x1e, 0xa1, 0x77, 0xf9, 0x73, 0xd5, 0xcd, 0x24, 0x6b,
    0xed, 0x11, 0x10, 0x63, 0x78, 0xda, 0xc8, 0xff, 0x95, 0x2b, 0x19, 0x07
};

static unsigned char g_ecc192CorrectLittleN[] = {
    0x31, 0x28, 0xd2, 0xb4, 0xb1, 0xc9, 0x6b, 0x14, 0x36, 0xf8, 0xde, 0x99,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const int ECC224_PUB_KEY_LEN = 80;
static const int ECC224_PRI_KEY_LEN = 44;
static constexpr int32_t NID_SECP192R1_LEN = 24;

static uint8_t g_mockEcc224PubKeyBlobData[ECC224_PUB_KEY_LEN] = { 48, 78, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1,
    6, 5, 43, 129, 4, 0, 33, 3, 58, 0, 4, 252, 171, 11, 115, 79, 252, 109, 120, 46, 97, 131, 145, 207, 141, 146,
    235, 133, 37, 218, 180, 8, 149, 47, 244, 137, 238, 207, 95, 153, 65, 250, 32, 77, 184, 249, 181, 172, 192, 2,
    99, 194, 170, 25, 44, 255, 87, 246, 42, 133, 83, 66, 197, 97, 95, 12, 84 };

static uint8_t g_mockEcc224PriKeyBlobData[ECC224_PRI_KEY_LEN] = { 48, 42, 2, 1, 1, 4, 28, 250, 86, 6, 147, 222, 43,
    252, 139, 90, 139, 5, 33, 184, 230, 26, 68, 94, 57, 145, 229, 146, 49, 221, 119, 206, 32, 198, 19, 160, 7, 6,
    5, 43, 129, 4, 0, 33 };

static std::string g_eccAlgName = "ECC";
static std::string g_eccFieldType = "Fp";
static int32_t g_ecc192CorrectH = 1;
static int32_t g_ecc224CorrectH = 1;
static int32_t g_ecc256CorrectH = 1;
static int32_t g_ecc384CorrectH = 1;
static int32_t g_ecc521CorrectH = 1;

static HcfEccCommParamsSpec g_ecc192CommSpec;
static HcfEccCommParamsSpec g_ecc224CommSpec;
static HcfEccPubKeyParamsSpec g_ecc224PubKeySpec;
static HcfEccPriKeyParamsSpec g_ecc224PriKeySpec;
static HcfEccKeyPairParamsSpec g_ecc224KeyPairSpec;
static HcfEccCommParamsSpec g_ecc256CommSpec;
static HcfEccPubKeyParamsSpec g_ecc256PubKeySpec;
static HcfEccPriKeyParamsSpec g_ecc256PriKeySpec;
static HcfEccKeyPairParamsSpec g_ecc256KeyPairSpec;
static HcfEccCommParamsSpec g_ecc384CommSpec;
static HcfEccPubKeyParamsSpec g_ecc384PubKeySpec;
static HcfEccPriKeyParamsSpec g_ecc384PriKeySpec;
static HcfEccKeyPairParamsSpec g_ecc384KeyPairSpec;
static HcfEccCommParamsSpec g_ecc521CommSpec;
static HcfEccPubKeyParamsSpec g_ecc521PubKeySpec;
static HcfEccPriKeyParamsSpec g_ecc521PriKeySpec;
static HcfEccKeyPairParamsSpec g_ecc521KeyPairSpec;
static HcfECFieldFp g_fieldFp;

#ifdef __cplusplus
}
#endif
#endif