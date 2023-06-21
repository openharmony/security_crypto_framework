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

#include <gtest/gtest.h>
#include "securec.h"

#include "asy_key_generator.h"
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaAsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaAsyKeyGeneratorBySpecTest::SetUpTestCase() {}

void CryptoRsaAsyKeyGeneratorBySpecTest::TearDownTestCase() {}

void CryptoRsaAsyKeyGeneratorBySpecTest::SetUp() {}

void CryptoRsaAsyKeyGeneratorBySpecTest::TearDown() {}

namespace {
constexpr uint32_t RSA_512_N_BYTE_SIZE = 64;
constexpr uint32_t RSA_512_D_BYTE_SIZE = 64;
constexpr uint32_t RSA_512_E_BYTE_SIZE = 3;

constexpr uint32_t RSA_768_N_BYTE_SIZE = 96;
constexpr uint32_t RSA_768_D_BYTE_SIZE = 96;
constexpr uint32_t RSA_768_E_BYTE_SIZE = 3;

constexpr uint32_t RSA_1024_N_BYTE_SIZE = 128;
constexpr uint32_t RSA_1024_D_BYTE_SIZE = 128;
constexpr uint32_t RSA_1024_E_BYTE_SIZE = 3;

constexpr uint32_t RSA_2048_N_BYTE_SIZE = 256;
constexpr uint32_t RSA_2048_D_BYTE_SIZE = 256;
constexpr uint32_t RSA_2048_E_BYTE_SIZE = 3;

constexpr uint32_t RSA_3072_N_BYTE_SIZE = 384;
constexpr uint32_t RSA_3072_D_BYTE_SIZE = 384;
constexpr uint32_t RSA_3072_E_BYTE_SIZE = 3;

constexpr uint32_t RSA_4096_N_BYTE_SIZE = 512;
constexpr uint32_t RSA_4096_D_BYTE_SIZE = 512;
constexpr uint32_t RSA_4096_E_BYTE_SIZE = 3;

constexpr uint32_t RSA_8192_N_BYTE_SIZE = 1024;
constexpr uint32_t RSA_8192_D_BYTE_SIZE = 1024;
constexpr uint32_t RSA_8192_E_BYTE_SIZE = 3;

constexpr unsigned char CORRECT_512_N[] = {
    0x9f, 0x25, 0x5d, 0x8b, 0xf9, 0xe1, 0x5c, 0xa8, 0x6f, 0xa3, 0xf1, 0x62, 0x0c, 0x4b,
    0x78, 0xc4, 0x44, 0x66, 0xe6, 0xe1, 0xe1, 0xf7, 0x29, 0x9c, 0x0f, 0xd7, 0xd1, 0x40,
    0x57, 0x46, 0x15, 0x1a, 0x1b, 0x93, 0xea, 0xf2, 0x8d, 0x13, 0xb6, 0x22, 0x3e, 0xc6,
    0x98, 0x2e, 0xf5, 0x47, 0xd2, 0x83, 0x97, 0x6a, 0x2e, 0x60, 0x43, 0xb2, 0xfe, 0x8b,
    0x7e, 0xf7, 0x36, 0x32, 0xce, 0x27, 0x49, 0xb5
};

constexpr unsigned char CORRECT_512_D[] = {
    0x73, 0xf2, 0xc1, 0x49, 0x2e, 0x71, 0x67, 0x14, 0xc0, 0xe1, 0xed, 0x07, 0xc6, 0x75, 0x66,
    0x33, 0x78, 0xb2, 0x90, 0x1c, 0x9a, 0x89, 0x7d, 0x23, 0x5a, 0xd7, 0x9e, 0x79, 0x06, 0x1c,
    0xe5, 0x59, 0xcd, 0xf7, 0xf4, 0x16, 0xf0, 0xc2, 0xd8, 0xb3, 0x3e, 0x3e, 0x14, 0xd3, 0x6e,
    0xc6, 0x8a, 0x6a, 0x22, 0xb4, 0x84, 0x01, 0x66, 0xf2, 0x61, 0x49, 0xe6, 0x43, 0x9f, 0x8c,
    0x54, 0x0d, 0xdc, 0x01
};

constexpr unsigned char CORRECT_768_N[] = {
    0xa0, 0x65, 0x4e, 0x6c, 0x75, 0x3b, 0x3b, 0x50, 0x13, 0xbe, 0xf5, 0xc4, 0x1d, 0x22, 0xca,
    0x4f, 0x39, 0xb0, 0xa0, 0xf4, 0xf2, 0x78, 0x12, 0xea, 0x2e, 0x03, 0x2b, 0xec, 0x84, 0x05,
    0xcc, 0xa9, 0x3e, 0xc3, 0x77, 0xf7, 0x26, 0x14, 0x75, 0x3e, 0xda, 0x87, 0x7e, 0xb4, 0xf4,
    0x51, 0xbd, 0x08, 0x10, 0x71, 0x61, 0xf6, 0xc2, 0x34, 0xd1, 0xb3, 0xa6, 0x0d, 0xe7, 0x52,
    0x82, 0xb9, 0xb1, 0x85, 0x0f, 0xad, 0x09, 0x1c, 0x37, 0x25, 0xb4, 0x70, 0x75, 0xfa, 0xb8,
    0x17, 0xe9, 0x97, 0x99, 0x1b, 0xa6, 0xb4, 0x03, 0x0e, 0x54, 0x4d, 0x0d, 0x41, 0xfd, 0xbe,
    0x96, 0xe2, 0xb8, 0xa4, 0xb1, 0x8b
};

constexpr unsigned char CORRECT_768_D[] = {
    0x47, 0x26, 0xa9, 0x73, 0x53, 0x4d, 0xc3, 0x31, 0xf2, 0x90, 0x73, 0x55, 0x5b, 0xd7, 0x63,
    0x07, 0x62, 0x00, 0x08, 0x66, 0xa0, 0x68, 0xc3, 0x7b, 0x3e, 0x8e, 0x09, 0x9e, 0x11, 0xb2,
    0xc0, 0xe7, 0x13, 0x00, 0x82, 0xe7, 0x0f, 0xed, 0x63, 0x55, 0x4e, 0x7b, 0x6c, 0xa9, 0xb8,
    0xf7, 0xc9, 0x72, 0x66, 0x51, 0xb8, 0x72, 0x53, 0x0a, 0x77, 0xcd, 0x84, 0xdc, 0xb0, 0x4b,
    0xb0, 0x07, 0x92, 0x81, 0x77, 0xaf, 0x22, 0x1a, 0x08, 0x17, 0x6b, 0xf2, 0xd3, 0xf9, 0xd3,
    0x0e, 0x62, 0x01, 0xdd, 0x1e, 0xc5, 0xa6, 0xa8, 0xb0, 0x75, 0xb1, 0x69, 0x45, 0x9c, 0xde,
    0xe3, 0xc2, 0x39, 0x09, 0x32, 0x01
};

constexpr unsigned char CORRECT_1024_N[] = {
    0xce, 0x2c, 0xc7, 0xeb, 0xb4, 0xf0, 0xe8, 0x49, 0xec, 0xc8, 0xa3, 0x4f, 0x01, 0xd1, 0x43,
    0x30, 0xa8, 0xe8, 0x30, 0x1a, 0x1f, 0x2f, 0xe8, 0x17, 0x98, 0x5b, 0x30, 0x15, 0x98, 0x1b,
    0xc1, 0x84, 0xde, 0x10, 0x36, 0xaf, 0x90, 0x8d, 0x34, 0x98, 0x5c, 0x15, 0x0c, 0x2e, 0xe9,
    0x07, 0x35, 0x5b, 0x29, 0x12, 0x6d, 0xdf, 0xc7, 0x5b, 0x3a, 0x2f, 0xae, 0x2e, 0xe4, 0x7d,
    0x14, 0xd6, 0xa9, 0x41, 0x73, 0x08, 0x17, 0xc1, 0x77, 0x87, 0x9e, 0x69, 0x47, 0xb3, 0xf8,
    0xf4, 0x1c, 0xc1, 0x13, 0x9b, 0xeb, 0x34, 0x84, 0xca, 0x28, 0x6e, 0x63, 0x4e, 0x28, 0x7a,
    0x22, 0x32, 0xef, 0xd6, 0xde, 0xe5, 0x46, 0x6e, 0xbe, 0x8d, 0x31, 0x56, 0x45, 0x24, 0xc9,
    0x99, 0xb9, 0xad, 0x45, 0xdd, 0x22, 0x49, 0xd3, 0xde, 0xf7, 0x1f, 0x38, 0x44, 0x42, 0x7e,
    0xff, 0xdc, 0xd3, 0x6f, 0x93, 0xbb, 0x1c, 0x3d
};
constexpr unsigned char CORRECT_1024_D[] = {
    0x27, 0x52, 0xfb, 0x3e, 0xc5, 0xe0, 0x3d, 0x2d, 0xfc, 0x6f, 0xb8, 0x56, 0x55, 0x6e, 0x68,
    0x76, 0x5b, 0x81, 0x0d, 0xcb, 0xad, 0xaf, 0x21, 0x81, 0x7e, 0x99, 0xc5, 0xee, 0x18, 0x79,
    0x12, 0xcc, 0x18, 0xde, 0xd6, 0xcf, 0x5d, 0xae, 0xd1, 0x1d, 0x4e, 0x52, 0xe5, 0x63, 0xfd,
    0x26, 0x56, 0xd2, 0xf0, 0x5e, 0x87, 0x7e, 0x6b, 0x33, 0xc7, 0x41, 0x58, 0xe3, 0xb0, 0xc8,
    0xfa, 0xb4, 0x86, 0xcb, 0x90, 0xd5, 0x85, 0xb9, 0xa0, 0x35, 0x32, 0xb9, 0xe2, 0xf5, 0x3c,
    0x46, 0xe5, 0xb2, 0xd8, 0x5e, 0x27, 0x2e, 0x80, 0x8b, 0xfc, 0x6a, 0xd5, 0x88, 0xe1, 0xcb,
    0x02, 0xf7, 0xde, 0x6b, 0x26, 0x5b, 0x63, 0xd4, 0xfd, 0x26, 0x23, 0x4f, 0x28, 0x71, 0xc0,
    0xc0, 0x56, 0x80, 0x38, 0xcc, 0xbe, 0x7e, 0xe4, 0x76, 0xd2, 0x2d, 0x31, 0x1a, 0xeb, 0xa4,
    0x6d, 0x45, 0x64, 0x34, 0xbe, 0xd2, 0x3b, 0x01
};

constexpr unsigned char CORRECT_2048_N[] =
    "\x92\x60\xd0\x75\x0a\xe1\x17\xee\xe5\x5c\x3f\x3d\xea\xba\x74\x91"
    "\x75\x21\xa2\x62\xee\x76\x00\x7c\xdf\x8a\x56\x75\x5a\xd7\x3a\x15"
    "\x98\xa1\x40\x84\x10\xa0\x14\x34\xc3\xf5\xbc\x54\xa8\x8b\x57\xfa"
    "\x19\xfc\x43\x28\xda\xea\x07\x50\xa4\xc4\x4e\x88\xcf\xf3\xb2\x38"
    "\x26\x21\xb8\x0f\x67\x04\x64\x43\x3e\x43\x36\xe6\xd0\x03\xe8\xcd"
    "\x65\xbf\xf2\x11\xda\x14\x4b\x88\x29\x1c\x22\x59\xa0\x0a\x72\xb7"
    "\x11\xc1\x16\xef\x76\x86\xe8\xfe\xe3\x4e\x4d\x93\x3c\x86\x81\x87"
    "\xbd\xc2\x6f\x7b\xe0\x71\x49\x3c\x86\xf7\xa5\x94\x1c\x35\x10\x80"
    "\x6a\xd6\x7b\x0f\x94\xd8\x8f\x5c\xf5\xc0\x2a\x09\x28\x21\xd8\x62"
    "\x6e\x89\x32\xb6\x5c\x5b\xd8\xc9\x20\x49\xc2\x10\x93\x2b\x7a\xfa"
    "\x7a\xc5\x9c\x0e\x88\x6a\xe5\xc1\xed\xb0\x0d\x8c\xe2\xc5\x76\x33"
    "\xdb\x26\xbd\x66\x39\xbf\xf7\x3c\xee\x82\xbe\x92\x75\xc4\x02\xb4"
    "\xcf\x2a\x43\x88\xda\x8c\xf8\xc6\x4e\xef\xe1\xc5\xa0\xf5\xab\x80"
    "\x57\xc3\x9f\xa5\xc0\x58\x9c\x3e\x25\x3f\x09\x60\x33\x23\x00\xf9"
    "\x4b\xea\x44\x87\x7b\x58\x8e\x1e\xdb\xde\x97\xcf\x23\x60\x72\x7a"
    "\x09\xb7\x75\x26\x2d\x7e\xe5\x52\xb3\x31\x9b\x92\x66\xf0\x5a\x25";

constexpr unsigned char CORRECT_E[] = "\x01\x00\x01";

constexpr unsigned char CORRECT_2048_D[] =
    "\x6a\x7d\xf2\xca\x63\xea\xd4\xdd\xa1\x91\xd6\x14\xb6\xb3\x85\xe0"
    "\xd9\x05\x6a\x3d\x6d\x5c\xfe\x07\xdb\x1d\xaa\xbe\xe0\x22\xdb\x08"
    "\x21\x2d\x97\x61\x3d\x33\x28\xe0\x26\x7c\x9d\xd2\x3d\x78\x7a\xbd"
    "\xe2\xaf\xcb\x30\x6a\xeb\x7d\xfc\xe6\x92\x46\xcc\x73\xf5\xc8\x7f"
    "\xdf\x06\x03\x01\x79\xa2\x11\x4b\x76\x7d\xb1\xf0\x83\xff\x84\x1c"
    "\x02\x5d\x7d\xc0\x0c\xd8\x24\x35\xb9\xa9\x0f\x69\x53\x69\xe9\x4d"
    "\xf2\x3d\x2c\xe4\x58\xbc\x3b\x32\x83\xad\x8b\xba\x2b\x8f\xa1\xba"
    "\x62\xe2\xdc\xe9\xac\xcf\xf3\x79\x9a\xae\x7c\x84\x00\x16\xf3\xba"
    "\x8e\x00\x48\xc0\xb6\xcc\x43\x39\xaf\x71\x61\x00\x3a\x5b\xeb\x86"
    "\x4a\x01\x64\xb2\xc1\xc9\x23\x7b\x64\xbc\x87\x55\x69\x94\x35\x1b"
    "\x27\x50\x6c\x33\xd4\xbc\xdf\xce\x0f\x9c\x49\x1a\x7d\x6b\x06\x28"
    "\xc7\xc8\x52\xbe\x4f\x0a\x9c\x31\x32\xb2\xed\x3a\x2c\x88\x81\xe9"
    "\xaa\xb0\x7e\x20\xe1\x7d\xeb\x07\x46\x91\xbe\x67\x77\x76\xa7\x8b"
    "\x5c\x50\x2e\x05\xd9\xbd\xde\x72\x12\x6b\x37\x38\x69\x5e\x2d\xd1"
    "\xa0\xa9\x8a\x14\x24\x7c\x65\xd8\xa7\xee\x79\x43\x2a\x09\x2c\xb0"
    "\x72\x1a\x12\xdf\x79\x8e\x44\xf7\xcf\xce\x0c\x49\x81\x47\xa9\xb1";

constexpr unsigned char CORRECT_3072_N[] = {
    0xf9, 0xb0, 0xc2, 0x4b, 0xe4, 0x8f, 0x50, 0x2c, 0xb9, 0xb3, 0xa5, 0x14, 0x4b, 0xeb, 0x21,
    0xa4, 0xa0, 0x2a, 0xc2, 0x0a, 0x89, 0xcb, 0x58, 0x40, 0xf3, 0x94, 0x1b, 0x6d, 0xc6, 0x38,
    0xd3, 0x87, 0x58, 0x8f, 0x52, 0x8e, 0x47, 0x32, 0xf3, 0xa5, 0x5a, 0xcd, 0x75, 0x43, 0xce,
    0x74, 0x7e, 0x9f, 0x41, 0xad, 0xad, 0x24, 0xe0, 0x0d, 0xb3, 0xaa, 0xe7, 0x58, 0xe1, 0xa3,
    0x5f, 0x38, 0xbc, 0x1c, 0xa8, 0xe5, 0xba, 0x1f, 0xb4, 0x05, 0x7f, 0xa8, 0xc4, 0x40, 0x95,
    0x20, 0xd4, 0xbf, 0x8f, 0x03, 0xac, 0x0f, 0x7f, 0x7a, 0x8a, 0xba, 0x13, 0x11, 0x76, 0x49,
    0x48, 0xc8, 0x67, 0x24, 0xda, 0x3e, 0xeb, 0x29, 0x24, 0xb2, 0x6d, 0x61, 0xa0, 0x5f, 0x7e,
    0xe1, 0x5b, 0x87, 0xca, 0xc8, 0x5b, 0x06, 0xed, 0x7d, 0xb2, 0x6e, 0xd4, 0x17, 0xde, 0x24,
    0xcb, 0x65, 0xbc, 0x8d, 0xe4, 0x5d, 0x00, 0x73, 0x21, 0xc0, 0x05, 0x3a, 0x00, 0xe3, 0xa6,
    0x92, 0x17, 0x25, 0x47, 0x49, 0xbe, 0x56, 0x08, 0x74, 0x23, 0x3a, 0x18, 0x1f, 0xd7, 0x8e,
    0xa7, 0xc5, 0xec, 0x7c, 0x05, 0x75, 0xd0, 0x83, 0x7a, 0xc4, 0xd7, 0x8a, 0x7f, 0xbf, 0xc6,
    0xe9, 0x43, 0x29, 0xe9, 0x67, 0xe5, 0x04, 0x48, 0xe1, 0x81, 0x53, 0x54, 0xbb, 0x8e, 0xa1,
    0x3a, 0x95, 0xd1, 0x6b, 0x93, 0xb4, 0xb2, 0xc3, 0x6e, 0x28, 0x05, 0x45, 0xdf, 0x6e, 0xe8,
    0x74, 0x49, 0x01, 0xb3, 0x26, 0xef, 0xa1, 0x78, 0xba, 0x4d, 0x11, 0xf1, 0x42, 0xfd, 0x91,
    0x0d, 0x0f, 0x23, 0xfa, 0x0f, 0x9d, 0xe9, 0xa5, 0x57, 0xdc, 0xd1, 0x7e, 0xce, 0x83, 0x42,
    0xa4, 0x7f, 0xa6, 0x96, 0xe1, 0x66, 0xc3, 0xa6, 0x65, 0x7a, 0xa3, 0xa8, 0x7a, 0x6d, 0x3d,
    0xf4, 0x97, 0x84, 0xae, 0x96, 0xce, 0x2d, 0x45, 0x69, 0xe0, 0x13, 0xbd, 0xd9, 0xec, 0x23,
    0x2a, 0xad, 0xa0, 0x8c, 0xfc, 0xd3, 0x08, 0xc9, 0x27, 0x28, 0xca, 0xd5, 0x4d, 0x29, 0x3e,
    0x4c, 0xf9, 0x49, 0xd3, 0x09, 0xce, 0xe7, 0x9f, 0xda, 0x83, 0xe6, 0x7e, 0xe4, 0x34, 0xf9,
    0x52, 0xc1, 0x63, 0x6b, 0xd5, 0x53, 0x7b, 0x99, 0x8c, 0x1b, 0xb5, 0x65, 0xca, 0x4b, 0x0d,
    0xd3, 0xd4, 0x74, 0x6e, 0x8f, 0x25, 0x99, 0x68, 0x9d, 0x00, 0x89, 0x8c, 0x09, 0x30, 0x8f,
    0x22, 0x13, 0x77, 0x5d, 0xf8, 0xb2, 0xc1, 0x0f, 0x01, 0x17, 0x91, 0x0c, 0x1b, 0x8b, 0xa2,
    0xe5, 0x24, 0xd6, 0xef, 0x34, 0xc8, 0x21, 0xc8, 0x32, 0x1d, 0x89, 0x48, 0x73, 0x43, 0x25,
    0x70, 0xdc, 0x08, 0x2d, 0x49, 0x8a, 0x9d, 0x73, 0xe4, 0xd8, 0x56, 0x86, 0xc4, 0x0d, 0x85,
    0x65, 0x88, 0x57, 0x3f, 0xe0, 0x83, 0x0a, 0x9c, 0x51, 0x35, 0x82, 0xf2, 0x89, 0x48, 0x4e,
    0x8e, 0x70, 0x7f, 0xd5, 0xa8, 0x04, 0xae, 0xe3, 0x87
};
constexpr unsigned char CORRECT_3072_D[] = {
    0x2f, 0xba, 0x10, 0xb9, 0x8e, 0xfb, 0xb1, 0xd8, 0x8a, 0xba, 0x82, 0xf0, 0x69, 0x3e, 0x8d,
    0x94, 0xb9, 0x24, 0xd3, 0x28, 0x4e, 0x84, 0x76, 0xdf, 0x1b, 0x70, 0x10, 0xfa, 0x1f, 0xac,
    0x97, 0x0a, 0x44, 0xec, 0x48, 0x5c, 0x77, 0xd1, 0x8e, 0x6e, 0xe9, 0xf7, 0x61, 0xd5, 0xcf,
    0x2d, 0xc7, 0x52, 0x4b, 0xac, 0x95, 0xee, 0xf9, 0x80, 0xc4, 0xfa, 0x02, 0xf4, 0xa3, 0x54,
    0xa6, 0x0b, 0xe3, 0x31, 0x1b, 0x3b, 0xa6, 0x23, 0x0f, 0x37, 0x09, 0xda, 0xc9, 0x80, 0x8a,
    0xc0, 0xd6, 0xc9, 0xb2, 0xdd, 0x81, 0xd3, 0x08, 0x8b, 0xf4, 0xde, 0x72, 0x6c, 0xa1, 0x0e,
    0x8b, 0x01, 0xfb, 0x6d, 0x38, 0xe6, 0x53, 0xee, 0xee, 0x5b, 0xc8, 0xba, 0xa3, 0x7b, 0xfd,
    0x75, 0xb8, 0x18, 0x31, 0xb3, 0xb0, 0x6a, 0x97, 0x94, 0xb2, 0x39, 0xab, 0x02, 0xd0, 0xec,
    0x79, 0x90, 0x7d, 0xc5, 0x25, 0x84, 0x7d, 0x64, 0x84, 0x6b, 0xfe, 0xd3, 0xc2, 0x7d, 0xc1,
    0x46, 0x25, 0x74, 0x73, 0xb6, 0xed, 0xd1, 0xe6, 0x15, 0xc4, 0xf2, 0x02, 0xd0, 0x7b, 0x54,
    0x82, 0x4f, 0x3b, 0xcf, 0xcc, 0xff, 0x63, 0x16, 0xee, 0xad, 0x97, 0x81, 0x9a, 0xbf, 0x9e,
    0x96, 0xd1, 0xc6, 0xbe, 0x1d, 0xa4, 0xd1, 0xf7, 0xd8, 0x5a, 0xef, 0x01, 0xc0, 0x44, 0x18,
    0x1f, 0x69, 0xa9, 0xb9, 0x05, 0x67, 0xc1, 0xcf, 0xc7, 0x4b, 0x91, 0x0e, 0x14, 0x6a, 0x6b,
    0x92, 0xad, 0x33, 0x3d, 0xbf, 0x09, 0xbb, 0xaf, 0x36, 0xcd, 0x7d, 0xaf, 0x33, 0xcf, 0xbe,
    0x2f, 0x6e, 0x60, 0xf6, 0x51, 0xb9, 0x7b, 0x7a, 0x1d, 0x95, 0x0c, 0x39, 0xec, 0xe0, 0xbe,
    0xfe, 0x5a, 0x2c, 0x68, 0xfe, 0x06, 0x04, 0xbc, 0xdb, 0xe6, 0xfd, 0x7f, 0x19, 0xc5, 0x15,
    0xad, 0x0c, 0x82, 0x91, 0x04, 0x1c, 0xf4, 0x98, 0x40, 0xf3, 0xca, 0xcc, 0xf7, 0xf9, 0xd0,
    0xac, 0xd8, 0xee, 0x1c, 0x8f, 0x69, 0x72, 0x3a, 0xa9, 0xd1, 0xaf, 0x90, 0x00, 0x55, 0x1d,
    0x9a, 0x72, 0x9d, 0xd3, 0x3d, 0x02, 0xe9, 0x79, 0xa2, 0x95, 0x13, 0xa9, 0x6f, 0x8e, 0xaf,
    0xa3, 0x39, 0xe8, 0x3b, 0x01, 0x31, 0x51, 0xc5, 0x46, 0x77, 0xbb, 0xe5, 0x5f, 0xd6, 0x4d,
    0x19, 0x54, 0xff, 0xd2, 0x40, 0x40, 0x1e, 0x9f, 0x54, 0x69, 0x99, 0xad, 0x12, 0xfe, 0xb5,
    0xa8, 0xbb, 0x19, 0x9b, 0xcc, 0x63, 0xf7, 0x6d, 0x77, 0xa2, 0x9c, 0x55, 0x33, 0x6c, 0x08,
    0x95, 0x27, 0x5f, 0x84, 0xb5, 0x9e, 0x2d, 0xa7, 0x96, 0x46, 0x38, 0xf7, 0x29, 0x66, 0xd7,
    0x01, 0x19, 0x7c, 0xfd, 0x45, 0x87, 0x81, 0xb0, 0xdd, 0xcd, 0x04, 0x73, 0x6a, 0x79, 0xbc,
    0x77, 0xd7, 0x1d, 0x29, 0x9b, 0xd4, 0x66, 0xec, 0x6d, 0x4f, 0x84, 0xb9, 0xad, 0xcd, 0x6d,
    0x40, 0x2f, 0xf5, 0x75, 0x1d, 0x3a, 0xbf, 0x01, 0xa9
};


constexpr unsigned char CORRECT_4096_N[] = {
    0xc4, 0x68, 0xa2, 0x94, 0x23, 0xd8, 0xf4, 0x02, 0xf2, 0x0a, 0x0c, 0x50, 0xc8, 0xc2, 0xd5, 0xe5,
    0x57, 0xfe, 0xf7, 0x3a, 0x51, 0x4e, 0xad, 0x2c, 0x91, 0x58, 0x58, 0x0d, 0xdb, 0x4d, 0x0c, 0x58,
    0x92, 0x42, 0x07, 0x60, 0x1a, 0xb1, 0x07, 0x97, 0xb9, 0x63, 0xeb, 0x51, 0xef, 0x75, 0x69, 0xe5,
    0x9a, 0xc7, 0xef, 0xee, 0x20, 0x2f, 0xf2, 0x39, 0x61, 0x7b, 0x0e, 0x6b, 0xf6, 0x07, 0x30, 0xbf,
    0x30, 0xb4, 0x88, 0x64, 0xf0, 0xde, 0xcc, 0x47, 0xd5, 0xad, 0x7d, 0xfb, 0x81, 0x4d, 0x81, 0xde,
    0xa7, 0x0b, 0xb1, 0xff, 0xfd, 0x40, 0xca, 0xf8, 0xed, 0xfb, 0x62, 0x2d, 0x83, 0xa8, 0xcc, 0xdc,
    0x7a, 0x96, 0xea, 0x75, 0x39, 0x8f, 0xc5, 0x50, 0x86, 0x51, 0x04, 0x7d, 0x13, 0x94, 0x17, 0xed,
    0x1a, 0x90, 0xd8, 0x0f, 0xa3, 0xd7, 0x96, 0x87, 0x49, 0xa8, 0x6c, 0x51, 0x25, 0x2c, 0x0c, 0xf4,
    0x50, 0x5d, 0xfe, 0xf9, 0x4c, 0x94, 0x83, 0x40, 0xf5, 0x46, 0xa9, 0xcd, 0x42, 0x61, 0x89, 0x8c,
    0x52, 0x6f, 0xdc, 0x72, 0x5f, 0xfb, 0x11, 0x87, 0x37, 0x00, 0xb1, 0x46, 0x12, 0x93, 0xb9, 0x60,
    0x94, 0x00, 0x7c, 0x81, 0xc1, 0x48, 0xd7, 0xd3, 0x51, 0xe9, 0x3a, 0x0f, 0x59, 0xad, 0xd3, 0x9f,
    0x7c, 0x8d, 0x22, 0x61, 0x45, 0xeb, 0x5e, 0x1f, 0x7c, 0xa0, 0x15, 0xb9, 0x8e, 0x4e, 0xe3, 0xca,
    0xc5, 0x2c, 0x0d, 0x1e, 0x20, 0x76, 0x12, 0xa6, 0x9d, 0xf4, 0x95, 0x6b, 0xa2, 0x9b, 0x92, 0xf3,
    0xc9, 0x28, 0x2e, 0x97, 0x81, 0xac, 0xd6, 0x2f, 0x98, 0x43, 0xa7, 0xf5, 0x80, 0x8f, 0xc7, 0xfd,
    0x9c, 0x04, 0xad, 0x5e, 0xcd, 0x61, 0x9d, 0xd0, 0xde, 0xfd, 0x45, 0x42, 0x7e, 0xcf, 0x7e, 0xaf,
    0xf8, 0x9c, 0xe5, 0xc8, 0xb2, 0x67, 0xfe, 0x68, 0x2d, 0xed, 0xbb, 0x55, 0xdf, 0xba, 0xb2, 0xdf,
    0x57, 0x73, 0xa6, 0xa4, 0x02, 0x80, 0x33, 0xaf, 0x45, 0xb3, 0x72, 0x2a, 0xca, 0xd0, 0xc2, 0x37,
    0xbe, 0x11, 0xd8, 0x8e, 0xd7, 0xaa, 0x1f, 0xca, 0xd6, 0x3d, 0xc4, 0x14, 0x27, 0x17, 0x23, 0xda,
    0xec, 0x29, 0x8a, 0x98, 0x91, 0xf9, 0x8e, 0xdd, 0x5b, 0x69, 0xf2, 0x0a, 0x35, 0xe3, 0x4d, 0x5a,
    0x35, 0x7d, 0xe5, 0x67, 0xd2, 0x4d, 0x0b, 0xf4, 0x01, 0x28, 0xe8, 0x4f, 0xbf, 0x7d, 0x8d, 0xc0,
    0x28, 0x8d, 0x6b, 0x3a, 0x2b, 0x98, 0x5d, 0x93, 0x9e, 0x52, 0x85, 0xe9, 0xee, 0xed, 0xc6, 0x1d,
    0x24, 0x36, 0x0a, 0x91, 0x6c, 0xc7, 0xfa, 0xe5, 0x32, 0x9e, 0xa4, 0x58, 0xc8, 0xa4, 0xe9, 0xc5,
    0x15, 0x66, 0x4d, 0xfa, 0x77, 0xa0, 0x04, 0xab, 0xc5, 0xe5, 0x3b, 0xe5, 0x58, 0x1b, 0xb7, 0x2e,
    0x94, 0x2e, 0xdc, 0x65, 0x2f, 0x96, 0x85, 0x96, 0x0e, 0x3d, 0x91, 0x2a, 0x3b, 0xf7, 0x4e, 0xf8,
    0xef, 0x4a, 0x6e, 0x73, 0xb0, 0x4b, 0xd1, 0xd7, 0xa0, 0xbe, 0x03, 0x22, 0x30, 0x10, 0x06, 0x07,
    0xcb, 0x0c, 0x64, 0xb5, 0x0f, 0xa1, 0x89, 0x2a, 0x7a, 0xe6, 0x39, 0xc1, 0x66, 0x94, 0xe5, 0x88,
    0x2a, 0x6e, 0xea, 0x3f, 0x30, 0xe4, 0x1f, 0x93, 0x38, 0xa6, 0x04, 0x64, 0x23, 0x4e, 0x1b, 0x65,
    0xa0, 0x50, 0x86, 0x27, 0x6c, 0xab, 0xf5, 0xfb, 0x38, 0x31, 0x40, 0x78, 0x1b, 0xc1, 0xf8, 0xe3,
    0x9c, 0x65, 0xd8, 0x1a, 0x6b, 0x14, 0x7e, 0x4e, 0x30, 0x39, 0x58, 0x21, 0xba, 0x85, 0xe2, 0x40,
    0xc2, 0xb8, 0xb3, 0x7a, 0xd8, 0xd6, 0x54, 0xfa, 0xcd, 0x99, 0xb4, 0xb0, 0x3a, 0x62, 0xb7, 0x70,
    0x23, 0x0f, 0xec, 0x8c, 0xf0, 0x4c, 0x84, 0xeb, 0x68, 0xa8, 0x92, 0xd5, 0x65, 0x17, 0x25, 0x77,
    0xaa, 0x9c, 0x54, 0x57, 0x9e, 0xe6, 0xc6, 0x35, 0x85, 0xb1, 0x19, 0x77, 0xb0, 0xe6, 0xe7, 0xeb
};
constexpr unsigned char CORRECT_4096_D[] = {
    0x71, 0xb9, 0x50, 0x61, 0xcc, 0x7b, 0xe3, 0x96, 0x0d, 0x05, 0x8a, 0x6a, 0x00, 0x44, 0xe8, 0x4a,
    0xfa, 0x6f, 0xb4, 0x40, 0xfd, 0x31, 0x3c, 0x0e, 0x71, 0x3e, 0x21, 0x06, 0x2c, 0xf3, 0xe8, 0xf1,
    0x24, 0x06, 0xbd, 0x74, 0x85, 0x1f, 0xfa, 0x10, 0x7d, 0x15, 0x00, 0xfd, 0x99, 0x54, 0x77, 0xf3,
    0xad, 0x72, 0x95, 0x57, 0x61, 0x25, 0xc1, 0xf0, 0x3d, 0xa4, 0x5e, 0x0e, 0x5f, 0x0f, 0x7c, 0xc7,
    0x47, 0x71, 0x51, 0x04, 0x79, 0x7f, 0xd7, 0xf2, 0xc4, 0x23, 0xc7, 0xad, 0xa8, 0x09, 0xf3, 0xe7,
    0xb2, 0xfb, 0x8f, 0x9e, 0x74, 0xca, 0x5e, 0x7c, 0x52, 0x77, 0xdb, 0x3a, 0x15, 0x60, 0xd8, 0xf5,
    0xd4, 0xb9, 0xab, 0x9a, 0x22, 0xb1, 0x3f, 0x83, 0xc7, 0xb2, 0x03, 0x92, 0x54, 0x92, 0xcc, 0x63,
    0xca, 0x9d, 0x11, 0xad, 0xc4, 0xa5, 0xa1, 0x10, 0x46, 0xb3, 0x11, 0xbc, 0xce, 0x74, 0x3a, 0x30,
    0x00, 0x94, 0xdc, 0x7d, 0x07, 0x3d, 0x7a, 0xde, 0x52, 0xe7, 0x0e, 0x8c, 0xbe, 0x21, 0xf1, 0xdd,
    0xe1, 0x21, 0xca, 0x18, 0x23, 0xc1, 0x21, 0x3e, 0x14, 0xb7, 0xfe, 0xed, 0x5e, 0xf6, 0x50, 0x41,
    0x3e, 0x91, 0x25, 0x86, 0x90, 0x1f, 0x18, 0x70, 0xd0, 0x9d, 0xe5, 0xb3, 0x5b, 0xae, 0xcd, 0xb9,
    0x2c, 0x0a, 0x20, 0x5d, 0x08, 0x7a, 0x27, 0x2e, 0xbe, 0x1f, 0x87, 0x54, 0xc0, 0xb4, 0xa7, 0x2b,
    0x12, 0x8d, 0xd6, 0x2e, 0x9a, 0x87, 0x23, 0x77, 0x7c, 0x40, 0x51, 0x80, 0x58, 0x50, 0x12, 0x7f,
    0xbb, 0xfa, 0xdb, 0x37, 0x78, 0xab, 0x55, 0xfd, 0x8b, 0x01, 0xa9, 0xaf, 0xfa, 0x37, 0xc6, 0x89,
    0xef, 0x1b, 0xba, 0x33, 0x09, 0x62, 0xbb, 0x59, 0x64, 0xb4, 0x6b, 0xb4, 0xfb, 0xee, 0x33, 0x21,
    0xbb, 0x27, 0x45, 0xd9, 0xb6, 0x8b, 0x86, 0x80, 0x56, 0x0f, 0xb0, 0x08, 0x22, 0x1a, 0x5d, 0x54,
    0xf6, 0x96, 0xc4, 0x47, 0x77, 0x85, 0xec, 0x3c, 0x86, 0x91, 0xc4, 0x03, 0x0e, 0xc3, 0x9f, 0x99,
    0xc4, 0x7e, 0xef, 0x78, 0x2e, 0x7b, 0x60, 0xb0, 0x9e, 0x49, 0x53, 0xa7, 0x9f, 0x1b, 0x74, 0x32,
    0xf4, 0x31, 0x3f, 0x5b, 0x75, 0xd3, 0xc0, 0x59, 0xa2, 0x47, 0xd7, 0xe8, 0x69, 0x82, 0x3c, 0x6c,
    0xfd, 0xfa, 0x24, 0xb6, 0xa7, 0x3c, 0xaa, 0x29, 0x94, 0xa1, 0x68, 0x67, 0x09, 0xd4, 0x93, 0xc3,
    0x0e, 0x76, 0xa1, 0xbd, 0x9b, 0xfb, 0xca, 0x2a, 0x05, 0x07, 0xfc, 0xdc, 0x14, 0xb0, 0x9c, 0x44,
    0x30, 0xde, 0x02, 0x26, 0x21, 0x5f, 0x86, 0xb8, 0x6a, 0x81, 0xf2, 0xf0, 0xe1, 0xc1, 0x3d, 0x16,
    0xfe, 0xca, 0x80, 0xc7, 0xe3, 0xdb, 0x8b, 0xd2, 0xbd, 0x3d, 0xaa, 0x51, 0xac, 0xcd, 0x95, 0x0d,
    0x1c, 0x5b, 0x1e, 0x63, 0xb1, 0xf7, 0x85, 0xe2, 0xba, 0x65, 0xef, 0x68, 0xab, 0x55, 0xea, 0xc6,
    0xd8, 0x93, 0x82, 0x50, 0x33, 0x58, 0x90, 0x00, 0x47, 0x19, 0x50, 0x79, 0x9f, 0x8d, 0xe4, 0xb0,
    0x64, 0xca, 0xb1, 0xdd, 0xae, 0x47, 0x44, 0x3f, 0x81, 0x31, 0xd6, 0x90, 0x36, 0x93, 0x07, 0x21,
    0xb8, 0x44, 0x38, 0xbb, 0xd6, 0xdc, 0x00, 0x58, 0x87, 0xcc, 0xe9, 0x75, 0x5a, 0x82, 0x84, 0x38,
    0x5d, 0x63, 0x6d, 0x6b, 0x58, 0x4d, 0x9d, 0x97, 0xfc, 0xa7, 0xea, 0x18, 0x61, 0xdc, 0xed, 0xd7,
    0x16, 0xce, 0x81, 0xf5, 0x5b, 0x36, 0xda, 0xe0, 0x68, 0xba, 0xf6, 0x1f, 0x1b, 0xa5, 0xe3, 0x04,
    0xb5, 0xbe, 0xba, 0x49, 0x67, 0x76, 0x65, 0x90, 0xb2, 0x6d, 0x8f, 0x79, 0xad, 0xe9, 0x3c, 0x54,
    0x84, 0xfb, 0x73, 0x9b, 0x68, 0x3b, 0xbe, 0x4c, 0x1a, 0xfc, 0xe5, 0xa3, 0x9d, 0x0c, 0x94, 0xbb,
    0x47, 0xe2, 0xa8, 0x10, 0x1e, 0xf1, 0xb7, 0xdb, 0x3e, 0x50, 0x1f, 0x1d, 0x09, 0x39, 0x48, 0xa1
};

constexpr unsigned char CORRECT_8192_N[] = {
    0xbe, 0xb0, 0x16, 0xc4, 0x00, 0xfe, 0x62, 0x75, 0x53, 0x5e, 0x2f, 0x0d, 0x36, 0xbe, 0x94, 0x7b,
    0x8e, 0x58, 0xb4, 0x98, 0xaa, 0xa7, 0xdf, 0x81, 0x74, 0xc7, 0xda, 0x8c, 0x35, 0x37, 0xd0, 0x21,
    0xf0, 0x36, 0x27, 0xdb, 0x25, 0xbb, 0xd2, 0x05, 0xb9, 0xf1, 0xce, 0x15, 0xec, 0x65, 0x2f, 0x9c,
    0x89, 0x01, 0xf6, 0x6a, 0x92, 0x42, 0x39, 0xa4, 0xad, 0xc5, 0x3c, 0x60, 0x0e, 0x48, 0x3b, 0x3b,
    0x1a, 0xe6, 0xce, 0xdd, 0x61, 0xe2, 0xda, 0x08, 0x1d, 0x3b, 0x18, 0xfa, 0x12, 0x4f, 0x53, 0x70,
    0x56, 0xdc, 0xc6, 0xc6, 0xbe, 0x19, 0xc7, 0x8f, 0x4d, 0x25, 0x5c, 0xf5, 0x58, 0x44, 0xd0, 0x64,
    0xfd, 0xd6, 0xb3, 0x55, 0xca, 0xd9, 0x06, 0x4e, 0x69, 0xdf, 0x4e, 0x76, 0x64, 0x41, 0xbb, 0xd7,
    0x5a, 0x26, 0xe1, 0x5e, 0x62, 0x54, 0x30, 0xf6, 0x79, 0x15, 0x5b, 0x9a, 0x88, 0x73, 0xb1, 0xbe,
    0x0a, 0xfe, 0x54, 0x04, 0x13, 0x99, 0x3b, 0xfa, 0xfc, 0x8f, 0x9a, 0x93, 0xd4, 0x14, 0xde, 0x09,
    0x98, 0x78, 0x98, 0x10, 0x39, 0xdf, 0x9f, 0x58, 0xae, 0x10, 0xb1, 0xab, 0xe6, 0xae, 0x39, 0x85,
    0xe1, 0x83, 0x74, 0xf8, 0x05, 0x2a, 0xf8, 0xb3, 0xca, 0x4a, 0xee, 0x17, 0xce, 0xcf, 0x6b, 0x25,
    0x8c, 0xba, 0x89, 0x92, 0x3c, 0xc9, 0x0a, 0xe6, 0x93, 0x84, 0x3e, 0x81, 0xc6, 0x8c, 0x85, 0x6c,
    0x1a, 0xa6, 0xe9, 0x8e, 0x58, 0xe6, 0x94, 0x3c, 0xeb, 0xaf, 0x98, 0x55, 0xab, 0x6c, 0x8c, 0x66,
    0xe8, 0x45, 0x99, 0x2e, 0xd3, 0xad, 0xd8, 0xac, 0x9e, 0x78, 0x15, 0x78, 0x86, 0x5e, 0x97, 0x83,
    0x53, 0x34, 0xab, 0xec, 0xa5, 0x54, 0xf7, 0x82, 0xf1, 0x17, 0x01, 0x91, 0x96, 0x24, 0x6d, 0x7c,
    0x22, 0x4d, 0x67, 0xca, 0xa5, 0x67, 0x34, 0x59, 0xe8, 0x79, 0x71, 0x8d, 0xe5, 0xba, 0x31, 0x65,
    0x82, 0xfa, 0xa8, 0x8c, 0x1f, 0xe6, 0x1b, 0x7f, 0x03, 0xec, 0x60, 0x6e, 0xcd, 0xac, 0x75, 0xfd,
    0xaa, 0x9b, 0xf9, 0x6c, 0xe0, 0x83, 0x5a, 0x37, 0x32, 0xc7, 0x5c, 0x5c, 0x85, 0xb2, 0xd0, 0xe7,
    0x6e, 0x90, 0xa7, 0x24, 0x5a, 0x34, 0x6a, 0x09, 0xfd, 0x51, 0x12, 0xf3, 0xd1, 0xe5, 0x5d, 0xee,
    0x9f, 0x6d, 0xc8, 0xc8, 0x14, 0x43, 0x55, 0x26, 0x26, 0xb3, 0xe3, 0x47, 0x18, 0xdf, 0xcf, 0x34,
    0xc7, 0xda, 0xa6, 0x62, 0x59, 0xab, 0xa1, 0xe7, 0x87, 0x35, 0x34, 0x7b, 0x75, 0x68, 0x0a, 0x84,
    0xc4, 0x3b, 0xb3, 0x7c, 0xe8, 0xda, 0x42, 0x77, 0x04, 0xf4, 0x5e, 0x75, 0xaf, 0xa1, 0x02, 0x58,
    0xc7, 0x84, 0x51, 0x57, 0xc4, 0xc1, 0xad, 0xbf, 0x49, 0x71, 0xb2, 0x55, 0x99, 0xae, 0xec, 0xf1,
    0x20, 0xe0, 0x92, 0x6e, 0x95, 0xa3, 0x74, 0x65, 0xbe, 0x1b, 0xeb, 0xd5, 0xf3, 0x2c, 0xe8, 0xcb,
    0xc2, 0xfc, 0x20, 0x60, 0x39, 0xbf, 0xb0, 0xbe, 0xac, 0xc0, 0x15, 0x59, 0x56, 0x64, 0x13, 0xa8,
    0xb4, 0x0b, 0xfe, 0xf3, 0x2e, 0xc6, 0xbe, 0x8c, 0x58, 0x7a, 0x98, 0x0f, 0x46, 0x60, 0x59, 0xcd,
    0xfb, 0xd0, 0x5f, 0x37, 0x16, 0x9d, 0xb4, 0xfe, 0x5f, 0x30, 0x2a, 0x96, 0x7c, 0x07, 0x22, 0x46,
    0x9b, 0xe7, 0x22, 0x10, 0xd2, 0x1e, 0xca, 0xc4, 0xab, 0xd4, 0x23, 0x9a, 0x65, 0x5d, 0xa9, 0xc2,
    0x50, 0x2d, 0xf3, 0x44, 0x5a, 0x8b, 0x4e, 0x11, 0x18, 0x41, 0xcb, 0xca, 0xa3, 0x5a, 0x1e, 0xf9,
    0xec, 0xbe, 0xc7, 0x8b, 0xd4, 0x90, 0xa4, 0x79, 0x03, 0x9c, 0xf2, 0x97, 0xfc, 0x33, 0xc1, 0x30,
    0x58, 0x7b, 0x4e, 0xce, 0xb5, 0x0d, 0x0e, 0x11, 0x1a, 0x29, 0x39, 0x1c, 0xe2, 0x88, 0x67, 0xa1,
    0x2f, 0xb8, 0x42, 0x30, 0x72, 0x03, 0x90, 0x01, 0xe1, 0x20, 0x0b, 0xad, 0x11, 0x63, 0xaa, 0xa3,
    0x55, 0x52, 0xf8, 0xb8, 0xe6, 0xe3, 0x2e, 0xc5, 0xf3, 0x1a, 0xfd, 0x72, 0x2b, 0xb7, 0xef, 0x4c,
    0x4b, 0xf8, 0x36, 0x58, 0x34, 0x15, 0xe4, 0x3b, 0xdd, 0xd0, 0x77, 0xf8, 0x46, 0xa1, 0x8f, 0x98,
    0xdb, 0x44, 0xc6, 0xc2, 0x30, 0xe5, 0x25, 0x3c, 0x39, 0x5c, 0xe4, 0x36, 0xc6, 0x74, 0xed, 0xd1,
    0x20, 0x81, 0xea, 0xd9, 0x72, 0x4a, 0xad, 0xfa, 0x19, 0x22, 0xc0, 0x69, 0x33, 0xd7, 0x46, 0xb5,
    0x32, 0xfd, 0xa6, 0x30, 0xf9, 0x0f, 0xd9, 0x19, 0xac, 0x71, 0xb2, 0x43, 0x8d, 0x5a, 0xda, 0x55,
    0xdd, 0x70, 0xdc, 0x1c, 0xf2, 0xdb, 0x93, 0x93, 0xc9, 0xaa, 0xee, 0x38, 0x7a, 0x22, 0xe6, 0x64,
    0xa3, 0xbf, 0x65, 0x28, 0xa3, 0x34, 0x36, 0x91, 0xff, 0xe8, 0x73, 0x90, 0x35, 0x64, 0xad, 0x0a,
    0xcf, 0xa3, 0xac, 0x04, 0x96, 0x83, 0xf4, 0x55, 0x07, 0x8e, 0xf7, 0x90, 0x1d, 0xa3, 0x22, 0xf5,
    0x4d, 0x7a, 0xb0, 0xf6, 0x7e, 0xfc, 0xe6, 0x0b, 0x59, 0xab, 0xd5, 0x38, 0xa3, 0xa7, 0x45, 0x5d,
    0x88, 0x9c, 0x7f, 0xc0, 0x7d, 0x99, 0xce, 0x6d, 0x45, 0xce, 0x70, 0xea, 0x4f, 0x85, 0x86, 0x90,
    0xdb, 0xf6, 0xaf, 0xbe, 0x79, 0x7a, 0xcc, 0x94, 0x47, 0x2c, 0x28, 0x7a, 0xcc, 0xdc, 0x8c, 0x52,
    0xc1, 0x6b, 0x87, 0xf6, 0x98, 0x79, 0x03, 0x39, 0xcd, 0x51, 0xc9, 0x41, 0x0e, 0x9b, 0x84, 0xaa,
    0x8e, 0x16, 0x2d, 0xaf, 0xb6, 0x50, 0xbd, 0xc1, 0xbb, 0xf4, 0xea, 0x02, 0x2a, 0xe8, 0x10, 0x41,
    0xe8, 0x39, 0xc5, 0xce, 0x6d, 0x03, 0x9e, 0x2f, 0xc7, 0x35, 0x58, 0x76, 0x06, 0xfa, 0xf5, 0x67,
    0x99, 0x8f, 0x40, 0xfe, 0xd7, 0x2d, 0x0f, 0xe0, 0xae, 0x5f, 0x0e, 0x47, 0xe5, 0x9f, 0xb3, 0x19,
    0xa0, 0x7d, 0xe9, 0xd4, 0xa0, 0x08, 0xed, 0xcb, 0x84, 0xc3, 0x2a, 0xc5, 0xb9, 0x66, 0xf7, 0x55,
    0x4f, 0x6b, 0x26, 0xc7, 0xca, 0x4f, 0xf4, 0xc0, 0x80, 0xe9, 0xcb, 0x5a, 0x0a, 0x02, 0xe1, 0x15,
    0xd7, 0x5d, 0xb8, 0x47, 0x71, 0xec, 0xa3, 0x20, 0xfb, 0x73, 0xfb, 0x65, 0x4b, 0x7d, 0x25, 0xe8,
    0x9d, 0x38, 0x81, 0x56, 0x31, 0x39, 0x95, 0xfe, 0x30, 0x13, 0xf6, 0x83, 0x28, 0x97, 0xe5, 0xa2,
    0xf4, 0xf7, 0x0e, 0x7d, 0x6b, 0xc2, 0xfa, 0x81, 0xbb, 0xe7, 0x4a, 0x3b, 0x4c, 0x53, 0x04, 0xe1,
    0x51, 0x50, 0xea, 0xf2, 0x4c, 0xc7, 0x9d, 0xe7, 0x5e, 0x5b, 0x06, 0x19, 0x88, 0x9a, 0xc2, 0x89,
    0x9c, 0xf2, 0xab, 0xeb, 0xf6, 0xf3, 0xeb, 0xb5, 0xd0, 0x20, 0x3d, 0xce, 0x3d, 0xea, 0xea, 0x04,
    0xf1, 0x83, 0x87, 0xc8, 0x0c, 0x90, 0x61, 0x81, 0x33, 0x14, 0x40, 0x1d, 0x9e, 0x3c, 0xcf, 0xba,
    0x54, 0x41, 0x5f, 0xb2, 0x77, 0x7c, 0xad, 0x52, 0xe0, 0x5d, 0x30, 0xcc, 0xca, 0x25, 0x07, 0x23,
    0xcf, 0xa5, 0xca, 0x12, 0x1b, 0x9c, 0x8b, 0x0c, 0xd3, 0x72, 0xda, 0x1c, 0x5d, 0xf1, 0x5a, 0x02,
    0x32, 0x40, 0x58, 0x8f, 0x13, 0x37, 0xf7, 0x9d, 0x16, 0x46, 0xd2, 0x62, 0xc9, 0x93, 0x7e, 0x35,
    0x29, 0x40, 0x98, 0x78, 0xe9, 0x3c, 0xb5, 0x99, 0x39, 0xcf, 0xa3, 0xcc, 0xcc, 0x4f, 0xf5, 0xa9,
    0x82, 0x35, 0xf8, 0x61, 0xee, 0x41, 0xec, 0xfa, 0x9b, 0x70, 0x53, 0x1d, 0xcf, 0x72, 0xc1, 0xef,
    0xdc, 0xc8, 0xd8, 0x73, 0x09, 0x04, 0x91, 0x0e, 0xc1, 0xfc, 0xc4, 0x78, 0xf8, 0xd7, 0x09, 0x68,
    0xc6, 0x75, 0x58, 0xe3, 0x79, 0x8d, 0xe6, 0xfd, 0xdd, 0x03, 0x1b, 0x00, 0x85, 0x89, 0xbf, 0xe0,
    0xf9, 0x09, 0x8d, 0x5b, 0xe3, 0xab, 0xe7, 0x17, 0xab, 0x4a, 0x35, 0xdf, 0xe6, 0xf8, 0x7d, 0xc5,
    0x6d, 0xfd, 0x1f, 0x5e, 0x85, 0xbe, 0xa8, 0x56, 0x18, 0xa2, 0x10, 0xcc, 0x4d, 0x4f, 0xac, 0x69
};
constexpr unsigned char CORRECT_8192_D[] = {
    0x9e, 0x4c, 0x46, 0x09, 0xde, 0x9d, 0x4f, 0x15, 0x00, 0xe9, 0x4d, 0xfc, 0x15, 0x37, 0x2e, 0xc2,
    0x47, 0x50, 0x22, 0x54, 0x1e, 0x4f, 0x8f, 0xfe, 0xc2, 0xf8, 0x69, 0xd8, 0x3d, 0x11, 0xa1, 0x49,
    0x9b, 0x45, 0x09, 0xdf, 0x26, 0x3a, 0xfe, 0x45, 0xdc, 0xaf, 0xfc, 0x9a, 0x3c, 0x8d, 0x5f, 0x71,
    0xfe, 0x56, 0xcf, 0xbe, 0x76, 0xbe, 0x5d, 0x65, 0xf5, 0x0f, 0xa8, 0x68, 0x41, 0x52, 0xfb, 0x40,
    0xbc, 0xbb, 0x60, 0x7d, 0x6d, 0x96, 0x49, 0xd3, 0xb4, 0x98, 0x6b, 0xca, 0xa5, 0x4a, 0x8f, 0x04,
    0xd2, 0x47, 0x23, 0x08, 0xb7, 0xa5, 0x65, 0x01, 0xf4, 0x54, 0x11, 0x10, 0x67, 0x7f, 0x70, 0xd4,
    0x75, 0xd9, 0x37, 0x35, 0x00, 0x59, 0x1b, 0xa0, 0x1a, 0xc9, 0xd3, 0x33, 0xfb, 0x54, 0x8a, 0x60,
    0x63, 0x29, 0xa5, 0xab, 0x99, 0xcb, 0x34, 0x7e, 0x57, 0xd4, 0x40, 0x20, 0x50, 0x28, 0x63, 0x24,
    0x55, 0xb1, 0xfe, 0x03, 0x08, 0x56, 0x0b, 0xf1, 0xf6, 0x9a, 0x2c, 0x03, 0x8e, 0x6a, 0xe8, 0x4c,
    0x64, 0xf3, 0xaf, 0xa0, 0xc0, 0xba, 0x80, 0x68, 0xb8, 0xcf, 0x88, 0xff, 0x20, 0x57, 0xff, 0xce,
    0xc1, 0x80, 0x44, 0xa8, 0xe4, 0x79, 0x60, 0xce, 0xb8, 0x1f, 0x6d, 0xf9, 0xfb, 0xa8, 0x3a, 0xd5,
    0x88, 0x37, 0x0e, 0x9f, 0x84, 0xb0, 0x8c, 0xc9, 0x0f, 0x2b, 0x18, 0x4c, 0xd9, 0x8b, 0xab, 0xf3,
    0x2b, 0x48, 0xe6, 0xd8, 0x51, 0xba, 0xd0, 0xd2, 0xa6, 0x01, 0x36, 0x5f, 0xe0, 0x18, 0x13, 0x92,
    0x16, 0x3e, 0x38, 0xc5, 0x23, 0xda, 0xcc, 0xe5, 0xb8, 0x04, 0x0e, 0x26, 0xe8, 0xbd, 0x3b, 0xe0,
    0x3c, 0x41, 0x9c, 0x7b, 0xae, 0x60, 0x93, 0xbc, 0x72, 0xf1, 0xdb, 0x4e, 0x85, 0xaa, 0xa5, 0xed,
    0x07, 0xf8, 0xe4, 0x31, 0xd9, 0x0f, 0x8c, 0xe9, 0x1a, 0x51, 0x3e, 0xd0, 0x42, 0x26, 0x48, 0x7d,
    0x71, 0xb7, 0x2e, 0x16, 0x6d, 0x20, 0xb4, 0x30, 0xc4, 0x0c, 0x05, 0x9d, 0xd6, 0x45, 0xd6, 0x09,
    0x88, 0x09, 0x45, 0x8d, 0x79, 0xef, 0xf1, 0x03, 0xa3, 0xb6, 0xd6, 0x58, 0xc4, 0x70, 0xc6, 0x75,
    0x69, 0x56, 0xd2, 0x3a, 0x1e, 0x5c, 0x26, 0xaf, 0x36, 0x48, 0x88, 0x88, 0x39, 0xf5, 0xc3, 0xfd,
    0xa5, 0x02, 0x19, 0x4c, 0xe7, 0x6d, 0x62, 0x11, 0x72, 0xcd, 0xa0, 0xde, 0x53, 0xaa, 0xf0, 0x33,
    0x6b, 0xb9, 0x7a, 0xa8, 0x68, 0xb2, 0x4f, 0x8c, 0x89, 0xb4, 0xc4, 0x65, 0xbc, 0xf8, 0x6a, 0xca,
    0xfe, 0xb0, 0x64, 0xf7, 0x4b, 0xc2, 0x6c, 0xac, 0xab, 0x43, 0x45, 0xeb, 0x42, 0xaa, 0x51, 0xed,
    0x6b, 0x6b, 0xcf, 0xaf, 0x21, 0xda, 0x7a, 0xa7, 0x32, 0x8c, 0x1d, 0x34, 0x6c, 0x89, 0x47, 0x8f,
    0x80, 0xf0, 0x8c, 0xff, 0x1a, 0x5f, 0xff, 0xef, 0xba, 0x5b, 0x29, 0x73, 0x8a, 0x14, 0xfd, 0x08,
    0xb2, 0x4c, 0x65, 0x80, 0x1c, 0x50, 0xa2, 0xa4, 0x17, 0x7a, 0xb9, 0xfe, 0x58, 0xf6, 0x69, 0x4f,
    0x82, 0x6f, 0xf6, 0xec, 0xe0, 0x27, 0x02, 0xe6, 0x35, 0x49, 0x48, 0x54, 0x5d, 0xe2, 0xfc, 0x8a,
    0x40, 0x02, 0x22, 0x18, 0xf4, 0x40, 0x65, 0x91, 0x49, 0x6a, 0x0d, 0xe0, 0xb1, 0x03, 0xa7, 0x13,
    0xa0, 0xb6, 0xc6, 0x93, 0xda, 0x2a, 0xcf, 0xbf, 0x66, 0xb9, 0x8b, 0xf8, 0xcf, 0x2f, 0x6b, 0x0e,
    0xb1, 0x4b, 0x04, 0x08, 0xf9, 0x75, 0x6d, 0x90, 0x49, 0x67, 0xcd, 0x8a, 0xe2, 0x02, 0x9d, 0x76,
    0x72, 0x6f, 0x89, 0xed, 0xed, 0xbf, 0x49, 0x9a, 0x60, 0x42, 0x79, 0x2d, 0x6c, 0xa3, 0x76, 0x3b,
    0xf1, 0x28, 0x24, 0x2a, 0xfb, 0x27, 0xe4, 0x46, 0x94, 0x46, 0x26, 0x70, 0x71, 0x2a, 0x35, 0x85,
    0x1c, 0xbd, 0x44, 0xcd, 0x3c, 0xc8, 0xf2, 0x52, 0x6d, 0x16, 0x12, 0x3b, 0x51, 0x15, 0x41, 0x00,
    0x39, 0xa2, 0x53, 0x1e, 0x41, 0x98, 0x34, 0x69, 0xc8, 0x42, 0x3d, 0xdd, 0x5b, 0x92, 0xc4, 0xdf,
    0xa7, 0x22, 0xc5, 0xc1, 0x6f, 0x07, 0x60, 0xcd, 0x9b, 0x80, 0xcf, 0x4e, 0x88, 0xad, 0xe6, 0xc3,
    0x0a, 0x3e, 0x02, 0xba, 0x52, 0x29, 0x30, 0xe2, 0xdc, 0xe1, 0x67, 0x1d, 0x3e, 0x69, 0x0d, 0x8b,
    0x18, 0x93, 0xad, 0xd4, 0x21, 0xc5, 0x4d, 0x38, 0xc8, 0x1f, 0xec, 0xf1, 0xdb, 0xa3, 0xa2, 0xf5,
    0x75, 0x42, 0xf1, 0x87, 0xe5, 0xa1, 0xdf, 0x44, 0x6c, 0xa4, 0xa3, 0x05, 0x37, 0x99, 0x74, 0x2f,
    0x81, 0x93, 0xcb, 0xeb, 0x21, 0xae, 0xa7, 0x05, 0x44, 0xb3, 0x4a, 0x15, 0xed, 0x7c, 0x25, 0xe0,
    0xb4, 0x46, 0xf7, 0x56, 0xfe, 0x80, 0xb6, 0x9f, 0x1c, 0xb8, 0xf8, 0x36, 0xc9, 0x1a, 0x1f, 0x5d,
    0x38, 0xe3, 0x24, 0x62, 0x31, 0x95, 0xf8, 0x67, 0x5a, 0xdb, 0xe4, 0x24, 0x30, 0x8f, 0x8b, 0xb6,
    0xa5, 0xb2, 0xa5, 0x4d, 0x1d, 0x10, 0x1a, 0xa8, 0x68, 0x01, 0xd0, 0x9e, 0xc3, 0x2f, 0xaf, 0x2a,
    0x05, 0xcc, 0xac, 0xb1, 0x5b, 0xbe, 0x72, 0x72, 0x0e, 0xf1, 0xb3, 0x51, 0x0e, 0x7a, 0x18, 0x93,
    0x3f, 0x57, 0xc2, 0x6b, 0x13, 0xae, 0x2b, 0xcf, 0xa5, 0x6b, 0x30, 0x49, 0xe5, 0x8f, 0xbb, 0xf2,
    0x6c, 0xe3, 0x87, 0xdf, 0x21, 0x34, 0x3e, 0x25, 0xee, 0x7d, 0x6e, 0x56, 0x01, 0xbe, 0x03, 0xd0,
    0x3c, 0xce, 0x09, 0x6b, 0x6e, 0x6a, 0x1c, 0x04, 0xb7, 0x4a, 0xc6, 0xc0, 0x40, 0xad, 0xdc, 0x3d,
    0x1d, 0xb2, 0x44, 0x84, 0x3e, 0x25, 0x2c, 0x63, 0x87, 0x26, 0x0d, 0x80, 0x33, 0xe8, 0xc5, 0xf6,
    0x7d, 0x54, 0x0a, 0xad, 0xe9, 0x92, 0x49, 0xdf, 0xe2, 0x43, 0x03, 0x87, 0x45, 0xd3, 0x76, 0xac,
    0x3c, 0x61, 0x5a, 0x66, 0xc5, 0x22, 0x27, 0xff, 0x22, 0xe3, 0x2d, 0x46, 0x9e, 0xaf, 0x21, 0x3f,
    0xc0, 0x91, 0x97, 0x1a, 0xcd, 0x8d, 0x0d, 0xb2, 0x0c, 0xfc, 0x91, 0xc4, 0x9a, 0x73, 0xb4, 0x01,
    0x18, 0xd6, 0xec, 0xa5, 0xad, 0x13, 0xb5, 0x7e, 0xae, 0xab, 0xaa, 0xf7, 0xce, 0xdf, 0x52, 0x2e,
    0xf3, 0x5f, 0x38, 0xef, 0x90, 0x68, 0xd6, 0xe9, 0x5a, 0x89, 0x70, 0xe8, 0x0f, 0x42, 0xe6, 0x89,
    0xb9, 0x79, 0xf9, 0xb8, 0x46, 0xbc, 0x0d, 0x8e, 0x9d, 0x22, 0x77, 0x07, 0x57, 0xcb, 0x5e, 0x46,
    0x9a, 0x9b, 0x4f, 0x44, 0x65, 0x1f, 0x7e, 0x8f, 0xfd, 0xce, 0x7a, 0x32, 0xb4, 0x50, 0x6b, 0x27,
    0xd3, 0xc7, 0x3c, 0xd9, 0x9d, 0xce, 0x4b, 0x25, 0xac, 0x43, 0x9d, 0x2c, 0x97, 0x20, 0xa8, 0x6f,
    0x11, 0x5a, 0xc4, 0x31, 0x4f, 0x2b, 0x65, 0x0b, 0x4a, 0xcf, 0x06, 0x2d, 0xe8, 0x40, 0x87, 0x87,
    0xf8, 0xd7, 0xff, 0x29, 0xa5, 0xf7, 0x61, 0xc0, 0x8a, 0x2f, 0x69, 0x4a, 0x55, 0x05, 0xb1, 0xaf,
    0x8a, 0x9a, 0xbf, 0xae, 0xe7, 0x40, 0x08, 0xa9, 0x89, 0xe1, 0x9c, 0xc0, 0x35, 0x17, 0xa6, 0x61,
    0x23, 0x70, 0xe0, 0x90, 0x51, 0x32, 0x0d, 0x5e, 0x8b, 0x2b, 0xb5, 0xab, 0xec, 0xa9, 0xbf, 0x22,
    0x98, 0x4b, 0xdb, 0x14, 0x81, 0x97, 0x38, 0x95, 0xf0, 0x1c, 0x2e, 0xe5, 0x74, 0x74, 0x21, 0x5a,
    0x69, 0xb6, 0xfd, 0x96, 0x53, 0x62, 0x91, 0x30, 0x2f, 0x95, 0xf8, 0x91, 0xac, 0xff, 0x11, 0x9f,
    0x02, 0x15, 0xf7, 0x0b, 0xf3, 0xf0, 0xf2, 0x2d, 0xa1, 0x83, 0xa5, 0x15, 0x34, 0xee, 0xfa, 0x61,
    0x32, 0xfd, 0xb7, 0x29, 0x3e, 0xbe, 0x95, 0x2c, 0xe2, 0x95, 0x16, 0x27, 0x73, 0xd9, 0x74, 0xce,
    0x1b, 0x07, 0xf8, 0x5f, 0x25, 0x77, 0x7a, 0xf2, 0xbe, 0x22, 0x60, 0x7f, 0x58, 0x2b, 0x6c, 0x95,
    0x22, 0x92, 0x33, 0xba, 0xa3, 0xd8, 0x87, 0x58, 0x29, 0xa0, 0x69, 0x01, 0xd9, 0x51, 0x87, 0x01
};

const char *g_asyKeyGeneratorBySpecClass = "HcfAsyKeyGeneratorBySpec";

const char *g_rsaAlgName = "RSA";
}

static void RemoveLastChar(const unsigned char *str, unsigned char *dest, uint32_t destLen)
{
    for (size_t i = 0; i < destLen; i++) {
        dest[i] = str[i];
    }
    return;
}

static void EndianSwap(unsigned char *pData, int startIndex, int length)
{
    int cnt = length / 2;
    int start = startIndex;
    int end  = startIndex + length - 1;
    unsigned char tmp;
    for (int i = 0; i < cnt; i++) {
        tmp = pData[start + i];
        pData[start + i] = pData[end - i];
        pData[end - i] = tmp;
    }
}

// 512 defined the length of byte array
static void GenerateRsa512CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_512_N, dataN, RSA_512_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_512_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_512_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa512CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa512CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_512_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_512_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_512_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa512CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa512CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_512_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_512_D, dataD, RSA_512_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_512_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_512_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_512_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_512_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 768 defined the length of byte array
static void GenerateRsa768CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_768_N, dataN, RSA_768_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_768_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_768_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa768CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa768CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_768_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_768_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_768_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa768CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa768CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_768_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_768_D, dataD, RSA_768_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_768_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_768_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_768_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_768_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 1024 defined the length of byte array
static void GenerateRsa1024CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_1024_N, dataN, RSA_1024_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_1024_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_1024_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa1024CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa1024CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_1024_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_1024_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_1024_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa1024CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa1024CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_1024_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_1024_D, dataD, RSA_1024_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_1024_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_1024_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_1024_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_1024_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 2048 defined the length of byte array
static void GenerateRsa2048CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_2048_N, dataN, RSA_2048_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_2048_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_2048_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa2048CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_2048_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_2048_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa2048CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_2048_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_2048_D, dataD, RSA_2048_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_2048_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_2048_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_2048_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_2048_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 3072 defined the length of byte array
static void GenerateRsa3072CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_3072_N, dataN, RSA_3072_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_3072_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_3072_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa3072CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa3072CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_3072_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_3072_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_3072_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa3072CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa3072CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_3072_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_3072_D, dataD, RSA_3072_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_3072_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_3072_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_3072_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_3072_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 4096 defined the length of byte array
static void GenerateRsa4096CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_4096_N, dataN, RSA_4096_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_4096_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_4096_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa4096CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa4096CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_4096_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_4096_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_4096_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa4096CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa4096CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_4096_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_4096_D, dataD, RSA_4096_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_4096_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_4096_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_4096_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_4096_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

// 8192 defined the length of byte array
static void GenerateRsa8192CorrectCommonKeySpec(unsigned char *dataN, HcfRsaCommParamsSpec *returnSpec)
{
    RemoveLastChar(CORRECT_8192_N, dataN, RSA_8192_N_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataN, 0, RSA_8192_N_BYTE_SIZE);
    }
    returnSpec->n.data = dataN;
    returnSpec->n.len = RSA_8192_N_BYTE_SIZE;
    returnSpec->base.algName = const_cast<char *>(g_rsaAlgName);
    returnSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    return;
}

static void GenerateRsa8192CorrectPubKeySpec(unsigned char *dataN, unsigned char *dataE,
    HcfRsaPubKeyParamsSpec *returnPubSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_8192_E_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_8192_E_BYTE_SIZE);
    }
    returnPubSpec->pk.data = dataE;
    returnPubSpec->pk.len = RSA_8192_E_BYTE_SIZE;
    returnPubSpec->base = rsaCommSpec;
    returnPubSpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
}

static void GenerateRsa8192CorrectKeyPairSpec(unsigned char *dataN, unsigned char *dataE, unsigned char *dataD,
    HcfRsaKeyPairParamsSpec *returnPairSpec)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);
    RemoveLastChar(CORRECT_E, dataE, RSA_8192_E_BYTE_SIZE);
    RemoveLastChar(CORRECT_8192_D, dataD, RSA_8192_D_BYTE_SIZE);
    if (!IsBigEndian()) {
        // the device is not big endian
        EndianSwap(dataE, 0, RSA_8192_E_BYTE_SIZE);
        EndianSwap(dataD, 0, RSA_8192_D_BYTE_SIZE);
    }
    returnPairSpec->pk.data = dataE;
    returnPairSpec->pk.len = RSA_8192_E_BYTE_SIZE;
    returnPairSpec->sk.data = dataD;
    returnPairSpec->sk.len = RSA_8192_D_BYTE_SIZE;
    returnPairSpec->base = rsaCommSpec;
    returnPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
}

static bool CheckGeneratorBySpecKeyFunc(HcfAsyKeyGeneratorBySpec *generator)
{
    if (generator->generateKeyPair == nullptr || generator->generatePriKey == nullptr ||
        generator->generatePubKey == nullptr) {
        return false;
    }
    return true;
}

// basic generator create test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest001, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest024, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest025, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest026, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest027, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest028, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest029, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest030, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest031, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest032, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest033, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest034, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest035, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest036, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest037, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest038, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest039, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest040, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest041, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest042, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest043, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest044, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest045, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest046, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest047, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest048, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest049, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest050, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_2048_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest051, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest052, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest053, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest054, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest055, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest056, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest057, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest058, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest059, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest060, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest061, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest062, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest063, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest064, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest065, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest066, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest067, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest068, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest069, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest070, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest071, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest072, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest073, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest074, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 2048 generate keyPair get all big int
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest100, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_2048_D_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_2048_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 2048 generate pub key get
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest110, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_2048_E_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_2048_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_2048_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 2048 generate common key spec (not support)
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest130, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_2048_N_BYTE_SIZE] = {0};
    GenerateRsa2048CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}


//  =============================   RSA 512  testcase begin =============================
// basic generator create test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest131, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    GenerateRsa512CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest132, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest133, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest134, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest135, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest136, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest137, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest138, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest139, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest140, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest141, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest142, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest143, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest144, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest145, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest146, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest147, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest148, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest149, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest150, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest151, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest152, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest153, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest154, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest155, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest156, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest157, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest158, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest159, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest160, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest161, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest162, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest163, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest164, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest165, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest166, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest167, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest168, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest169, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest170, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest171, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest172, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest173, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_512_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest174, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest175, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest176, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest177, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest178, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest179, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest180, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest181, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest182, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest183, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest184, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest185, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest186, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest187, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest188, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest189, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA512", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest190, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest191, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest192, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest193, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest194, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest195, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest196, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest197, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 512 generate keyPair get all big int
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest198, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_512_D_BYTE_SIZE] = {0};
    GenerateRsa512CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_512_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 512 generate pub key get
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest199, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_512_E_BYTE_SIZE] = {0};
    GenerateRsa512CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_512_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_512_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 512 generate common key spec (not support)
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest200, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_512_N_BYTE_SIZE] = {0};
    GenerateRsa512CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}
//  =============================   RSA 512  testcase end =============================


//  =============================   RSA 768  testcase begin =============================
// basic generator create test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest201, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    GenerateRsa768CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest202, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest203, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest204, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest205, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest206, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest207, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest208, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest209, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest210, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest211, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest212, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest213, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest214, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest215, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest216, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest217, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest218, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest219, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest220, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest221, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest222, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest223, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest224, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest225, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest226, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest227, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest228, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest229, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest230, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest231, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest232, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest233, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest234, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest235, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest236, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest237, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest238, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest239, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest240, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest241, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest242, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest243, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_768_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest244, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest245, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest246, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest247, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest248, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest249, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest250, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest251, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest252, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest253, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest254, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest255, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest256, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest257, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest258, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest259, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest260, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest261, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest262, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest263, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest264, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest265, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest266, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest267, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 768 generate keyPair get all big int
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest268, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_768_D_BYTE_SIZE] = {0};
    GenerateRsa768CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_768_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 768 generate pub key get
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest269, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_768_E_BYTE_SIZE] = {0};
    GenerateRsa768CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_768_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_768_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 768 generate common key spec (not support)
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest270, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_768_N_BYTE_SIZE] = {0};
    GenerateRsa768CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}

//  =============================   RSA 768  testcase end =============================

//  =============================   RSA 1024  testcase begin =============================
// basic generator create test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest271, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest272, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest273, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest274, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest275, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest276, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest277, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest278, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest279, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest280, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest281, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest282, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest283, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest284, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest285, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest286, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest287, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest288, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest289, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest290, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest291, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest292, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest293, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest294, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest295, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest296, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest297, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest298, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest299, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest300, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest301, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest302, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest303, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest304, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest305, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest306, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest307, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest308, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest309, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest310, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest311, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest312, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest313, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_1024_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest314, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest315, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest316, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest317, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest318, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest319, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest320, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest321, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest322, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest323, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest324, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest325, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest326, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest327, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest328, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest329, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest330, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest331, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest332, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest333, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest334, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest335, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest336, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest337, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 1024 generate keyPair get all big int
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest338, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_1024_D_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_1024_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 1024 generate pub key get
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest339, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_1024_E_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_1024_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_1024_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 1024 generate common key spec (not support)
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest340, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_1024_N_BYTE_SIZE] = {0};
    GenerateRsa1024CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}
//  =============================   RSA 1024  testcase end =============================


//  =============================   RSA 3072  testcase begin =============================
// basic generator create test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest341, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest342, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest343, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest344, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest345, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest346, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest347, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest348, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest349, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest350, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest351, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest352, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest353, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest354, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest355, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest356, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest357, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest358, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest359, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest360, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest361, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest362, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest363, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest364, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest365, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest366, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest367, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest368, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest369, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest370, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest371, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest372, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest373, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest374, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest375, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest376, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest377, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest378, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest379, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest380, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest381, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest382, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest383, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_3072_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest384, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest385, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest386, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest387, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest388, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest389, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest390, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest391, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest392, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest393, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest394, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest395, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest396, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest397, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest398, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest399, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA3072", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest400, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest401, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest402, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest403, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest404, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest405, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest406, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest407, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 3072 generate keyPair get all big int
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest408, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_3072_D_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_3072_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 3072 generate pub key get
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest409, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_3072_E_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_3072_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_3072_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 3072 generate common key spec (not support)
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest410, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_3072_N_BYTE_SIZE] = {0};
    GenerateRsa3072CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}
//  =============================   RSA 3072  testcase end =============================

//  =============================   RSA 4096  testcase begin =============================
// basic generator create test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest411, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest412, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest413, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest414, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest415, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest416, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest417, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest418, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest419, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest420, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest421, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest422, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest423, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest424, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest425, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest426, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest427, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest428, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest429, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest430, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest431, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest432, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest433, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest434, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest435, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest436, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest437, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest438, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest439, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest440, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest441, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest442, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest443, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest444, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest445, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest446, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest447, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest448, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest449, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest450, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest451, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest452, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest453, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_4096_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest454, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest455, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest456, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest457, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest458, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest459, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest460, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest461, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest462, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest463, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest464, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest465, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest466, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest467, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest468, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest469, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA4096", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest470, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest471, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest472, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest473, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest474, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest475, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest476, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest477, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 4096 generate keyPair get all big int
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest478, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_4096_D_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_4096_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 4096 generate pub key get
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest479, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_4096_E_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_4096_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_4096_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 4096 generate common key spec (not support)
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest480, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_4096_N_BYTE_SIZE] = {0};
    GenerateRsa4096CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}
//  =============================   RSA 4096  testcase end =============================

//  =============================   RSA 8192  testcase begin =============================
// basic generator create test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest481, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest482, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest483, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// test generator by spec genrate key funciton not null
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest484, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfObjDestroy(generator);
}

// test generator by spec get class string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest485, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecClass = generator->base.getClass();
    EXPECT_STREQ(generatorBySpecClass, g_asyKeyGeneratorBySpecClass);
    HcfObjDestroy(generator);
}

// test generator by spec get getAlgName string test
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest486, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    const char *generatorBySpecAlgName = generator->getAlgName(generator);
    EXPECT_STREQ(generatorBySpecAlgName, g_rsaAlgName);
    HcfObjDestroy(generator);
}

// test generator by spec basic destroy
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest487, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);


    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    generator->base.destroy(&(generator->base));
}
// test correct spec and generate key pair, pri key, and pub key.
// pub spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest488, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest489, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest490, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);
    EXPECT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest491, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest492, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest493, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check normal key function from key pairs of key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest494, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *keyPairClassName = keyPair->base.getClass();
    EXPECT_STREQ(keyPairClassName, OPENSSL_RSA_KEYPAIR_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest495, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest496, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkClassName = keyPair->pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest497, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest498, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest499, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest500, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest501, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest502, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest503, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *skClassName = keyPair->priKey->base.base.getClass();
    EXPECT_STREQ(skClassName, OPENSSL_RSA_PRIKEY_CLASS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest504, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest505, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *alg = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest506, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest507, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest508, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);

    HcfFree(n.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest509, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    const char *pkFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);

    HcfFree(d.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest510, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest511, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest512, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest513, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest514, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest515, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest516, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check key function of pri key generated by key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest517, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkClassName = priKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PRIKEY_CLASS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest518, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    priKey->base.base.destroy(&(priKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest519, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *alg = priKey->base.getAlgorithm(&(priKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest520, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(blob.data, nullptr);
    EXPECT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest521, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    const char *pkFormat = priKey->base.getFormat(&(priKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PRIKEY_FORMAT);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest522, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest523, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    HcfBigInteger d = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &d);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(d.data, nullptr);
    EXPECT_NE(d.len, 0);
    res = memcmp(d.data, dataD, RSA_8192_D_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(d.data);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// check key functions of pub key from pub key spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest524, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkClassName = pubKey->base.base.getClass();
    EXPECT_STREQ(pkClassName, OPENSSL_RSA_PUBKEY_CLASS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest525, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&(pubKey->base.base));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest526, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *alg = pubKey->base.getAlgorithm(&(pubKey->base));
    EXPECT_STREQ(alg, OPENSSL_RSA_ALGORITHM);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest527, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest528, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    const char *pkFormat = pubKey->base.getFormat(&(pubKey->base));
    EXPECT_STREQ(pkFormat, OPENSSL_RSA_PUBKEY_FORMAT);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest529, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger n = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &n);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(n.data, nullptr);
    EXPECT_NE(n.len, 0);
    res = memcmp(n.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(n.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest530, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger e = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &e);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(e.data, nullptr);
    EXPECT_NE(e.len, 0);
    res = memcmp(e.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(e.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check encoded key pair's pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest531, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest532, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pub key spec and convert to pub key object
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest533, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfFree(blob.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded key pair's pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest534, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest535, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    // encoded and convert key pair's pubKey
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from key pair spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest536, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest537, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert key pair's pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check encoded pub key from pubKey spec, convert to pub key object and check the get function
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest538, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_PK_BN, &dupE);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupE.data, nullptr);
    EXPECT_NE(dupE.len, 0);
    res = memcmp(dupE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupE.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest539, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    // encoded and convert pubKey
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(blob.data, nullptr);
    EXPECT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generatorConvert = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA8192", &generatorConvert);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorConvert, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorConvert->convertKey(generatorConvert, nullptr, &blob, nullptr, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair->priKey, nullptr);
    EXPECT_NE(dupKeyPair->pubKey, nullptr);

    HcfBigInteger dupN = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(dupKeyPair->pubKey, RSA_N_BN, &dupN);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupN.data, nullptr);
    EXPECT_NE(dupN.len, 0);
    res = memcmp(dupN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(res, 0);

    HcfFree(blob.data);
    HcfFree(dupN.data);
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorConvert);
}

// check invalid get key functions of key pair's pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest540, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest541, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of key pair's pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest542, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecInt, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)keyPair->pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest543, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    EXPECT_NE(keyPair->priKey->getAsyKeySpecString, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pub key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest544, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecInt, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest545, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    EXPECT_NE(pubKey->getAsyKeySpecString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// check invalid get key functions of pri key from key pair spec
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest546, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecInt, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest547, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    EXPECT_EQ(CheckGeneratorBySpecKeyFunc(generator), true);
    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priKey, nullptr);

    EXPECT_NE(priKey->getAsyKeySpecString, nullptr);

    priKey->clearMem(priKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 8192 generate keyPair get all big int
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest548, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec rsaPairSpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    unsigned char dataD[RSA_8192_D_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectKeyPairSpec(dataN, dataE, dataD, &rsaPairSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPairSpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    // generator key type from generator's spec
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnPriN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    HcfBigInteger returnD = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_N_BN, &returnPriN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, RSA_SK_BN, &returnD);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    // check the array data
    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnPriN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnD.data, dataD, RSA_8192_D_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);

    HcfFree(returnPubN.data);
    HcfFree(returnPriN.data);
    HcfFree(returnD.data);
    HcfFree(returnE.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: RSA 8192 generate pub key get
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest549, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    unsigned char dataE[RSA_8192_E_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectPubKeySpec(dataN, dataE, &rsaPubKeySpec);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec), &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubKey, nullptr);

    HcfBigInteger returnPubN = { .data = nullptr, .len = 0 };
    HcfBigInteger returnE = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_N_BN, &returnPubN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, RSA_PK_BN, &returnE);
    EXPECT_EQ(res, HCF_SUCCESS);

    int memRes = 0;
    memRes = memcmp(returnPubN.data, dataN, RSA_8192_N_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    memRes = memcmp(returnE.data, dataE, RSA_8192_E_BYTE_SIZE);
    EXPECT_EQ(memRes, 0);
    HcfFree(returnPubN.data);
    HcfFree(returnE.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate incorrect case: RSA 8192 generate common key spec (not support)
HWTEST_F(CryptoRsaAsyKeyGeneratorBySpecTest, CryptoRsaAsyKeyGeneratorBySpecTest550, TestSize.Level0)
{
    HcfRsaCommParamsSpec rsaCommSpec = {};

    unsigned char dataN[RSA_8192_N_BYTE_SIZE] = {0};
    GenerateRsa8192CorrectCommonKeySpec(dataN, &rsaCommSpec);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaCommSpec), &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    HcfObjDestroy(generator);
}
//  =============================   RSA 8192  testcase end =============================
}
