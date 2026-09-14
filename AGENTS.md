# 加解密算法库框架组件指引

## 算法库概述

加解密算法库框架（Crypto Architecture Kit / crypto_framework）是 OpenHarmony 安全子系统下的密码学算法框架，屏蔽第三方密码学算法库（standard 系统用 OpenSSL、mini 系统用 mbedTLS）的实现差异，对外提供统一的加解密、签名验签、消息验证码（MAC）、消息摘要（MD）、密钥协商、密钥派生（KDF）、密钥封装（KEM）、安全随机数等能力。仅提供基础密码算法能力，不提供密钥管理能力，密钥材料的持久化存储、安全存储与生命周期管理由HUKS（OpenHarmony Universal KeyStore，OpenHarmony通用密钥库系统） 负责，HUKS不在本模职责范围内。

## 项目定位

本仓库对应 OpenHarmony `base/security/crypto_framework`。加解密算法库框架屏蔽了第三方密码学算法库（OpenSSL、mbedTLS）的实现差异，对外提供统一的加解密、签名验签、消息验证码、哈希、密钥协商、KDF、安全随机数等能力。优先按这些目录定位问题：

- `frameworks/`：框架实现层，通过 SPI 加载插件，适配并屏蔽三方算法库差异。
- `frameworks/spi/`：框架与插件之间的服务提供者接口，是框架与插件解耦的关键边界。
- `frameworks/crypto_operation/`、`frameworks/key/`：算法操作和密钥材料的框架侧实现。
- `frameworks/js/napi/`、`frameworks/js/ani/`、`frameworks/js/jsi/`：JS 接口的三种封装（NAPI/ANI/JSI）。
- `frameworks/native/`、`frameworks/cj/`：对外 C 接口（ohcrypto）和 Cangjie FFI 接口。
- `plugin/openssl_plugin/`、`plugin/mbedtls_plugin/`：针对具体三方算法库的插件实现（standard 系统用 OpenSSL，mini 系统用 mbedTLS）。
- `interfaces/kits/native/`：public C API 头文件。
- `interfaces/inner_api/`：inner c接口，为框架层的接口，JS 接口和 public C API 均调用inner c接口，OpenHarmony内部模块可能会调用inner c接口。
- `common/`：内部公共方法（日志、内存、字符串、Parcel、参数解析）。
- `test/unittest/`、`test/fuzztest/`：单元测试和 fuzz 目标。

### 按任务类型定位代码

| 任务类型　　　　　　　　　 | 先看　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| ----------------------------| ------------------------------------------------------------------------------------------------|
| 新增/修改对称加解密算法　　| `plugin/openssl_plugin/crypto_operation/cipher/`中aes、chacha20、des、和cipher_openssl.c文件　 |
| 新增/修改非对称加解密　　　| `plugin/openssl_plugin/crypto_operation/cipher/`中sm2、rsa文件　　　　　　　　　　　　　　　　 |
| 新增/修改签名验签　　　　　| `plugin/openssl_plugin/crypto_operation/signature/`　　　　　　　　　　　　　　　　　　　　　　|
| 新增/修改消息摘要　　　　　| `plugin/openssl_plugin/crypto_operation/md/`、`plugin/mbedtls_plugin/md/`　　　　　　　　　　　|
| 新增/修改消息认证码　　　　| `plugin/openssl_plugin/crypto_operation/hmac/`　　　　　　　　　　　　　　　　　　　　　　　　 |
| 新增/修改密钥派生　　　　　| `plugin/openssl_plugin/crypto_operation/kdf/`　　　　　　　　　　　　　　　　　　　　　　　　　|
| 新增/修改密钥协商　　　　　| `plugin/openssl_plugin/crypto_operation/key_agreement/`　　　　　　　　　　　　　　　　　　　　|
| 新增/修改安全随机数　　　　| `plugin/openssl_plugin/crypto_operation/rand/`、`plugin/mbedtls_plugin/rand/`　　　　　　　　　|
| 新增/修改密钥封装　　　　　| `plugin/openssl_plugin/crypto_operation/kem/`　　　　　　　　　　　　　　　　　　　　　　　　　|
| 新增/修改对称密钥生成　　　| `plugin/openssl_plugin/key/sym_key_generator/`　　　　　　　　　　　　　　　　　　　　　　　　 |
| 新增/修改非对称密钥生成　　| `plugin/openssl_plugin/key/asy_key_generator/`　　　　　　　　　　　　　　　　　　　　　　　　 |
| 新增/修改算法参数规格　　　| `common/src/params_parser.c`，仅对称/非对称加解密算法、密钥派生、签名验签、对称/非对称密钥生成 |
| 新增/修改框架层　　　　　　| `frameworks/crypto_operation`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 inner c 接口　　　　　| `interfaces/inner_api`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 NAPI JS 接口　　　　　| `frameworks/js/napi/crypto/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 ANI JS 接口　　　　　 | `frameworks/js/ani/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 JSI 接口（mini 系统） | `frameworks/js/jsi/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 public C 接口　　　　 | `frameworks/native/src`、`interfaces/kits/native/include/`　　　　　　　　　　　　　　　　　　 |
| 修改 Cangjie FFI 接口　　　| `frameworks/cj/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| 修改 SPI 接口定义　　　　　| `frameworks/spi/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 OpenSSL 适配公共逻辑　| `plugin/openssl_plugin/common/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|
| 修改 API 度量统计　　　　　| `frameworks/api_metrics/`　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　|

### 嵌套指引

本仓库无目录级别的嵌套指引。所有任务级指导通过本文件和接口头文件中的注释提供。

## 知识索引

### 词汇型路由

当任务描述、issue、日志、API 或文件中出现以下术语时，先读对应文件再动手。
插件层路径以 `plugin/openssl_plugin/crypto_operation/` 为根，省略前缀。

#### 对称加解密

共享链路：JS `napi_cipher.cpp`/`ani_cipher.cpp`（IDL: `ohos.security.cryptoFramework.cryptoFramework.taihe`）→ public C `frameworks/native/src/sym_cipher.c`、`crypto_asym_cipher.c` → inner c `interfaces/inner_api/crypto_operation/cipher.h` → SPI `frameworks/spi/cipher_factory_spi.h` → 框架层 `frameworks/crypto_operation/cipher.c`

| 领域术语 | 插件层实现 |
| --- | --- |
| AES | `cipher/src/cipher_aes_openssl.c`、`cipher_aes_common.c`；公共：`common/inc/aes_openssl_common.h` |
| SM4 | `cipher/src/cipher_sm4_openssl.c` |
| DES / 3DES | `cipher/src/cipher_des_openssl.c` |
| ChaCha20 / Poly1305 | `cipher/src/cipher_chacha20_openssl.c` |
| 通用对称调度 | `cipher/src/cipher_openssl.c` |

#### 非对称加解密

共享上述链路。

| 领域术语 | 插件层实现 |
| --- | --- |
| RSA（PKCS1/OAEP） | `cipher/src/cipher_rsa_openssl.c`；公共：`common/inc/rsa_openssl_common.h` |
| SM2 | `cipher/src/cipher_sm2_openssl.c` |

#### 签名验签

共享链路：JS `napi_sign.cpp`、`napi_verify.cpp`/`ani_sign.cpp`、`ani_verify.cpp` → public C `frameworks/native/src/signature.c` → inner c `interfaces/inner_api/crypto_operation/signature.h` → SPI `frameworks/spi/signature_spi.h` → 框架层 `frameworks/crypto_operation/signature.c`

| 领域术语 | 插件层实现 |
| --- | --- |
| RSA 签名（PKCS1/PSS） | `signature/src/signature_rsa_openssl.c` |
| ECDSA | `signature/src/ecdsa_openssl.c` |
| SM2 签名 | `signature/src/sm2_openssl.c` |
| DSA | `signature/src/dsa_openssl.c` |
| Ed25519 | `signature/src/ed25519_openssl.c` |
| ML-DSA（后量子签名） | `signature/src/ml_dsa_openssl.c` |

#### 消息摘要

共享链路：JS `napi_md.cpp`/`ani_md.cpp` → public C `frameworks/native/src/digest.c` → inner c `interfaces/inner_api/crypto_operation/md.h` → SPI `frameworks/spi/md_spi.h` → 框架层 `frameworks/crypto_operation/md.c`

| 领域术语 | 插件层实现 |
| --- | --- |
| MD5/SHA1/SHA224/256/384/512/SHA3/SM3 | `md/src/md_openssl.c`；mbedTLS: `plugin/mbedtls_plugin/md/src/mbedtls_md.c` |

#### MAC

共享链路：JS `napi_mac.cpp`/`ani_mac.cpp` → public C `frameworks/native/src/crypto_mac.c` → inner c `interfaces/inner_api/crypto_operation/mac.h` → SPI `frameworks/spi/mac_spi.h` → 框架层 `frameworks/crypto_operation/mac.c`

| 领域术语 | 插件层实现 |
| --- | --- |
| HMAC / CMAC | `hmac/src/mac_openssl.c` |

#### 密钥协商

共享链路：JS `napi_key_agreement.cpp`/`ani_key_agreement.cpp` → public C `frameworks/native/src/crypto_key_agreement.c` → inner c `interfaces/inner_api/crypto_operation/key_agreement.h` → SPI `frameworks/spi/key_agreement_spi.h` → 框架层 `frameworks/crypto_operation/key_agreement.c`

| 领域术语 | 插件层实现 |
| --- | --- |
| DH（modp/ffdhe） | `key_agreement/src/dh_openssl.c`；公共：`common/inc/dh_openssl_common.h` |
| ECDH（含 Brainpool） | `key_agreement/src/ecdh_openssl.c`；公共：`common/inc/ecc_openssl_common.h` |
| X25519 | `key_agreement/src/x25519_openssl.c` |

#### KDF

共享链路：JS `napi_kdf.cpp`/`ani_kdf.cpp` → public C `frameworks/native/src/crypto_kdf.c` → inner c `interfaces/inner_api/crypto_operation/kdf.h` → SPI `frameworks/spi/kdf_spi.h` → 框架层 `frameworks/crypto_operation/kdf.c`

| 领域术语 | 插件层实现 |
| --- | --- |
| HKDF | `kdf/src/hkdf_openssl.c` |
| PBKDF2 | `kdf/src/pbkdf2_openssl.c` |
| scrypt | `kdf/src/scrypt_openssl.c` |
| X963KDF | `kdf/src/x963kdf_openssl.c` |

#### 密钥封装（KEM）

JS `napi_kem.cpp`/`ani_kem.cpp` → inner c `interfaces/inner_api/crypto_operation/kem.h` → SPI `frameworks/spi/kem_spi.h` → 框架层 `frameworks/crypto_operation/kem.c` → 插件层 `kem/src/kem_openssl.c`

#### 安全随机数

共享链路：JS `napi_rand.cpp`/`ani_rand.cpp` → public C `frameworks/native/src/crypto_rand.c` → inner c `interfaces/inner_api/crypto_operation/rand.h` → SPI `frameworks/spi/rand_spi.h` → 框架层 `frameworks/crypto_operation/rand.c`

| 领域术语 | 插件层实现 |
| --- | --- |
| CTR_DRBG / OpenSSL RAND | `rand/src/rand_openssl.c` |
| 硬件熵源 / HUKS | `rand/src/rand_hks_provider.c` |

#### 对称密钥生成

JS `napi_sym_key_generator.cpp`/`ani_sym_key_generator.cpp` → public C `frameworks/native/src/sym_key.c` → inner c `interfaces/inner_api/key/sym_key_generator.h`、`sym_key.h` → SPI `frameworks/spi/sym_key_factory_spi.h` → 框架层 `frameworks/key/sym_key_generator.c` → 插件层 `plugin/openssl_plugin/key/sym_key_generator/src/sym_key_openssl.c`

#### 非对称密钥生成

共享链路：JS `napi_asy_key_generator.cpp`、`napi_asy_key_spec_generator.cpp`/`ani_asy_key_generator.cpp`、`ani_asy_key_generator_by_spec.cpp` → public C `frameworks/native/src/asym_key.c` → inner c `interfaces/inner_api/key/asy_key_generator.h`、`key.h`、`key_pair.h`、`pri_key.h`、`pub_key.h` → SPI `frameworks/spi/asy_key_generator_spi.h` → 框架层 `frameworks/key/asy_key_generator.c`

插件层路径以 `plugin/openssl_plugin/key/asy_key_generator/src/` 为根。

| 领域术语 | 插件层实现 |
| --- | --- |
| RSA 密钥生成 | `rsa_asy_key_generator_openssl.c` |
| ECC 密钥生成 | `ecc_asy_key_generator_openssl.c`、`ecc_common_asy_key_generator_openssl.c` |
| SM2 密钥生成 | `sm2_asy_key_generator_openssl.c` |
| DH 密钥生成 | `dh_asy_key_generator_openssl.c` |
| Ed25519/X25519 密钥生成 | `alg_25519_asy_key_generator_openssl.c` |
| DSA 密钥生成 | `dsa_asy_key_generator_openssl.c` |
| ML-DSA 密钥生成 | `ml_dsa_asy_key_generator_openssl.c` |
| ML-KEM 密钥生成 | `ml_kem_asy_key_generator_openssl.c` |

#### 辅助能力

| 领域术语 | JS(NAPI/ANI) | inner c | 框架层 | 插件层 |
| --- | --- | --- | --- | --- |
| SM2 密文格式（C1C3C2/C1C2C3）转换 | `napi_sm2_crypto_util.cpp`、`ani_sm2_crypto_util.cpp` | `sm2_crypto_util.h`、`algorithm_parameter/sm2_crypto_params.h` | `sm2_crypto_util.c` | `cipher/src/cipher_sm2_crypto_util_openssl.c`；公共：`common/inc/openssl_adapter.h`（`Sm2CipherTextSt`） |
| EC/SM2 签名数据格式（r/s DER 编解码）转换 | `napi_sm2_ec_signature.cpp`、`ani_signature_utils.cpp` | `sm2_ec_signature_data.h` | `sm2_ec_signature_data.c` | `cipher/src/cipher_sm2_ecdsa_signature_openssl.c`；公共：`common/inc/openssl_adapter.h`（`OpensslEcdsaSigNew`/`OpensslD2iSm2EcdsaSig`/`OpensslI2dSm2EcdsaSig`） |
| PEM/DER 密钥编解码 | `napi_pri_key.cpp`、`napi_pub_key.cpp` | `key/pri_key.h`、`pub_key.h` | `frameworks/key/asy_key_generator.c` | `plugin/openssl_plugin/key/asy_key_generator/`；公共：`common/inc/openssl_common.h` |
| DH 密钥工具（命名组参数生成） | `napi_dh_key_util.cpp`、`ani_dh_key_util.cpp` | `key/dh_key_util.h` | `frameworks/key/dh_key_util.c` | `plugin/openssl_plugin/key/asy_key_generator/src/dh_common_param_spec_generator_openssl.c` |
| ECC 密钥工具（点编解码/参数生成） | `napi_ecc_key_util.cpp`、`ani_ecc_key_util.cpp` | `key/ecc_key_util.h` | `frameworks/key/ecc_key_util.c` | `plugin/openssl_plugin/key/asy_key_generator/src/ecc_common_param_spec_generator_openssl.c` |
| 算法名解析（如 `AES128\|CBC\|NoPadding`） | — | `algorithm_parameter/algorithm_parameter.h`、`detailed_*.h` | — | `common/src/params_parser.c` |
| AEAD（GCM/CCM）参数 | — | `algorithm_parameter/detailed_gcm_params.h`、`detailed_ccm_params.h`、`detailed_aead_params.h` | — | — |
| RSA 填充（PKCS1/OAEP/PSS） | — | `crypto_operation/cipher.h`（`OAEP_*`）、`signature.h`（`PSS_*`） | — | `common/inc/rsa_openssl_common.h` |

### 任务型路由

当任务涉及多个"按任务类型定位代码"表中的类型时，按下表确定依次涉及的类型和顺序：

| 任务场景 | 依次涉及的任务类型 |
| --- | --- |
| JS 接口新增一个定长摘要算法（如 SM3） | 新增/修改消息摘要 |
| JS 接口新增一个 XOF 摘要算法（需新增接口） | 新增/修改消息摘要 → 修改 SPI 接口定义 → 新增/修改框架层 → 修改 NAPI JS 接口 + 修改 ANI JS 接口 |
| JS 接口新增一个摘要算法（不新增接口，仅扩展算法名） | 新增/修改消息摘要 → 新增/修改算法参数规格 |
| JS 接口新增一个签名算法（不新增接口，仅扩展算法名） | 新增/修改签名验签 → 修改 inner c 接口（如需新增签名参数）→ 新增/修改算法参数规格 |

通用规则：
- 仅扩展算法名（不新增接口）：插件实现 → 算法参数规格（`params_parser.c`）
- 新增接口：插件实现 → SPI 接口定义 → 框架层 → NAPI JS 接口 + ANI JS 接口
- 新增 inner c 接口参数：插件实现 → inner c 接口（`interfaces/inner_api`）→ 算法参数规格
- 修改 public C 接口：inner c 接口 → public C 接口（`frameworks/native/src`）→ 版本脚本（`crypto_native.map`）

### 开始编辑前

在修改代码前，按以下顺序确认：
1. 确认任务类别
2. 根据上表确定需要阅读的文档
3. 根据"项目约束"确认不违反任何约束
4. 声明："将修改 X，已阅读 Y 文档，遵循 Z 约束"

## 构建和验证

### 构建方式1-基于OpenHarmony项目构建
构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name rk3568 --build-target crypto_framework --ccache
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 crypto_framework_test
```

public C 接口库目标为 `ohcrypto`，Cangjie FFI 库目标为 `cj_cryptoframework_ffi`，ANI 库目标为 `cryptoframework_ani`，NAPI 库目标为 `cryptoframework_napi`，框架库目标为 `crypto_framework_lib`，OpenSSL 插件库目标为 `crypto_openssl_plugin_lib`。

### 构建方式2-独立构建
无需OpenHarmony全量代码，仅下载构建算法库依赖的OpenHarmony构建工具，及其依赖的部件，不在本子目录执行。
#### 下载代码
```sh
mkdir -p openharmony/independent_build && cd openharmony/independent_build
repo init -u https://gitcode.com/openharmony/manifest.git -b master --no-repo-verify
repo sync -c build
python3 -m pip install --user build/hb
bash build/prebuilts_config.sh #执行比较耗时
repo sync -c security_crypto_framework
```

#### 构建
```sh
time hb build crypto_framework -i #构建发布件，后续构建可以添加--skip-download
time hb build crypto_framework -t #构建tdd用例，后续构建可以添加--skip-download
```

### 构建方式3-通用编译器构建

#### 准备工作
下载完代码后将修改同步到build_asan_tdd目录下的build_asan_tdd/security/crypto_framework
```sh
git clone https://gitcode.com/kang1024/build_asan_tdd.git && cd build_asan_tdd
git submodule update --init --recursive --remote # clone submodule
```
#### 构建
```sh
bash build.sh crypto        # Build crypto
bash build.sh crypto_capi   # Build crypto_capi
bash build.sh clean         # Clean output directory
```
#### 执行用例
```sh
bash build.sh test crypto_framework_test
bash build.sh test crypto_framework_capi_test
bash build.sh test certificate_framework_test # Run certificate all test
```

### 静态检查
修改 C/C++ 文件后，执行本地代码检查，确认无新增告警再提交。

检查命令从 OpenHarmony 源码根目录执行，不在本子目录执行。
```sh
./build.sh --product-name rk3568 --build-target crypto_framework --gn-args enable_cpp_static_check=true
```

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述构建命令
   - 构建方式1-基于OpenHarmony项目构建 和 构建方式2-独立构建 二选一，保证mr门禁无编译问题
   - 构建方式3-通用编译器构建 若修改inner c层以下代码，则必选，会验证inner c接口和public c接口，保证其功能，并通过ASAN检查
3. **相关测试通过** - 对应单元测试和 fuzz 测试通过
4. **板侧验证（如适用）** - 涉及加解密行为、密钥生成、随机数质量的改动需提供验证证据
5. **文档更新（如适用）** - 公共 API 修改需更新注释和文档

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（API 兼容性、密码学安全性、性能风险）、未完成事项。

## 项目约束

### 性能约束

- 加解密、签名验签、哈希等大块数据处理路径避免不必要的内存拷贝和全量格式化日志。
- 大数据加解密支持分段更新，不要在单次 doFinal 中强制缓冲全部数据。
- 随机数生成是高频调用，避免在每次调用中重复初始化插件上下文。

### 架构约束

- 框架层（`frameworks/`）与插件层（`plugin/`）必须通过 SPI（`frameworks/spi/`）解耦。框架层不直接调用 OpenSSL/mbedTLS API，插件层不直接暴露给上层。
- standard 系统使用 `openssl_plugin`，mini 系统使用 `mbedtls_plugin`，两者通过同一套 SPI 接口对接框架。新增算法能力时需同时考虑两个插件的适配范围。
- 框架对象的销毁统一走 `HcfObjDestroy` 和对象自身的 `destroy` 方法，遵循 `HcfObjectBase` 的对象模型，不要跨层手动 free。
- 插件能力通过 `HcfXxxCreate` 工厂函数按算法名实例化，算法名匹配规则集中在框架层，插件只负责实现具体算法。
- 如果某个算法不支持某个函数，必须提供空实现并返回 `HCF_ERR_INVALID_CALL`，防止上层调用时因函数指针为 NULL 导致 crash。

### 编码约定

- 本仓库以 C 语言为主（框架、插件、public C接口封装），C++ 用于 NAPI/ANI/CJ 绑定和测试。C 文件改动优先复用项目既有宏和约定。
- 内存分配使用 `HcfMalloc`/`HcfFree`（`common/inc/memory.h`），释放使用 `SELF_FREE_PTR`/`HCF_FREE_PTR` 宏，不要混用原生 `malloc`/`free`。
- 返回值统一使用 `HcfResult`（`interfaces/inner_api/common/result.h`），成功返回 `HCF_SUCCESS`，错误使用 `HCF_INVALID_PARAMS`、`HCF_NOT_SUPPORT`、`HCF_ERR_MALLOC`、`HCF_ERR_CRYPTO_OPERATION` 等。
- 日志使用 `LOGD`/`LOGI`/`LOGW`/`LOGE`（`common/inc/log.h`），不要使用 `printf` 等日志打印方式。
- 字符串操作使用 `hcf_string.h` 提供的安全封装，依赖 `bounds_checking_function` 做边界检查。
- C++ 改动（NAPI/ANI/CJ）优先复用 `napi_utils.h` 等既有封装，对象包装遵循已有的 wrap/unwrap 模式。
- napi 层一旦 C++ 对象通过 `napi_wrap` 成功绑定到 napi 对象，就不能主动释放该 C++ 对象。`napi_wrap` 绑定时已指定释放回调（finalizer），对象生命周期由 napi 托管，GC 时由回调负责 `delete`；主动释放会导致 double-free。仅在 `napi_wrap` 失败时才需手动 `delete`（参考 `napi_cipher.cpp` 中 `napi_wrap` 失败分支的处理）。
- napi 层异步接口中，若未对参数数据进行拷贝（如 `GetNapiUint8ArrayDataNoCopy` 零拷贝取数据），必须通过 `napi_create_reference` 增加该 napi 参数的引用计数，否则异步任务执行期间 JS 侧参数对象可能被 GC 释放，导致 native 层访问到已释放的内存（use-after-free）。引用在异步上下文清理时通过 `napi_delete_reference` 释放（参考 `napi_cipher.cpp` 中 `BuildContextForUpdate` 对 `inputRef` 的创建与释放）。
- napi 层异步接口中，当前操作对象（`thisVar`）同样必须通过 `napi_create_reference` 增加引用计数，否则异步任务执行期间 JS 侧 `this` 对象可能被 GC 释放，导致 native 层通过 unwrap 获取的 C++ 对象指针悬空。引用在异步上下文清理时通过 `napi_delete_reference` 释放（参考 `napi_cipher.cpp` 中 `CreateCipherRef` 对 `cipherRef` 的创建与释放）。
- JS 接口调用失败抛出异常时，`errMsg` 应尽可能详细，包含失败原因、关键参数值、算法名等上下文信息，便于应用开发者定位问题。

### 公共 API 约束

**Do not（禁止）：**
- 修改已发布的 NAPI、ANI、public C API、Inner API 的函数签名、参数类型、返回值类型
- 修改已有 API 的错误码（`Result` 枚举值），除非明确标注为废弃
- 删除或重命名已有公共 API
- 修改已有 API 的行为语义（如同步变异步、返回数据格式变化）
- 修改 `framework_lib.map`、`crypto_native.map`、`openssl_plugin.map`、`cj_cryptoframework_ffi.map` 中已导出的符号
- 修改 `interfaces/inner_api/` 和 `interfaces/kits/native/include/` 下已发布的头文件结构布局

**Ask before（修改前必须确认）：**
- 新增公共 API：确认是否需要 DFX 日志、API 度量统计（`frameworks/api_metrics/`）、错误码定义
- 新增算法能力：确认是否需要 OpenSSL 和 mbedTLS 双插件适配
- 修改inner c接口：确认是否影响OpenHarmony内部调用者
- 修改错误处理逻辑：确认是否影响应用层的错误码兼容性
- 新增 public C API：确认是否需要更新 `crypto_native.map` 版本脚本
- 新增inner c接口：确认API必须HCF开头

### 安全与密码学边界

**Do not（禁止）：**
- 在日志中输出密钥明文、私钥材料、随机数种子、中间敏感状态
- 将密钥材料或加解密结果残留内存未清零即释放（应使用安全清零后释放）
- 绕过参数校验直接将外部输入传入底层 OpenSSL/mbedTLS 接口
- 在未验证长度的情况下进行内存拷贝、缓冲区操作
- 硬编码密钥、IV、盐值等敏感常量到源码中
- 使用不安全的随机数源（如 `rand()`）替代密码学安全随机数

**Ask before（修改前必须确认）：**
- 替换OpenSSL/mbedTLS 接口
- 引入新的密码学算法或模式，其参数考虑是否完备，需确认符合相关标准（NIST/GB/T）
- 修改算法调用相关的逻辑，尤其是对称加密算法
- 修改内存安全告警相关的污点数据处理逻辑

### 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 `HcfBlob`、`HcfObjectBase`、`HcfResult` 等跨层数据结构的字段顺序和布局
- 修改算法名匹配字符串（如 `"AES128|CBC|NoPadding"`）的格式约定
- 修改密钥编码格式（PEM/DER）的输出约定
- 修改已有算法参数结构（`Hcf*ParamsSpec`）的字段顺序

**Ask before（修改前必须确认）：**
- 新增算法参数规格：确认参数序列化和兼容性处理
- 修改算法名解析规则：确认是否影响既有调用方的算法字符串

### 生成代码边界

**Do not（禁止）：**
- 直接修改 ANI IDL 编译器生成的 C++ 代码文件
- 手动编辑 `taihe_ffi_gen` 生成的 FFI 代码

**正确做法：**
- 修改 ANI 接口时编辑 IDL 定义文件（`frameworks/js/ani/idl/*.taihe`）
- 重新运行 IDL 编译器生成代码
- 如果生成代码不满足需求，考虑调整 IDL 定义

### 设备操作约束

**涉及真实设备时的注意事项：**
- 涉及加解密行为验证的改动，必须提供板侧证据（日志、测试输出）
- 不要在真实设备上执行可能影响系统安全的破坏性密码学操作
- 密码学自测（KAT）类验证需明确标注测试向量来源
