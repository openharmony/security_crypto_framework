# 加解密算法库框架

## 简介
为屏蔽底层硬件和算法库，向上提供统一的密码算法库加解密和证书相关接口。

## 目录
```
base/security/crypto_framwork
├── build                    # 配置构建相关
├── interfaces               # 对外接口目录
├── test                     # unitest
├── common                   # 内部依赖的公共方法
├── plugin                   # 算法适配的插件
│   └── openssl_plugin       # openssl 插件
├── frameworks               # api调用SPI的实现
│   ├── spi                  # 放SPI的头文件
│   ├── js
│       └── napi             # 通过napi封装的JS接口代码实现
│   ├── algorithm_parameter  # 算法参数
│   ├── certificate          # 证书
│   ├── crypto_operation     # 算法操作，包括mac、md、加解密、签名验签、秘钥协商
│   ├── key
│   └── rand
```

## 相关仓

**安全子系统**

[security\_crypto\_framwork](https://gitee.com/openharmony/security_crypto_framwork)