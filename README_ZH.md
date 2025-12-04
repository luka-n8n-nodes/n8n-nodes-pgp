# n8n-nodes-pgp

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![N8N](https://img.shields.io/badge/platform-N8N-brightgreen.svg)
![TypeScript](https://img.shields.io/badge/language-TypeScript-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18.10-green.svg)

一个功能完整的 N8N 社区节点，用于在 n8n 工作流中无缝集成 PGP（Pretty Good Privacy）加密功能。轻松加密、解密、签名和验证消息，支持 OpenPGP 标准。

[OpenPGP](https://www.openpgp.org/) 是用于数据加密和签名的标准。

[n8n](https://n8n.io/) 是一个[公平代码许可](https://docs.n8n.io/reference/license/)的工作流自动化平台。

## 🚀 特性

- ✅ **6 个核心操作**：加密、解密、签名、验证、加密并签名、解密并验证
- ✅ **文本和二进制支持**：处理文本消息和二进制文件
- ✅ **嵌入式签名**：支持在加密消息中嵌入签名
- ✅ **压缩支持**：二进制文件自动压缩
- ✅ **安全凭证**：密码保护的密钥管理
- ✅ **TypeScript 支持**：完整的类型定义和智能提示
- ✅ **高测试覆盖率**：98.93% 代码覆盖率，包含全面的单元测试

## 📦 安装

### 方式一：NPM 安装（推荐）

```bash
npm install @luka-cat-mimi/n8n-nodes-pgp
```

### 方式二：手动安装

1. 克隆或下载项目到本地
2. 安装依赖并构建项目

```bash
pnpm install
pnpm build
```

3. 将编译后的文件复制到 N8N 的 `custom` 目录

详细安装说明请参考 n8n 社区节点文档中的[安装指南](https://docs.n8n.io/integrations/community-nodes/installation/)。

## ⚙️ 配置

### 凭证设置

要使用此节点，需要提供以下凭证：

| 字段 | 说明 | 示例 | 必填 |
|------|------|------|------|
| **Passphrase（密码短语）** | 私钥的密码短语 | `your-secure-passphrase` | ❌ |
| **Public Key（公钥）** | 用于加密和验证的装甲公钥 | `-----BEGIN PGP PUBLIC KEY BLOCK-----...` | ❌ |
| **Private Key（私钥）** | 用于解密和签名的装甲私钥 | `-----BEGIN PGP PRIVATE KEY BLOCK-----...` | ❌ |

> **注意**：所有凭证字段都是可选的，但您至少需要一个公钥用于加密/验证操作，以及一个私钥（可选密码短语）用于解密/签名操作。

### 获取 PGP 密钥

您可以使用各种工具生成 PGP 密钥：

- **GPG 命令行**：`gpg --gen-key` 和 `gpg --export` / `gpg --export-secret-keys`
- **在线工具**：各种基于 Web 的 PGP 密钥生成器
- **OpenPGP.js**：直接使用 OpenPGP.js 库

## 📊 操作说明

### 核心操作

| 操作 | 说明 | 输入类型 | 输出类型 |
|------|------|----------|----------|
| **Encrypt（加密）** | 使用公钥加密文本或二进制文件。二进制文件可以在加密前进行压缩。 | 文本/二进制 | 加密消息 |
| **Decrypt（解密）** | 使用私钥解密文本或二进制文件。压缩文件在解密后会自动解压。 | 加密消息 | 文本/二进制 |
| **Sign（签名）** | 使用私钥为文本或二进制文件创建数字签名。 | 文本/二进制 | 签名 |
| **Verify（验证）** | 使用公钥检查数字签名是否对文本或二进制文件有效。 | 文本/二进制 + 签名 | 验证结果 |
| **Encrypt-And-Sign（加密并签名）** | 一步完成文本或二进制文件的加密和签名。支持分离式和嵌入式签名。 | 文本/二进制 | 加密消息 + 签名 |
| **Decrypt-And-Verify（解密并验证）** | 一步完成文本或二进制文件的解密和验证。支持分离式和嵌入式签名。 | 加密消息 + 签名 | 文本/二进制 + 验证结果 |

### 嵌入式签名

**Encrypt-And-Sign** 和 **Decrypt-And-Verify** 操作支持嵌入式签名：

- **Embed Signature（嵌入签名）**（Encrypt-And-Sign）：启用后，签名将嵌入到加密消息中，而不是作为单独的输出提供。这将创建一个标准的 OpenPGP 消息格式，在单个消息中包含加密和签名验证。
- **Embedded Signature（嵌入式签名）**（Decrypt-And-Verify）：启用后，节点期望消息包含嵌入式签名，并在解密期间自动验证。不需要单独的签名输入。

默认情况下，两个选项都禁用，以保持与使用分离式签名的现有工作流的向后兼容性。

## 🛠️ 使用示例

### 基础用法

1. **添加 PGP 节点**到您的工作流
2. **选择操作**（例如："Encrypt"、"Decrypt"、"Sign"、"Verify"）
3. **配置凭证**：使用公钥/私钥设置您的 PGP 凭证
4. **配置参数**：
   - 选择输入数据类型（文本或二进制）
   - 对于二进制操作，如需要可选择压缩选项
   - 对于签名操作，配置嵌入式/分离式签名选项

### 加密文本示例

1. 选择**操作**："Encrypt"
2. **输入类型**："Text"
3. **输入数据**：您的明文消息
4. **公钥**：接收方的公钥（来自凭证）
5. 输出将是加密的装甲消息

### 解密文本示例

1. 选择**操作**："Decrypt"
2. **输入类型**："Text"
3. **输入数据**：加密的装甲消息
4. **私钥**：您的私钥（来自凭证）
5. **密码短语**：如果密钥已加密，请输入您的密码短语
6. 输出将是解密的明文

### 签名和验证示例

1. **签名**：
   - 选择**操作**："Sign"
   - **输入类型**："Text" 或 "Binary"
   - **输入数据**：您的消息
   - **私钥**：您的私钥
   - **密码短语**：您的密码短语
   - 输出：数字签名

2. **验证**：
   - 选择**操作**："Verify"
   - **输入数据**：原始消息
   - **签名**：来自签名步骤的数字签名
   - **公钥**：签名者的公钥
   - 输出：验证结果（有效/无效）

### 加密并签名示例

1. 选择**操作**："Encrypt-And-Sign"
2. **输入类型**："Text"
3. **输入数据**：您的消息
4. **公钥**：接收方的公钥（用于加密）
5. **私钥**：您的私钥（用于签名）
6. **嵌入签名**：如果需要嵌入式签名，请启用
7. 输出：加密消息（带可选的嵌入式签名）+ 单独签名（如果使用分离式）

## 🔧 开发

### 项目结构

```text
n8n-nodes-pgp/
├── credentials/                 # 凭证定义
│   ├── PgpCredentialsApi.credentials.ts
│   └── key.svg
├── nodes/                      # 节点定义
│   └── PgpNode/
│       ├── PgpNode.node.ts
│       ├── key.svg
│       └── utils/              # 工具函数
│           ├── BinaryUtils.ts
│           ├── DataCompressor.ts
│           └── operations.ts
├── tests/                      # 单元测试
│   ├── binary-utils.test.ts
│   ├── data-compressor.test.ts
│   ├── encrypt.test.ts
│   ├── sign.test.ts
│   └── embedded-signature.test.ts
├── dist/                       # 编译输出
├── package.json
├── tsconfig.json
└── gulpfile.js
```

### 构建命令

```bash
# 开发模式（监听文件变化）
pnpm dev

# 构建
pnpm build

# 运行测试
pnpm test

# 运行测试并生成覆盖率报告
pnpm coverage

# 监听测试
pnpm test:watch

# 代码检查
pnpm lint

# 修复代码检查问题
pnpm lintfix

# 格式化代码
pnpm format
```

## 📊 测试结果

本节显示基于实时 n8n 实例的每个操作的单元测试结果。

| 操作 | 最后测试 | 状态 |
|------|----------|------|
| Encrypt (Text) | 2025-12-03 | ✅ 成功 |
| Decrypt (Text) | 2025-12-03 | ✅ 成功 |
| Sign (Text) | 2025-12-03 | ✅ 成功 |
| Verify (Text) | 2025-12-03 | ✅ 成功 |
| Encrypt (Binary) | 2025-12-03 | ✅ 成功 |
| Decrypt (Binary) | 2025-12-03 | ✅ 成功 |
| Sign (Binary) | 2025-12-03 | ✅ 成功 |
| Verify (Binary) | 2025-12-03 | ✅ 成功 |

### 单元测试

可以使用以下命令执行单元测试：

```bash
pnpm test
```

#### 测试结果

**binary-utils.test.ts**

* 将文本数据转换为 base64 字符串
* 将 base64 字符串转换回文本数据
* 将二进制数据转换为 base64 字符串
* 将 base64 字符串转换回二进制数据

**sign.test.ts**

* 签名并验证文本消息
* 使用加密私钥签名并验证文本消息
* 使用不同密钥对验证失败
* 签名二进制数据
* 使用不同密钥对验证失败

**data-compressor.ts**

* 使用 zlib 压缩和解压缩
* 使用 zip 压缩和解压缩
* 压缩时对不支持的算法抛出错误
* 解压缩时对不支持的算法抛出错误

**encrypt.test.ts**

* 加密和解密文本消息
* 使用加密私钥加密和解密文本消息
* 使用不同私钥解密失败
* 加密和解密二进制文件
* 使用不同私钥二进制解密失败
* 加密和解密压缩的二进制文件

**embedded-signature.test.ts**

* 使用嵌入式签名加密和解密文本
* 使用加密私钥和嵌入式签名加密和解密文本
* 使用错误私钥解密失败，但嵌入式签名验证仍然有效
* 使用嵌入式签名加密和解密二进制
* 使用加密私钥和嵌入式签名加密和解密二进制
* 向后兼容：分离式签名仍然有效
* 使用错误公钥嵌入式签名验证失败
* 优雅处理无效消息
* 优雅处理无签名消息

#### 代码覆盖率：

* 语句：98.93%
* 分支：100%
* 函数：100%
* 行：98.91%

## 🤝 贡献

欢迎贡献！请随时提交 Issue 和 Pull Request。

### 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📝 许可证

本项目采用 MIT 许可证。详情请参见 [LICENSE.md](./LICENSE.md) 文件。

## 🆘 支持

- 📧 邮箱：**dengxiaomei714@gmail.com**
- 🐛 问题追踪：[GitHub Issues](https://github.com/luka-n8n-nodes/n8n-nodes-pgp/issues)
- 📖 OpenPGP.js 文档：[openpgpjs.org](https://openpgpjs.org/)
- 📖 n8n 社区节点文档：[n8n 文档](https://docs.n8n.io/integrations/community-nodes/)

## ⭐ 致谢

本项目基于原始仓库 [hapheus/n8n-nodes-pgp](https://github.com/hapheus/n8n-nodes-pgp) 开发。特别感谢原作者 [Franz Haberfellner](https://github.com/hapheus) 为 n8n 创建了这个优秀的 PGP 集成。

我们还要感谢：
- [N8N](https://n8n.io/) 提供强大的自动化平台
- [OpenPGP.js](https://openpgpjs.org/) 提供稳健的 OpenPGP 实现

---

如果这个项目对您有帮助，请给它一个 ⭐️！

