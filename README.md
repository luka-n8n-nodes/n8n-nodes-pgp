# n8n-nodes-pgp

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![N8N](https://img.shields.io/badge/platform-N8N-brightgreen.svg)
![TypeScript](https://img.shields.io/badge/language-TypeScript-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18.10-green.svg)

A comprehensive N8N community node for seamless integration of PGP (Pretty Good Privacy) encryption functionalities into n8n workflows. Encrypt, decrypt, sign, and verify messages effortlessly with OpenPGP standard support.

[OpenPGP](https://www.openpgp.org/) is a standard for encryption and signing of data.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/reference/license/) workflow automation platform.

## 🚀 Features

- ✅ **6 Core Operations**: Encrypt, Decrypt, Sign, Verify, Encrypt-And-Sign, Decrypt-And-Verify
- ✅ **Text & Binary Support**: Handle both text messages and binary files
- ✅ **Embedded Signatures**: Support for embedded signatures in encrypted messages
- ✅ **Compression Support**: Automatic compression for binary files
- ✅ **Secure Credentials**: Password-protected key management
- ✅ **TypeScript Support**: Full type definitions and IntelliSense
- ✅ **High Test Coverage**: 98.93% code coverage with comprehensive unit tests

## 📦 Installation

### Method 1: NPM Installation (Recommended)

```bash
npm install @luka-cat-mimi/n8n-nodes-pgp
```

### Method 2: Manual Installation

1. Clone or download the project to your local machine
2. Install dependencies and build the project

```bash
pnpm install
pnpm build
```

3. Copy the compiled files to N8N's `custom` directory

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation for detailed instructions.

## ⚙️ Configuration

### Credentials Setup

To authenticate with this node, you need to provide the following credentials:

| Field | Description | Example | Required |
|-------|-------------|---------|----------|
| **Passphrase** | The passphrase for the private key | `your-secure-passphrase` | ❌ |
| **Public Key** | Armored public key for encryption and verification | `-----BEGIN PGP PUBLIC KEY BLOCK-----...` | ❌ |
| **Private Key** | Armored private key for decryption and signing | `-----BEGIN PGP PRIVATE KEY BLOCK-----...` | ❌ |

> **Note**: All credential fields are optional, but you'll need at least a Public Key for encryption/verification operations and a Private Key (with optional Passphrase) for decryption/signing operations.

### Getting PGP Keys

You can generate PGP keys using various tools:

- **GPG Command Line**: `gpg --gen-key` and `gpg --export` / `gpg --export-secret-keys`
- **Online Tools**: Various web-based PGP key generators
- **OpenPGP.js**: Use the OpenPGP.js library directly

## 📊 Operations

### Core Operations

| Operation | Description | Input Type | Output Type |
|-----------|-------------|------------|-------------|
| **Encrypt** | Encrypts text or binary files using a public key. Binary files can be compressed before encryption. | Text/Binary | Encrypted Message |
| **Decrypt** | Decrypts text or binary files using a private key. Compressed files are automatically decompressed after decryption. | Encrypted Message | Text/Binary |
| **Sign** | Creates a digital signature for text or binary files using a private key. | Text/Binary | Signature |
| **Verify** | Checks if a digital signature is valid for text or binary files using a public key. | Text/Binary + Signature | Verification Result |
| **Encrypt-And-Sign** | Encrypts and signs text or binary files in one step. Supports both detached and embedded signatures. | Text/Binary | Encrypted Message + Signature |
| **Decrypt-And-Verify** | Decrypts and verifies text or binary files in one step. Supports both detached and embedded signatures. | Encrypted Message + Signature | Text/Binary + Verification Result |

### Embedded Signatures

The **Encrypt-And-Sign** and **Decrypt-And-Verify** operations support embedded signatures:

- **Embed Signature** (Encrypt-And-Sign): When enabled, the signature is embedded within the encrypted message rather than provided as a separate output. This creates a standard OpenPGP message format that includes both encryption and signature verification in a single message.
- **Embedded Signature** (Decrypt-And-Verify): When enabled, the node expects the message to contain an embedded signature and will automatically verify it during decryption. No separate signature input is required.

By default, both options are disabled to maintain backward compatibility with existing workflows that use detached signatures.

## 🛠️ Usage Examples

### Basic Usage

1. **Add PGP Node** to your workflow
2. **Select Operation** (e.g., "Encrypt", "Decrypt", "Sign", "Verify")
3. **Configure Credentials**: Set up your PGP credentials with Public/Private keys
4. **Configure Parameters**:
   - Select input data type (Text or Binary)
   - For binary operations, choose compression options if needed
   - For signature operations, configure embedded/detached signature options

### Encrypt Text Example

1. Select **Operation**: "Encrypt"
2. **Input Type**: "Text"
3. **Input Data**: Your plain text message
4. **Public Key**: Recipient's public key (from credentials)
5. The output will be an encrypted armored message

### Decrypt Text Example

1. Select **Operation**: "Decrypt"
2. **Input Type**: "Text"
3. **Input Data**: Encrypted armored message
4. **Private Key**: Your private key (from credentials)
5. **Passphrase**: Your passphrase if the key is encrypted
6. The output will be the decrypted plain text

### Sign and Verify Example

1. **Signing**:
   - Select **Operation**: "Sign"
   - **Input Type**: "Text" or "Binary"
   - **Input Data**: Your message
   - **Private Key**: Your private key
   - **Passphrase**: Your passphrase
   - Output: Digital signature

2. **Verification**:
   - Select **Operation**: "Verify"
   - **Input Data**: Original message
   - **Signature**: Digital signature from signing step
   - **Public Key**: Signer's public key
   - Output: Verification result (valid/invalid)

### Encrypt-And-Sign Example

1. Select **Operation**: "Encrypt-And-Sign"
2. **Input Type**: "Text"
3. **Input Data**: Your message
4. **Public Key**: Recipient's public key (for encryption)
5. **Private Key**: Your private key (for signing)
6. **Embed Signature**: Enable if you want embedded signature
7. Output: Encrypted message (with optional embedded signature) + separate signature (if detached)

## 🔧 Development

### Project Structure

```text
n8n-nodes-pgp/
├── credentials/                 # Credential definitions
│   ├── PgpCredentialsApi.credentials.ts
│   └── key.svg
├── nodes/                      # Node definitions
│   └── PgpNode/
│       ├── PgpNode.node.ts
│       ├── key.svg
│       └── utils/              # Utility functions
│           ├── BinaryUtils.ts
│           ├── DataCompressor.ts
│           └── operations.ts
├── tests/                      # Unit tests
│   ├── binary-utils.test.ts
│   ├── data-compressor.test.ts
│   ├── encrypt.test.ts
│   ├── sign.test.ts
│   └── embedded-signature.test.ts
├── dist/                       # Compiled output
├── package.json
├── tsconfig.json
└── gulpfile.js
```

### Build Commands

```bash
# Development mode (watch for file changes)
pnpm dev

# Build
pnpm build

# Run tests
pnpm test

# Run tests with coverage
pnpm coverage

# Watch tests
pnpm test:watch

# Lint code
pnpm lint

# Fix linting issues
pnpm lintfix

# Format code
pnpm format
```

## 📊 Test Results

This section displays the results of unit tests for each operation, based on a live n8n instance.

| Operation        | Last Tested | Status    |
|------------------|-------------|-----------|
| Encrypt (Text)   | 2025-12-03  | ✅ Success |
| Decrypt (Text)   | 2025-12-03  | ✅ Success |
| Sign (Text)      | 2025-12-03  | ✅ Success |
| Verify (Text)    | 2025-12-03  | ✅ Success |
| Encrypt (Binary) | 2025-12-03  | ✅ Success |
| Decrypt (Binary) | 2025-12-03  | ✅ Success |
| Sign (Binary)    | 2025-12-03  | ✅ Success |
| Verify (Binary)  | 2025-12-03  | ✅ Success |

### Unit Tests

Unit tests can be executed with the following command:

```bash
pnpm test
```

#### Test Results

**binary-utils.test.ts**

* Convert text data to base64 string
* Convert base64 string back to text data
* Convert binary data to base64 string
* Convert base64 string back to binary data

**sign.test.ts**

* Signs and verifies text message
* Signs and verifies text message with encrypted private key
* Verify fails with a different keypair
* Signs binary data
* Verify fails with a different keypair

**data-compressor.ts**

* Compresses and decompresses with zlib
* Compresses and decompresses with zip
* Throws an error for unsupported algorithm during compression
* Throws an error for unsupported algorithm during decompression

**encrypt.test.ts**

* Encrypts and decrypts a text message
* Encrypts and decrypts a text message with encrypted private key
* Decryption fails with a different private key
* Encrypts and decrypts a binary file
* Binary decryption fails with a different private key
* Encrypts and decrypts a compressed binary file

**embedded-signature.test.ts**

* Encrypts and decrypts text with embedded signature
* Encrypts and decrypts text with embedded signature using encrypted private key
* Decrypt fails with wrong private key but embedded signature verification still works
* Encrypts and decrypts binary with embedded signature
* Encrypts and decrypts binary with embedded signature using encrypted private key
* Backward compatibility: detached signature still works
* Embedded signature verification fails with wrong public key
* Handle invalid messages gracefully
* Handle messages without signatures gracefully

#### Code Coverage:

* Statements: 98.93%
* Branches: 100%
* Functions: 100%
* Lines: 98.91%

## 🤝 Contributing

Contributions are welcome! Please feel free to submit Issues and Pull Requests.

### Contribution Guidelines

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License. See the [LICENSE.md](./LICENSE.md) file for details.

## 🆘 Support

- 📧 Email: **dengxiaomei714@gmail.com**
- 🐛 Issue Tracker: [GitHub Issues](https://github.com/luka-n8n-nodes/n8n-nodes-pgp/issues)
- 📖 OpenPGP.js Documentation: [openpgpjs.org](https://openpgpjs.org/)
- 📖 n8n Community Nodes Documentation: [n8n Docs](https://docs.n8n.io/integrations/community-nodes/)

## ⭐ Acknowledgments

This project is developed based on the original repository [hapheus/n8n-nodes-pgp](https://github.com/hapheus/n8n-nodes-pgp). Special thanks to the original author [Franz Haberfellner](https://github.com/hapheus) for creating this excellent PGP integration for n8n.

We also thank:
- [N8N](https://n8n.io/) for providing the powerful automation platform
- [OpenPGP.js](https://openpgpjs.org/) for the robust OpenPGP implementation

---

If this project helps you, please give it a ⭐️!
