import {
    IExecuteFunctions,
    INodeExecutionData,
    INodeType,
    INodeTypeDescription,
    NodeOperationError,
} from 'n8n-workflow';
import * as openpgp from 'openpgp';
import { PrivateKey, Key } from 'openpgp';
import {
    encryptText,
    encryptBinary,
    signText,
    signBinary,
    decryptText,
    decryptBinary,
    verifyText,
    verifyBinary,
    encryptTextWithSignature,
    encryptBinaryWithSignature,
    decryptTextWithVerification,
    decryptBinaryWithVerification,
} from './utils/operations';
import { BinaryUtils } from './utils/BinaryUtils';
import NodeUtils from '../help/utils/NodeUtils';

/**
 * Cleans and normalizes PGP armored format (keys, signatures, messages)
 * Removes extra whitespace, normalizes line endings, and ensures proper format
 * PGP armored format requires: header + blank line + data + footer
 */
function cleanArmoredKey(key: string): string {
    if (!key) {
        return key;
    }
    let cleaned = key.trim();
    cleaned = cleaned.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    const pgpBlocks = [
        { header: '-----BEGIN PGP PRIVATE KEY BLOCK-----', footer: '-----END PGP PRIVATE KEY BLOCK-----' },
        { header: '-----BEGIN PGP PUBLIC KEY BLOCK-----', footer: '-----END PGP PUBLIC KEY BLOCK-----' },
        { header: '-----BEGIN PGP SIGNATURE-----', footer: '-----END PGP SIGNATURE-----' },
        { header: '-----BEGIN PGP MESSAGE-----', footer: '-----END PGP MESSAGE-----' },
    ];

    let header = '';
    let footer = '';
    let startIdx = -1;
    let endIdx = -1;

    for (const block of pgpBlocks) {
        const headerPos = cleaned.indexOf(block.header);
        if (headerPos !== -1) {
            header = block.header;
            footer = block.footer;
            startIdx = headerPos;
            const footerPos = cleaned.indexOf(block.footer, headerPos);
            if (footerPos !== -1) {
                endIdx = footerPos + block.footer.length;
            }
            break;
        }
    }
    if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
        cleaned = cleaned.substring(startIdx, endIdx);
    }

    if (!header || !footer) {
        return cleaned;
    }
    const headerEnd = cleaned.indexOf(header) + header.length;
    const footerStart = cleaned.indexOf(footer);

    if (headerEnd >= footerStart) {
        return cleaned;
    }

    const dataPart = cleaned.substring(headerEnd, footerStart);
    const normalizedData = dataPart.trim().replace(/\n{3,}/g, '\n\n');

    return `${header}\n\n${normalizedData}\n${footer}\n`;
}

/**
 * Removes encryption extension from filename
 * If data has been decompressed, also removes compression extension
 * Handles: .pgp, .gpg, .zip.pgp, .gz.pgp, .zip.gpg, .gz.gpg
 * @param encryptedFileName - The encrypted filename
 */
function getDecryptedFileName(encryptedFileName: string): string {
    let fileName = encryptedFileName.replace(/\.(pgp|gpg)$/, '');
    return fileName;
}

/**
 * Validates and loads private key from credentials
 */
async function loadPrivateKey(credentials: any, getNode: () => any): Promise<PrivateKey> {
    if (!credentials.private_key || (credentials.private_key as string).trim() === '') {
        throw new NodeOperationError(
            getNode(),
            'Private key is missing or empty. Please provide a valid private key in credentials.',
        );
    }

    const cleanedPrivateKey = cleanArmoredKey(credentials.private_key as string);
    if (!cleanedPrivateKey.includes('-----BEGIN PGP PRIVATE KEY BLOCK-----')) {
        throw new NodeOperationError(
            getNode(),
            'Private key format is invalid. The key must start with "-----BEGIN PGP PRIVATE KEY BLOCK-----" and end with "-----END PGP PRIVATE KEY BLOCK-----".',
        );
    }

    try {
        if (credentials.passphrase) {
            return await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({
                    armoredKey: cleanedPrivateKey,
                }),
                passphrase: credentials.passphrase as string,
            });
        } else {
            return await openpgp.readPrivateKey({
                armoredKey: cleanedPrivateKey,
            });
        }
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        if (credentials.passphrase) {
            throw new NodeOperationError(
                getNode(),
                `Failed to decrypt private key. Please check: 1) Private key format is correct (should start with -----BEGIN PGP PRIVATE KEY BLOCK-----), 2) Passphrase is correct, 3) Private key and passphrase match. Error: ${errorMessage}`,
            );
        } else {
            throw new NodeOperationError(
                getNode(),
                `Failed to read private key. Please check: 1) Private key format is correct (should start with -----BEGIN PGP PRIVATE KEY BLOCK-----), 2) Private key is not encrypted (if encrypted, provide passphrase). Error: ${errorMessage}`,
            );
        }
    }
}

/**
 * Validates and loads public key from credentials
 */
async function loadPublicKey(credentials: any, getNode: () => any): Promise<Key> {
    if (!credentials.public_key || (credentials.public_key as string).trim() === '') {
        throw new NodeOperationError(
            getNode(),
            'Public key is missing or empty. Please provide a valid public key in credentials.',
        );
    }

    const cleanedPublicKey = cleanArmoredKey(credentials.public_key as string);
    if (!cleanedPublicKey.includes('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        throw new NodeOperationError(
            getNode(),
            'Public key format is invalid. The key must start with "-----BEGIN PGP PUBLIC KEY BLOCK-----" and end with "-----END PGP PUBLIC KEY BLOCK-----".',
        );
    }

    try {
        return await openpgp.readKey({
            armoredKey: cleanedPublicKey,
        });
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new NodeOperationError(
            getNode(),
            `Failed to read public key. Please check: 1) Public key format is correct (should start with -----BEGIN PGP PUBLIC KEY BLOCK-----), 2) Public key is complete and not corrupted. Error: ${errorMessage}`,
        );
    }
}

export class PgpNode implements INodeType {
    description: INodeTypeDescription = {
        displayName: 'PGP',
        name: 'pgpNode',
        icon: 'file:key.svg',
        group: ['transform'],
        version: 1,
        description: 'PGP Node',
        defaults: {
            name: 'PGP',
        },
        inputs: ['main'],
        outputs: ['main'],
        credentials: [
            {
                name: 'pgpCredentialsApi',
                required: true,
            },
        ],
        properties: [
            {
                displayName: 'Operation',
                name: 'operation',
                type: 'options',
                noDataExpression: true,
                default: 'encrypt',
                required: true,
                options: [
                    {
                        name: 'Decrypt',
                        value: 'decrypt',
                    },
                    {
                        name: 'Decrypt and Verify',
                        value: 'decrypt-and-verify',
                    },
                    {
                        name: 'Encrypt',
                        value: 'encrypt',
                    },
                    {
                        name: 'Encrypt and Sign',
                        value: 'encrypt-and-sign',
                    },
                    {
                        name: 'Sign',
                        value: 'sign',
                    },
                    {
                        name: 'Verify',
                        value: 'verify',
                    },
                ],
            },
            {
                displayName: 'Input Type',
                name: 'inputType',
                type: 'options',
                options: [
                    {
                        name: 'Text',
                        value: 'text',
                    },
                    {
                        name: 'Binary',
                        value: 'binary',
                    },
                ],
                default: 'text',
                description: 'Choose the type of input parameter',
            },
            {
                displayName: 'Compression Algorithm',
                name: 'compressionAlgorithm',
                type: 'options',
                options: [
                    {
                        name: 'Uncompressed',
                        value: 'uncompressed',
                    },
                    {
                        name: 'Zip',
                        value: 'zip',
                    },
                    {
                        name: 'Zlib',
                        value: 'zlib',
                    },
                ],
                default: 'uncompressed',
                description: 'Compress data before encryption. Select "Uncompressed" to skip compression.',
                displayOptions: {
                    show: {
                        operation: ['encrypt', 'encrypt-and-sign'],
                        inputType: ['binary'],
                    },
                },
            },
            {
                displayName: 'Decompression Algorithm',
                name: 'decompressionAlgorithm',
                type: 'options',
                options: [
                    {
                        name: 'Uncompressed',
                        value: 'uncompressed',
                    },
                    {
                        name: 'Zip',
                        value: 'zip',
                    },
                    {
                        name: 'Zlib',
                        value: 'zlib',
                    },
                ],
                default: 'uncompressed',
                description: 'Decompress data after decryption. Select "Uncompressed" to skip decompression.',
                displayOptions: {
                    show: {
                        operation: ['decrypt', 'decrypt-and-verify'],
                        inputType: ['binary'],
                    },
                },
            },
            {
                displayName: 'Message',
                name: 'message',
                type: 'string',
                default: '',
                placeholder: 'Message',
                description: 'The message text',
                displayOptions: {
                    show: {
                        inputType: ['text'],
                    },
                },
            },
            {
                displayName: 'Binary Property Name',
                name: 'binaryPropertyName',
                type: 'string',
                displayOptions: {
                    show: {
                        inputType: ['binary'],
                    },
                },
                default: 'message',
                description: 'Name of the binary property to process',
            },
            {
                displayName: 'Signature',
                name: 'signature',
                type: 'string',
                default: '',
                placeholder: '-----BEGIN PGP SIGNATURE-----',
                description: 'The PGP signature to verify. Required for verify operation.',
                displayOptions: {
                    show: {
                        inputType: ['text'],
                        operation: ['verify', 'decrypt-and-verify'],
                    },
                },
            },
            {
                displayName: 'Binary Property Name (Signature)',
                name: 'binaryPropertyNameSignature',
                type: 'string',
                default: 'signature',
                displayOptions: {
                    show: {
                        inputType: ['binary'],
                        operation: ['verify', 'decrypt-and-verify'],
                        embeddedSignature: [false],
                    },
                },
            },
            {
                displayName: 'Embed Signature',
                name: 'embedSignature',
                type: 'boolean',
                default: false,
                description: 'Whether to embed the signature in the encrypted message',
                displayOptions: {
                    show: {
                        operation: ['encrypt-and-sign'],
                    },
                },
            },
            {
                displayName: 'Embedded Signature',
                name: 'embeddedSignature',
                type: 'boolean',
                default: false,
                description: 'Whether the message contains an embedded signature',
                displayOptions: {
                    show: {
                        operation: ['decrypt-and-verify'],
                    },
                },
            },
        ],
    };

    async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
        const items = this.getInputData();

        const credentials = await this.getCredentials('pgpCredentialsApi');
        const priKey = await loadPrivateKey(credentials, () => this.getNode());
        const pubKey = await loadPublicKey(credentials, () => this.getNode());

        for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
            try {
                const operation = this.getNodeParameter('operation', itemIndex) as string;
                const inputType = this.getNodeParameter('inputType', itemIndex) as string;
                let compressionAlgorithm = 'uncompressed';
                let embedSignature = false;
                let embeddedSignature = false;
                const outputFormat: 'armored' | 'binary' = inputType === 'text' ? 'armored' : 'binary';
                let message: string;
                let binaryPropertyName: string;
                if (inputType === 'text') {
                    message = this.getNodeParameter('message', itemIndex) as string;
                    binaryPropertyName = '';
                } else {
                    message = '';
                    binaryPropertyName = this.getNodeParameter('binaryPropertyName', itemIndex) as string;
                    if (['encrypt', 'encrypt-and-sign'].includes(operation)) {
                        compressionAlgorithm = this.getNodeParameter('compressionAlgorithm', itemIndex) as string;
                    } else if (['decrypt', 'decrypt-and-verify'].includes(operation)) {
                        compressionAlgorithm = this.getNodeParameter('decompressionAlgorithm', itemIndex) as string;
                    }
                }

                if (operation === 'encrypt-and-sign') {
                    embedSignature = this.getNodeParameter('embedSignature', itemIndex) as boolean;
                } else if (operation === 'decrypt-and-verify') {
                    embeddedSignature = this.getNodeParameter('embeddedSignature', itemIndex) as boolean;
                }

                const item = items[itemIndex];
                if (inputType === 'text') {
                    item.binary = {};
                } else {
                    item.json = {};
                    if (!item.binary) {
                        throw new NodeOperationError(this.getNode(), 'binary is missing');
                    }

                    if (!item.binary[binaryPropertyName]) {
                        throw new NodeOperationError(this.getNode(), `binary "${binaryPropertyName}" is not defined`);
                    }
                }

                switch (operation) {
                    case 'encrypt':
                        if (inputType === 'text') {
                            item.json = {
                                encrypted: await encryptText(message, pubKey, outputFormat, compressionAlgorithm),
                            };
                        } else {
                            // Get binary data buffer (handles both Base64 and S3 storage)
                            const { data: binaryDataArray, options: options } = await NodeUtils.getBinaryData.call(
                                this,
                                itemIndex,
                                binaryPropertyName,
                            );
							const originalFileName = options.filename || 'encrypted';
                            let dataToEncrypt = binaryDataArray;
                            const encryptedMessage = await encryptBinary(dataToEncrypt, pubKey, outputFormat, compressionAlgorithm);

                            item.binary = {
                                message: {
                                    data: BinaryUtils.uint8ArrayToBase64(encryptedMessage as Uint8Array),
                                    mimeType: 'application/pgp-encrypted',
                                    fileName: `${originalFileName}.pgp`,
                                },
                            };
                        }
                        break;
                    case 'encrypt-and-sign':
                        if (inputType === 'text') {
                            if (embedSignature) {
                                item.json = {
                                    encrypted: await encryptTextWithSignature(message, pubKey, priKey, outputFormat, compressionAlgorithm),
                                };
                            } else {
                                item.json = {
                                    encrypted: await encryptText(message, pubKey, outputFormat, compressionAlgorithm),
                                    signature: await signText(message, priKey),
                                };
                            }
                        } else {
                            const { data: binaryDataEncryptAndSign, options: options } = await NodeUtils.getBinaryData.call(
                                this,
                                itemIndex,
                                binaryPropertyName,
                            );
                            let binaryDataEncryptAndSignArray = binaryDataEncryptAndSign;
                            const originalFileName = options.filename || 'encrypted';
                            if (embedSignature) {
                                const encryptedMessage = await encryptBinaryWithSignature(
                                    binaryDataEncryptAndSignArray,
                                    pubKey,
                                    priKey,
                                    outputFormat,
																		compressionAlgorithm
                                );
                                item.binary = {
                                    message: {
                                        data: BinaryUtils.uint8ArrayToBase64(encryptedMessage as Uint8Array),
                                        mimeType: 'application/pgp-encrypted',
                                        fileName: `${originalFileName}.pgp`,
                                    },
                                };
                            } else {
                                const signature = await signBinary(binaryDataEncryptAndSignArray, priKey);
                                const encryptedMessage = await encryptBinary(
                                    binaryDataEncryptAndSignArray,
                                    pubKey,
                                    outputFormat,
																		compressionAlgorithm
                                );

                                item.binary = {
                                    message: {
                                        data: BinaryUtils.uint8ArrayToBase64(encryptedMessage as Uint8Array),
                                        mimeType: 'application/pgp-encrypted',
                                        fileName: `${originalFileName}.pgp`,
                                    },
                                    signature: {
                                        data: btoa(signature as string),
                                        mimeType: 'application/pgp-signature',
                                        fileExtension: 'sig',
                                        fileName: item.binary[binaryPropertyName].fileName + '.sig',
                                    },
                                };
                            }
                        }
                        break;
                    case 'decrypt':
                        if (inputType === 'text') {
                            const decrypted = await decryptText(message, priKey);
                            if (decrypted === false) {
                                throw new NodeOperationError(this.getNode(), 'Message could not be decrypted');
                            }

                            item.json = {
                                decrypted: decrypted,
                            };
                        } else {
                            const {
                                data: binaryData,
                                value: buffer,
                                options: options,
                            } = await NodeUtils.getBinaryData.call(this, itemIndex, binaryPropertyName);

                            // Detect format and prepare message for decryption
                            let messageForDecryption: string | Uint8Array;
                            let formatType = 'binary';
                            try {
                                const textContent = buffer.toString('utf-8');
                                if (textContent.includes('-----BEGIN PGP')) {
                                    messageForDecryption = textContent;
                                    formatType = 'ASCII-armored';
                                } else {
                                    messageForDecryption = binaryData;
                                }
                            } catch {
                                messageForDecryption = binaryData;
                            }

                            let decryptedMessage: Uint8Array | false;
                            try {
                                decryptedMessage = await decryptBinary(messageForDecryption, priKey);
                            } catch (error) {
                                const errorMessage = error instanceof Error ? error.message : String(error);
                                const dataSize = binaryData.length;
                                throw new NodeOperationError(
                                    this.getNode(),
                                    `Decryption failed with error. ` +
                                    `Format: ${formatType}, ` +
                                    `Data size: ${dataSize} bytes, ` +
                                    `Error: ${errorMessage}`,
                                );
                            }

                            if (decryptedMessage === false) {
                                throw new NodeOperationError(
                                    this.getNode(),
                                    `Decryption returned false. Format: ${formatType}, Data size: ${binaryData.length} bytes`,
                                );
                            }

                            const encryptedFileName = options.filename;
                            item.binary = {
                                decrypted: {
                                    data: BinaryUtils.uint8ArrayToBase64(decryptedMessage as Uint8Array),
                                    mimeType: 'application/octet-stream',
                                    fileName: encryptedFileName
                                        ? getDecryptedFileName(encryptedFileName)
                                        : undefined,
                                },
                            };
                        }
                        break;
                    case 'decrypt-and-verify':
                        if (inputType === 'text') {
                            if (embeddedSignature) {
                                let result: { data: string; verified: boolean } | false;
                                try {
                                    result = await decryptTextWithVerification(message, priKey, pubKey);
                                } catch (error) {
                                    throw new NodeOperationError(this.getNode(), 'Message could not be decrypted');
                                }
                                if (result === false) {
                                    throw new NodeOperationError(
                                        this.getNode(),
                                        `Message could not be decrypted. Input type: text, Message length: ${message.length} characters`,
                                    );
                                }

                                item.json = {
                                    decrypted: result.data,
                                    verified: result.verified,
                                };
                            } else {
                                let decrypted: string | false;
                                try {
                                    decrypted = await decryptText(message, priKey);
                                } catch (error) {
                                    throw new NodeOperationError(this.getNode(), 'Message could not be decrypted'
                                    );
                                }
                                if (decrypted === false) {
                                    throw new NodeOperationError(
                                        this.getNode(),
                                        `Message could not be decrypted. Input type: text, Message length: ${message.length} characters`,
                                    );
                                }

                                const signature = this.getNodeParameter('signature', itemIndex) as string;
                                const isVerifiedDecryptAndVerify = await verifyText(decrypted, signature, pubKey);

                                item.json = {
                                    decrypted: decrypted,
                                    verified: isVerifiedDecryptAndVerify,
                                };
                            }
                        } else {
                            if (embeddedSignature) {
                                const {
                                    data: binaryData,
                                    value: buffer,
                                    options: options,
                                } = await NodeUtils.getBinaryData.call(this, itemIndex, binaryPropertyName);

                                let messageForDecryption: string | Uint8Array;
                                let formatType = 'binary';
                                try {
                                    const textContent = buffer.toString('utf-8');
                                    if (textContent.includes('-----BEGIN PGP')) {
                                        messageForDecryption = textContent;
                                        formatType = 'ASCII-armored';
                                    } else {
                                        messageForDecryption = binaryData;
                                    }
                                } catch {
                                    messageForDecryption = binaryData;
                                }

                                let decryptedMessageResult: { data: Uint8Array; verified: boolean } | false;
                                try {
                                    decryptedMessageResult = await decryptBinaryWithVerification(
                                        messageForDecryption,
                                        priKey,
                                        pubKey,
                                    );
                                } catch (error) {
                                    const errorMessage = error instanceof Error ? error.message : String(error);
                                    const dataSize = binaryData.length;
                                    throw new NodeOperationError(
                                        this.getNode(),
                                        `Decryption failed with error. ` +
                                        `Format: ${formatType}, ` +
                                        `Data size: ${dataSize} bytes, ` +
                                        `Error: ${errorMessage}`,
                                    );
                                }

                                if (decryptedMessageResult === false) {
                                    throw new NodeOperationError(
                                        this.getNode(),
                                        `Decryption returned false. Format: ${formatType}, Data size: ${binaryData.length} bytes`,
                                    );
                                }

                                const encryptedFileName = options.filename;
                                item.json = {
                                    verified: decryptedMessageResult.verified,
                                };
                                item.binary = {
                                    decrypted: {
                                        data: BinaryUtils.uint8ArrayToBase64(decryptedMessageResult.data),
                                        mimeType: 'application/octet-stream',
                                        fileName: encryptedFileName
                                            ? getDecryptedFileName(encryptedFileName)
                                            : undefined,
                                    },
                                };
                            } else {
                                const {
                                    data: binaryData,
                                    value: buffer,
                                    options: options,
                                } = await NodeUtils.getBinaryData.call(this, itemIndex, binaryPropertyName);

                                let messageForDecryption: string | Uint8Array;
                                let formatType = 'binary';
                                try {
                                    const textContent = buffer.toString('utf-8');
                                    if (textContent.includes('-----BEGIN PGP')) {
                                        messageForDecryption = textContent;
                                        formatType = 'ASCII-armored';
                                    } else {
                                        messageForDecryption = binaryData;
                                    }
                                } catch {
                                    messageForDecryption = binaryData;
                                }

                                let decryptedMessage: Uint8Array | false;
                                try {
                                    decryptedMessage = await decryptBinary(messageForDecryption, priKey);
                                } catch (error) {
                                    const errorMessage = error instanceof Error ? error.message : String(error);
                                    const dataSize = binaryData.length;
                                    throw new NodeOperationError(
                                        this.getNode(),
                                        `Decryption failed with error. ` +
                                        `Format: ${formatType}, ` +
                                        `Data size: ${dataSize} bytes, ` +
                                        `Error: ${errorMessage}`,
                                    );
                                }

                                if (decryptedMessage === false) {
                                    throw new NodeOperationError(
                                        this.getNode(),
                                        `Decryption returned false. Format: ${formatType}, Data size: ${binaryData.length} bytes`,
                                    );
                                }
                                const binaryPropertyNameSignature = this.getNodeParameter(
                                    'binaryPropertyNameSignature',
                                    itemIndex,
                                ) as string;
                                const signatureData = await NodeUtils.getSignatureData.call(
                                    this,
                                    itemIndex,
                                    binaryPropertyNameSignature,
                                );

                                const isVerified = await verifyBinary(decryptedMessage, signatureData, pubKey);

                                const encryptedFileName = options.filename;
                                item.json = {
                                    verified: isVerified,
                                };
                                item.binary = {
                                    decrypted: {
                                        data: BinaryUtils.uint8ArrayToBase64(decryptedMessage as Uint8Array),
                                        mimeType: 'application/octet-stream',
                                        fileName: encryptedFileName
                                            ? getDecryptedFileName(encryptedFileName)
                                            : undefined,
                                    },
                                };
                            }
                        }
                        break;
                    case 'sign':
                        if (inputType === 'text') {
                            item.json = {
                                signature: await signText(message, priKey),
                            };
                        } else {
                            const { data: binaryDataSign, options: options } = await NodeUtils.getBinaryData.call(
                                this,
                                itemIndex,
                                binaryPropertyName,
                            );
                            const signature = await signBinary(binaryDataSign, priKey);

                            item.binary = {
                                signature: {
                                    data: btoa(signature as string),
                                    mimeType: 'application/pgp-signature',
                                    fileExtension: 'sig',
                                    fileName: (options.filename || 'signature') + '.sig',
                                },
                            };
                        }
                        break;
                    case 'verify':
                        if (inputType === 'text') {
                            let signature = this.getNodeParameter('signature', itemIndex) as string;
                            if (!signature || signature.trim() === '') {
                                throw new NodeOperationError(
                                    this.getNode(),
                                    'Signature is missing or empty. Please provide a valid PGP signature.',
                                );
                            }
                            let processedSignature = signature;
                            if (signature.includes('\\n') && !signature.includes('\n')) {
                                processedSignature = signature.replace(/\\n/g, '\n');
                            }

                            const cleanedSignature = cleanArmoredKey(processedSignature);
                            if (!cleanedSignature.includes('-----BEGIN PGP SIGNATURE-----')) {
                                throw new NodeOperationError(
                                    this.getNode(),
                                    'Signature format is invalid. The signature must start with "-----BEGIN PGP SIGNATURE-----" and end with "-----END PGP SIGNATURE-----".',
                                );
                            }

                            const isVerified = await verifyText(message, cleanedSignature, pubKey);

                            item.json = {
                                verified: isVerified,
                            };
                        } else {
                            const binaryPropertyNameSignature = this.getNodeParameter(
                                'binaryPropertyNameSignature',
                                itemIndex,
                            ) as string;
                            const signatureData = await NodeUtils.getSignatureData.call(
                                this,
                                itemIndex,
                                binaryPropertyNameSignature,
                            );
                            const { data: binaryData } = await NodeUtils.getBinaryData.call(
                                this,
                                itemIndex,
                                binaryPropertyName,
                            );
                            const isVerified = await verifyBinary(binaryData, signatureData, pubKey);

                            item.json = {
                                verified: isVerified,
                            };
                            item.binary = {};
                        }
                        break;
                }
            } catch (error: any) {
                if (this.continueOnFail()) {
                    items.push({
                        json: this.getInputData(itemIndex)[0].json,
                        error,
                        pairedItem: itemIndex,
                    });
                } else {
                    if (error.context) {
                        error.context.itemIndex = itemIndex;
                        throw error;
                    }
                    throw new NodeOperationError(this.getNode(), error, {
                        itemIndex,
                    });
                }
            }
        }

        return this.prepareOutputData(items);
    }
}
