import * as openpgp from 'openpgp';
import { Key, PrivateKey } from 'openpgp';

function getCompressionAlgorithm(compressionAlgorithm) {
	let openpgpCompressionAlgorithm = {
		'uncompressed': openpgp.enums.compression.uncompressed,
		'zip': openpgp.enums.compression.zip,
		'zlib': openpgp.enums.compression.zlib
	}?.[compressionAlgorithm];
	if (!openpgpCompressionAlgorithm) { throw new Error('Unsupported algorithm'); }
	return openpgpCompressionAlgorithm;
}

export async function encryptText(message: string, publicKey: Key, outputFormat: 'armored' | 'binary' = 'armored', compressionAlgorithm: string = 'uncompressed'): Promise<string | Uint8Array> {
    if (outputFormat === 'binary') {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: message }),
            encryptionKeys: publicKey,
            format: 'binary',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }
        });
        return encrypted as Uint8Array;
    } else {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: message }),
            encryptionKeys: publicKey,
            format: 'armored',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }
        });
        return encrypted as string;
    }
}

export async function encryptBinary(data: Uint8Array, publicKey: Key, outputFormat: 'armored' | 'binary' = 'armored', compressionAlgorithm: string = 'uncompressed'): Promise<string | Uint8Array> {
    if (outputFormat === 'binary') {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ binary: data }),
            encryptionKeys: publicKey,
            format: 'binary',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }

        });
        return encrypted as Uint8Array;
    } else {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ binary: data }),
            encryptionKeys: publicKey,
            format: 'armored',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }
        });
        return encrypted as string;
    }
}

export async function decryptText(message: string, privateKey: PrivateKey): Promise<string | false> {
    try {
        const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: message }),
            decryptionKeys: privateKey,
            format: 'utf8',
        });

        return decrypted.data as string;
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}

export async function decryptBinary(message: string | Uint8Array, privateKey: PrivateKey): Promise<Uint8Array | false> {
    try {
        let decrypted;
        if (message instanceof Uint8Array) {
            const pgpMessage = await openpgp.readMessage({ binaryMessage: message });
            decrypted = await openpgp.decrypt({
                message: pgpMessage,
                decryptionKeys: privateKey,
                format: 'binary',
            });
        } else {
            const messageStr = message as string;
            if (messageStr.includes('-----BEGIN PGP')) {
                const pgpMessage = await openpgp.readMessage({ armoredMessage: messageStr });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    format: 'binary',
                });
            } else {
                const binaryData = new TextEncoder().encode(messageStr);
                const pgpMessage = await openpgp.readMessage({ binaryMessage: binaryData });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    format: 'binary',
                });
            }
        }

        return decrypted.data as Uint8Array;
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}

export async function signText(message: string, privateKey: PrivateKey): Promise<string> {
    const signature = await openpgp.sign({
        message: await openpgp.createMessage({ text: message }),
        signingKeys: privateKey,
        detached: true,
        format: 'armored',
    });

    return signature as string;
}

export async function signBinary(binaryData: Uint8Array, privateKey: PrivateKey): Promise<string> {
    const signature = await openpgp.sign({
        message: await openpgp.createMessage({ binary: binaryData }),
        signingKeys: privateKey,
        detached: true,
        format: 'armored',
    });

    return signature as string;
}

export async function verifyText(message: string, armoredSignature: string, publicKey: Key): Promise<boolean> {
    const verification = await openpgp.verify({
        message: await openpgp.createMessage({ text: message }),
        signature: await openpgp.readSignature({ armoredSignature }),
        verificationKeys: publicKey,
    });
    const { verified } = verification.signatures[0];
    try {
        await verified;
        return true;
    } catch {
        return false;
    }
}

export async function verifyBinary(binaryData: Uint8Array, signature: string, publicKey: Key): Promise<boolean> {
    const verification = await openpgp.verify({
        message: await openpgp.createMessage({ binary: binaryData }),
        signature: await openpgp.readSignature({ armoredSignature: signature }),
        verificationKeys: publicKey,
    });

    const { verified } = verification.signatures[0];
    try {
        await verified;
        return true;
    } catch {
        return false;
    }
}

export async function encryptTextWithSignature(
    message: string,
    publicKey: Key,
    privateKey: PrivateKey,
    outputFormat: 'armored' | 'binary' = 'armored',
		compressionAlgorithm: string = 'uncompressed'
): Promise<string | Uint8Array> {
    if (outputFormat === 'binary') {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: message }),
            encryptionKeys: publicKey,
            signingKeys: privateKey,
            format: 'binary',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }
        });
        return encrypted as Uint8Array;
    } else {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ text: message }),
            encryptionKeys: publicKey,
            signingKeys: privateKey,
            format: 'armored',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }
        });
        return encrypted as string;
    }
}

export async function encryptBinaryWithSignature(
    data: Uint8Array,
    publicKey: Key,
    privateKey: PrivateKey,
    outputFormat: 'armored' | 'binary' = 'armored',
		compressionAlgorithm: string = 'uncompressed'
): Promise<string | Uint8Array> {
    if (outputFormat === 'binary') {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ binary: data }),
            encryptionKeys: publicKey,
            signingKeys: privateKey,
            format: 'binary',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }
        });
        return encrypted as Uint8Array;
    } else {
        const encrypted = await openpgp.encrypt({
            message: await openpgp.createMessage({ binary: data }),
            encryptionKeys: publicKey,
            signingKeys: privateKey,
            format: 'armored',
						config: { preferredCompressionAlgorithm: getCompressionAlgorithm(compressionAlgorithm) }
        });
        return encrypted as string;
    }
}

export async function decryptTextWithVerification(
    message: string,
    privateKey: PrivateKey,
    publicKey: Key,
): Promise<{ data: string; verified: boolean } | false> {
    try {
        const decrypted = await openpgp.decrypt({
            message: await openpgp.readMessage({ armoredMessage: message }),
            decryptionKeys: privateKey,
            verificationKeys: publicKey,
            format: 'utf8',
        });

        const { data, signatures } = decrypted;
        let verified = false;

        if (signatures && signatures.length > 0) {
            try {
                await signatures[0].verified;
                verified = true;
            } catch {
                verified = false;
            }
        }

        return { data: data as string, verified };
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}

export async function decryptBinaryWithVerification(
    message: string | Uint8Array,
    privateKey: PrivateKey,
    publicKey: Key,
): Promise<{ data: Uint8Array; verified: boolean } | false> {
    try {
        let decrypted;
        if (message instanceof Uint8Array) {
            const pgpMessage = await openpgp.readMessage({ binaryMessage: message });
            decrypted = await openpgp.decrypt({
                message: pgpMessage,
                decryptionKeys: privateKey,
                verificationKeys: publicKey,
                format: 'binary',
            });
        } else {
            const messageStr = message as string;
            if (messageStr.includes('-----BEGIN PGP')) {
                const pgpMessage = await openpgp.readMessage({ armoredMessage: messageStr });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    verificationKeys: publicKey,
                    format: 'binary',
                });
            } else {
                const binaryData = new TextEncoder().encode(messageStr);
                const pgpMessage = await openpgp.readMessage({ binaryMessage: binaryData });
                decrypted = await openpgp.decrypt({
                    message: pgpMessage,
                    decryptionKeys: privateKey,
                    verificationKeys: publicKey,
                    format: 'binary',
                });
            }
        }

        const { data, signatures } = decrypted;
        let verified = false;

        if (signatures && signatures.length > 0) {
            try {
                await signatures[0].verified;
                verified = true;
            } catch {
                verified = false;
            }
        }

        return { data: data as Uint8Array, verified };
    } catch (error) {
        // Store error for better debugging - will be caught and re-thrown with context
        const errorMessage = error instanceof Error ? error.message : String(error);
        const errorWithDetails = new Error(errorMessage);
        (errorWithDetails as any).originalError = error;
        throw errorWithDetails;
    }
}
